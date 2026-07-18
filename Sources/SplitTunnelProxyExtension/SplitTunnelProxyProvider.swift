// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
import NetworkExtension

class SplitTunnelProxyProvider: NETransparentProxyProvider {

    private let matcher = ExcludedAppMatcher()
    private let relayQueue = DispatchQueue(label: "SplitTunnelProxyProvider.relays")
    private var relays = Set<FlowRelay>()

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        matcher.reload()

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .UDP, direction: .outbound)
        ]
        // DNS stays on the system resolver path, which the packet tunnel already
        // points at the tunnel's DNS servers while it is up.
        settings.excludedNetworkRules = [
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "0.0.0.0", port: "53"), remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound),
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "::", port: "53"), remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound)
        ]

        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        relayQueue.sync {
            for relay in relays {
                relay.cancel()
            }
            relays.removeAll()
        }
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        if String(data: messageData, encoding: .utf8) == SplitTunnelConfiguration.providerReloadMessage {
            matcher.reload()
        }
        completionHandler?(nil)
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard matcher.matches(flow: flow) else { return false }

        let relay: FlowRelay
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            guard let remote = tcpFlow.remoteEndpoint as? NWHostEndpoint,
                  EndpointClassifier.isRelayable(host: remote.hostname),
                  let tcpRelay = TCPFlowRelay(flow: tcpFlow, remote: remote) else { return false }
            relay = tcpRelay
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            relay = UDPFlowRelay(flow: udpFlow)
        } else {
            return false
        }

        relayQueue.sync {
            _ = relays.insert(relay)
        }
        relay.onFinish = { [weak self] finishedRelay in
            guard let self = self else { return }
            self.relayQueue.async {
                self.relays.remove(finishedRelay)
            }
        }
        relay.start()
        return true
    }
}

private final class ExcludedAppMatcher {
    private let lock = NSLock()
    private var bundleIdentifiers = [String]()
    private var bundlePaths = [String]()

    func reload() {
        let apps = SplitTunnelConfiguration.loadExcludedApps()
        lock.lock()
        bundleIdentifiers = apps.map { $0.bundleIdentifier }.filter { !$0.isEmpty }
        bundlePaths = apps.map { $0.bundlePath }.filter { !$0.isEmpty }.map { $0.hasSuffix("/") ? $0 : $0 + "/" }
        lock.unlock()
    }

    func matches(flow: NEAppProxyFlow) -> Bool {
        lock.lock()
        let identifiers = bundleIdentifiers
        let paths = bundlePaths
        lock.unlock()

        guard !identifiers.isEmpty || !paths.isEmpty else { return false }

        // Match both the app itself and its helper processes: helpers either
        // extend the app's signing identifier (com.example.app.helper) or live
        // inside the app bundle.
        let signingIdentifier = flow.metaData.sourceAppSigningIdentifier
        if !signingIdentifier.isEmpty {
            for identifier in identifiers where signingIdentifier == identifier || signingIdentifier.hasPrefix(identifier + ".") {
                return true
            }
        }
        if !paths.isEmpty, let processPath = Self.processPath(auditToken: flow.metaData.sourceAppAuditToken) {
            for path in paths where processPath.hasPrefix(path) {
                return true
            }
        }
        return false
    }

    private static func processPath(auditToken: Data?) -> String? {
        // audit_token_t is eight 32-bit values; the sixth one is the pid.
        guard let auditToken = auditToken, auditToken.count >= 8 * MemoryLayout<UInt32>.size else { return nil }
        let pid = auditToken.withUnsafeBytes { $0.load(fromByteOffset: 5 * MemoryLayout<UInt32>.size, as: pid_t.self) }
        var buffer = [CChar](repeating: 0, count: 4 * 1024)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }
}
