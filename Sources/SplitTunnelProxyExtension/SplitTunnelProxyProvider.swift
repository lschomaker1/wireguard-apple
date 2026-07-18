// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
import NetworkExtension
import os.log

let proxyLog = Logger(subsystem: Bundle.main.bundleIdentifier ?? "SplitTunnelProxy", category: "provider")

class SplitTunnelProxyProvider: NETransparentProxyProvider {

    private let matcher = ExcludedAppMatcher()
    private let interfaceMonitor = PhysicalInterfaceMonitor()
    private let relayQueue = DispatchQueue(label: "SplitTunnelProxyProvider.relays")
    private var relays = Set<FlowRelay>()

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let excludedCount = matcher.reload()
        interfaceMonitor.start()
        proxyLog.info("Starting proxy with \(excludedCount) excluded app(s)")

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .UDP, direction: .outbound)
        ]
        // DNS stays on the system resolver path, which the packet tunnel already
        // points at the tunnel's DNS servers while it is up. Port rules must name
        // TCP or UDP explicitly; a protocol of .any would ignore the port and
        // swallow every flow.
        settings.excludedNetworkRules = [
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "0.0.0.0", port: "53"), remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "0.0.0.0", port: "53"), remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .UDP, direction: .outbound),
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "::", port: "53"), remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: "::", port: "53"), remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .UDP, direction: .outbound)
        ]

        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                proxyLog.error("Proxy settings rejected: \(error.localizedDescription, privacy: .public)")
            } else {
                proxyLog.info("Proxy settings applied")
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        interfaceMonitor.stop()
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
            let excludedCount = matcher.reload()
            proxyLog.info("Reloaded exclusions: \(excludedCount) app(s)")
        }
        completionHandler?(nil)
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard matcher.matches(flow: flow) else { return false }

        let boundInterface = interfaceMonitor.current
        let relay: FlowRelay
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            guard let remote = tcpFlow.remoteEndpoint as? NWHostEndpoint,
                  remote.port != "53",
                  EndpointClassifier.isRelayable(host: remote.hostname),
                  let tcpRelay = TCPFlowRelay(flow: tcpFlow, remote: remote, boundInterface: boundInterface) else { return false }
            proxyLog.info("Bypassing TCP flow from \(flow.metaData.sourceAppSigningIdentifier, privacy: .public) to \(remote.hostname, privacy: .public):\(remote.port, privacy: .public) via \(boundInterface?.name ?? "auto", privacy: .public)")
            relay = tcpRelay
        } else if let udpFlow = flow as? NEAppProxyUDPFlow {
            proxyLog.info("Bypassing UDP flow from \(flow.metaData.sourceAppSigningIdentifier, privacy: .public)")
            relay = UDPFlowRelay(flow: udpFlow, boundInterface: boundInterface)
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
    private var teamIdentifiers = Set<String>()

    @discardableResult
    func reload() -> Int {
        let apps = SplitTunnelConfiguration.loadExcludedApps()
        // Derive the code-signing team from the bundle path for any app the UI
        // didn't record one for, so existing selections get whole-vendor
        // matching without the user re-adding them.
        var teams = Set<String>()
        for app in apps {
            if let team = app.teamIdentifier, !team.isEmpty {
                teams.insert(team)
            } else if let team = CodeSigning.teamIdentifier(forBundleAt: app.bundlePath) {
                teams.insert(team)
            }
        }
        lock.lock()
        bundleIdentifiers = apps.map { $0.bundleIdentifier }.filter { !$0.isEmpty }
        bundlePaths = apps.map { $0.bundlePath }.filter { !$0.isEmpty }.map { $0.hasSuffix("/") ? $0 : $0 + "/" }
        teamIdentifiers = teams
        lock.unlock()
        return apps.count
    }

    func matches(flow: NEAppProxyFlow) -> Bool {
        lock.lock()
        let identifiers = bundleIdentifiers
        let paths = bundlePaths
        let teams = teamIdentifiers
        lock.unlock()

        guard !identifiers.isEmpty || !paths.isEmpty || !teams.isEmpty else { return false }

        // Primary, most robust check: the code-signing team. Every process a
        // vendor ships shares its team, so excluding one app of a multi-process
        // suite (a game's launcher, client, and background service) excludes the
        // whole family regardless of bundle id or path.
        if !teams.isEmpty, let team = CodeSigning.teamIdentifier(forAuditToken: flow.metaData.sourceAppAuditToken), teams.contains(team) {
            return true
        }

        // Match both the app itself and its helper processes: helpers either
        // extend the app's signing identifier (com.example.app.helper) or live
        // inside the app bundle.
        let signingIdentifier = flow.metaData.sourceAppSigningIdentifier
        if !signingIdentifier.isEmpty {
            for identifier in identifiers where signingIdentifier == identifier || signingIdentifier.hasPrefix(identifier + ".") {
                return true
            }
        }
        if !paths.isEmpty, var pid = Self.pid(fromAuditToken: flow.metaData.sourceAppAuditToken) {
            // Walk up the process tree so that children spawned by an excluded
            // app (a shell in a terminal, a game launched by its client) are
            // excluded along with it.
            var depth = 0
            while pid > 1 && depth < 16 {
                if let processPath = Self.path(ofPid: pid) {
                    for path in paths where processPath == String(path.dropLast()) || processPath.hasPrefix(path) {
                        return true
                    }
                }
                guard let parent = Self.parentPid(of: pid), parent != pid else { break }
                pid = parent
                depth += 1
            }
        }
        return false
    }

    private static func pid(fromAuditToken auditToken: Data?) -> pid_t? {
        // audit_token_t is eight 32-bit values; the sixth one is the pid.
        guard let auditToken = auditToken, auditToken.count >= 8 * MemoryLayout<UInt32>.size else { return nil }
        return auditToken.withUnsafeBytes { $0.load(fromByteOffset: 5 * MemoryLayout<UInt32>.size, as: pid_t.self) }
    }

    private static func path(ofPid pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * 1024)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }

    private static func parentPid(of pid: pid_t) -> pid_t? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0, size > 0 else { return nil }
        return info.kp_eproc.e_ppid
    }
}
