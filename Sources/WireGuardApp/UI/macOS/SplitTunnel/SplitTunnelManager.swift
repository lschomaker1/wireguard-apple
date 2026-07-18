// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension

extension Notification.Name {
    static let splitTunnelStateDidChange = Notification.Name("SplitTunnelStateDidChange")
}

// Owns the transparent proxy that carries traffic of excluded apps around the
// tunnel. The proxy runs only while a tunnel is active and at least one app is
// excluded; the set of excluded apps is shared with the proxy provider through
// the app group defaults.
class SplitTunnelManager {

    static let shared = SplitTunnelManager()

    private(set) var excludedApps: [SplitTunnelApp]
    private(set) var isAnyTunnelActive = false

    private var proxyManager: NETransparentProxyManager?
    private var statusObserver: Any?

    private init() {
        excludedApps = SplitTunnelConfiguration.loadExcludedApps()
    }

    func setExcludedApps(_ apps: [SplitTunnelApp]) {
        guard apps != excludedApps else { return }
        excludedApps = apps
        SplitTunnelConfiguration.saveExcludedApps(apps)
        notifyProviderOfChanges()
        evaluateProxyState()
        NotificationCenter.default.post(name: .splitTunnelStateDidChange, object: self)
    }

    func tunnelsStateChanged(anyTunnelActive: Bool) {
        guard anyTunnelActive != isAnyTunnelActive else { return }
        isAnyTunnelActive = anyTunnelActive
        evaluateProxyState()
        NotificationCenter.default.post(name: .splitTunnelStateDidChange, object: self)
    }

    private func evaluateProxyState() {
        if isAnyTunnelActive && !excludedApps.isEmpty {
            startProxy()
        } else {
            stopProxy()
        }
    }

    private func loadOrCreateManager(createIfNeeded: Bool, completion: @escaping (NETransparentProxyManager?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            DispatchQueue.main.async {
                if let error = error {
                    wg_log(.error, message: "Split tunneling: unable to load proxy preferences: \(error.localizedDescription)")
                    completion(nil)
                    return
                }
                if let manager = managers?.first {
                    completion(manager)
                    return
                }
                guard createIfNeeded else {
                    completion(nil)
                    return
                }
                let manager = NETransparentProxyManager()
                let proxyProtocol = NETunnelProviderProtocol()
                proxyProtocol.providerBundleIdentifier = (Bundle.main.bundleIdentifier ?? "") + ".split-tunnel-proxy"
                proxyProtocol.serverAddress = "127.0.0.1"
                manager.protocolConfiguration = proxyProtocol
                manager.localizedDescription = "WireGuard Split Tunneling"
                completion(manager)
            }
        }
    }

    private func startProxy() {
        loadOrCreateManager(createIfNeeded: true) { [weak self] manager in
            guard let self = self, let manager = manager else { return }
            guard self.isAnyTunnelActive && !self.excludedApps.isEmpty else { return }
            self.observeStatus(of: manager)
            let status = manager.connection.status
            guard status != .connected && status != .connecting && status != .reasserting else {
                self.notifyProviderOfChanges()
                return
            }
            manager.isEnabled = true
            manager.saveToPreferences { saveError in
                DispatchQueue.main.async {
                    if let saveError = saveError {
                        wg_log(.error, message: "Split tunneling: unable to save proxy preferences: \(saveError.localizedDescription)")
                        return
                    }
                    manager.loadFromPreferences { _ in
                        DispatchQueue.main.async {
                            do {
                                try manager.connection.startVPNTunnel()
                            } catch {
                                wg_log(.error, message: "Split tunneling: unable to start proxy: \(error.localizedDescription)")
                            }
                        }
                    }
                }
            }
        }
    }

    private func stopProxy() {
        loadOrCreateManager(createIfNeeded: false) { [weak self] manager in
            guard let manager = manager else { return }
            self?.observeStatus(of: manager)
            let status = manager.connection.status
            if status != .disconnected && status != .invalid {
                manager.connection.stopVPNTunnel()
            }
        }
    }

    private func observeStatus(of manager: NETransparentProxyManager) {
        guard proxyManager !== manager else { return }
        if let statusObserver = statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        proxyManager = manager
        statusObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            if self.proxyManager?.connection.status == .connected {
                // The provider reads the app list when it starts; resend in case
                // the list changed while the proxy was still coming up.
                self.notifyProviderOfChanges()
            }
        }
    }

    private func notifyProviderOfChanges() {
        guard let session = proxyManager?.connection as? NETunnelProviderSession, session.status == .connected else { return }
        do {
            try session.sendProviderMessage(Data(SplitTunnelConfiguration.providerReloadMessage.utf8))
        } catch {
            wg_log(.error, message: "Split tunneling: unable to message proxy provider: \(error.localizedDescription)")
        }
    }
}
