// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

struct SplitTunnelApp: Codable, Equatable {
    let bundleIdentifier: String
    let name: String
    let bundlePath: String
}

enum SplitTunnelConfiguration {
    static let excludedAppsDefaultsKey = "SplitTunnelExcludedApps"
    static let providerReloadMessage = "split-tunnel-reload"

    private static var appGroupId: String? {
        return Bundle.main.object(forInfoDictionaryKey: "com.wireguard.macos.app_group_id") as? String
    }

    private static var sharedDefaults: UserDefaults? {
        guard let appGroupId = appGroupId else { return nil }
        return UserDefaults(suiteName: appGroupId)
    }

    static func loadExcludedApps() -> [SplitTunnelApp] {
        guard let data = sharedDefaults?.data(forKey: excludedAppsDefaultsKey) else { return [] }
        return (try? JSONDecoder().decode([SplitTunnelApp].self, from: data)) ?? []
    }

    static func saveExcludedApps(_ apps: [SplitTunnelApp]) {
        guard let data = try? JSONEncoder().encode(apps) else { return }
        sharedDefaults?.set(data, forKey: excludedAppsDefaultsKey)
    }
}
