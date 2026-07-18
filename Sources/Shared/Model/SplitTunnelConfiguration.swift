// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Security

struct SplitTunnelApp: Codable, Equatable {
    let bundleIdentifier: String
    let name: String
    let bundlePath: String
    // Code-signing team of the app. Matching on this excludes every process the
    // vendor ships (helpers, background agents, sibling apps), not just the one
    // bundle the user picked — essential for multi-process apps like games.
    var teamIdentifier: String?
}

// Shared between the app (resolves teams from bundles when apps are picked) and
// the proxy extension (resolves teams from live flows).
enum CodeSigning {
    static func teamIdentifier(forBundleAt path: String) -> String? {
        guard !path.isEmpty else { return nil }
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess, let staticCode = staticCode else { return nil }
        return teamIdentifier(fromSigningInfoOf: staticCode)
    }

    static func teamIdentifier(forAuditToken tokenData: Data?) -> String? {
        guard let tokenData = tokenData else { return nil }
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code = code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode = staticCode else { return nil }
        return teamIdentifier(fromSigningInfoOf: staticCode)
    }

    private static func teamIdentifier(fromSigningInfoOf staticCode: SecStaticCode) -> String? {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }
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
