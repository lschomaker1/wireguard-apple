// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

// How the tunnel's packets are disguised on the wire.
//
// A raw WireGuard datagram is trivially fingerprintable: the first byte is a
// message type (1...4) followed by three zero "reserved" bytes, and handshakes
// have fixed, well-known lengths. Networks that block WireGuard match exactly
// that.
//
// `udp2tcp` carries each datagram inside a TCP stream behind a 2-byte
// big-endian length prefix, which is the encapsulation Mullvad's WireGuard
// servers already accept on TCP ports 80, 443 and 5001. There is then no
// WireGuard-shaped UDP on the wire at all — just a TCP conversation with a web
// port — and because the far end de-encapsulates it, no server of your own is
// involved.
public enum Obfuscation: Equatable {
    case udp2tcp(port: UInt16)

    // The port a bare `Obfuscation = udp2tcp` means. 443 blends in best.
    public static let defaultUdp2TcpPort: UInt16 = 443

    public var stringRepresentation: String {
        switch self {
        case .udp2tcp(let port):
            return "udp2tcp:\(port)"
        }
    }

    public init?(stringRepresentation: String) {
        let parts = stringRepresentation
            .trimmingCharacters(in: .whitespaces)
            .lowercased()
            .split(separator: ":", omittingEmptySubsequences: false)
        guard parts.first == "udp2tcp" else { return nil }
        switch parts.count {
        case 1:
            self = .udp2tcp(port: Obfuscation.defaultUdp2TcpPort)
        case 2:
            guard let port = UInt16(parts[1]), port > 0 else { return nil }
            self = .udp2tcp(port: port)
        default:
            return nil
        }
    }
}

public struct InterfaceConfiguration {
    public var privateKey: PrivateKey
    public var addresses = [IPAddressRange]()
    public var listenPort: UInt16?
    public var mtu: UInt16?
    public var dns = [DNSServer]()
    public var dnsSearch = [String]()
    public var obfuscation: Obfuscation?

    public init(privateKey: PrivateKey) {
        self.privateKey = privateKey
    }
}

extension InterfaceConfiguration: Equatable {
    public static func == (lhs: InterfaceConfiguration, rhs: InterfaceConfiguration) -> Bool {
        let lhsAddresses = lhs.addresses.filter { $0.address is IPv4Address } + lhs.addresses.filter { $0.address is IPv6Address }
        let rhsAddresses = rhs.addresses.filter { $0.address is IPv4Address } + rhs.addresses.filter { $0.address is IPv6Address }

        return lhs.privateKey == rhs.privateKey &&
            lhsAddresses == rhsAddresses &&
            lhs.listenPort == rhs.listenPort &&
            lhs.mtu == rhs.mtu &&
            lhs.dns == rhs.dns &&
            lhs.dnsSearch == rhs.dnsSearch &&
            lhs.obfuscation == rhs.obfuscation
    }
}
