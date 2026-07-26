// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

// A loopback proxy that carries WireGuard over TCP instead of UDP.
//
// WireGuard is pointed at this proxy's local UDP port instead of the real
// server. Each datagram it sends is written to a TCP connection behind a 2-byte
// big-endian length prefix, and each frame read back off that connection is
// handed to WireGuard as a datagram. Nothing about WireGuard itself changes; it
// simply talks to 127.0.0.1.
//
// The encapsulation is Mullvad's `udp-over-tcp`, which their WireGuard servers
// accept on TCP 80, 443 and 5001 — so the far end de-encapsulates it and no
// server of your own is needed. There is deliberately no encryption or masking
// here: the far end is a stock WireGuard server that would reject altered
// bytes, and the payload is already encrypted and authenticated by WireGuard.
// What this buys is that no WireGuard-shaped UDP appears on the wire at all.
final class ObfuscationProxy {
    private let remoteHost: NWEndpoint.Host
    private let remotePort: NWEndpoint.Port
    private let queue = DispatchQueue(label: "ObfuscationProxy")
    private let interfaceMonitor = PhysicalInterfaceMonitor()

    private var listener: NWListener?
    // The WireGuard-facing side. wireguard-go can rebind its source port when
    // the network changes, which arrives as a fresh connection, so this tracks
    // whichever one spoke most recently.
    private var localConnection: NWConnection?
    private var remoteConnection: NWConnection?

    // Reassembly buffer for the TCP byte stream, which has no message boundaries.
    private var inbound = [UInt8]()
    // Datagrams produced before the TCP connection was ready. Handshake
    // initiations are retransmitted by WireGuard anyway, so this stays small.
    private var pendingOutbound = [Data]()
    private var isStopped = false
    private var reconnectDelay: TimeInterval = 0.25

    private static let maxPendingOutbound = 32
    private static let maxFrameLength = 65535

    enum ProxyError: Error {
        case listenerDidNotStart
    }

    init(remoteHost: NWEndpoint.Host, remotePort: NWEndpoint.Port) {
        self.remoteHost = remoteHost
        self.remotePort = remotePort
    }

    // Starts the proxy and returns the loopback UDP port WireGuard should use.
    func start() throws -> UInt16 {
        interfaceMonitor.start()

        let parameters = NWParameters.udp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        parameters.allowLocalEndpointReuse = true

        let listener = try NWListener(using: parameters)
        self.listener = listener

        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready, .failed, .cancelled:
                ready.signal()
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.adoptLocalConnection(connection)
        }
        listener.start(queue: queue)

        guard ready.wait(timeout: .now() + 5) == .success,
              case .ready = listener.state,
              let port = listener.port else {
            listener.cancel()
            self.listener = nil
            interfaceMonitor.stop()
            throw ProxyError.listenerDidNotStart
        }

        queue.async { [weak self] in
            self?.connectRemote()
        }

        wg_log(.info, message: "Obfuscation: udp2tcp via 127.0.0.1:\(port.rawValue) -> \(remoteHost):\(remotePort.rawValue)")
        return port.rawValue
    }

    func stop() {
        queue.sync {
            isStopped = true
            localConnection?.cancel()
            localConnection = nil
            remoteConnection?.cancel()
            remoteConnection = nil
            pendingOutbound.removeAll()
            inbound.removeAll()
        }
        listener?.cancel()
        listener = nil
        interfaceMonitor.stop()
    }

    // MARK: - WireGuard side

    private func adoptLocalConnection(_ connection: NWConnection) {
        queue.async { [weak self] in
            guard let self = self, !self.isStopped else {
                connection.cancel()
                return
            }
            self.localConnection?.cancel()
            self.localConnection = connection
            connection.start(queue: self.queue)
            self.receiveFromWireGuard(on: connection)
        }
    }

    private func receiveFromWireGuard(on connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                self.sendToRemote(data)
            }
            if error != nil || self.isStopped {
                return
            }
            self.receiveFromWireGuard(on: connection)
        }
    }

    // MARK: - Server side

    private func connectRemote() {
        guard !isStopped else { return }

        let parameters = NWParameters.tcp
        // A full-tunnel config owns the default route, so once the tunnel is up
        // this connection would be routed into the very tunnel it carries.
        // Positively binding to the physical interface is what keeps it outside.
        if let physical = interfaceMonitor.current {
            parameters.requiredInterface = physical
        }
        parameters.prohibitedInterfaceTypes = [.other]
        parameters.preferNoProxies = true
        if let tcp = parameters.defaultProtocolStack.internetProtocol as? NWProtocolTCP.Options {
            tcp.noDelay = true
        }

        let connection = NWConnection(host: remoteHost, port: remotePort, using: parameters)
        remoteConnection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.reconnectDelay = 0.25
                wg_log(.info, message: "Obfuscation: TCP tunnel established")
                self.flushPendingOutbound()
            case .failed(let error):
                wg_log(.error, message: "Obfuscation: TCP tunnel failed: \(error.localizedDescription)")
                self.scheduleReconnect(after: connection)
            case .cancelled:
                self.scheduleReconnect(after: connection)
            default:
                break
            }
        }
        connection.start(queue: queue)
        receiveFromRemote(on: connection)
    }

    private func scheduleReconnect(after connection: NWConnection) {
        guard !isStopped, remoteConnection === connection else { return }
        remoteConnection = nil
        inbound.removeAll()

        let delay = reconnectDelay
        reconnectDelay = min(reconnectDelay * 2, 10)
        queue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self, !self.isStopped, self.remoteConnection == nil else { return }
            self.connectRemote()
        }
    }

    private func sendToRemote(_ datagram: Data) {
        guard datagram.count <= ObfuscationProxy.maxFrameLength else { return }

        var framed = Data(capacity: datagram.count + 2)
        framed.append(UInt8(datagram.count >> 8))
        framed.append(UInt8(datagram.count & 0xFF))
        framed.append(datagram)

        guard let connection = remoteConnection, case .ready = connection.state else {
            if pendingOutbound.count < ObfuscationProxy.maxPendingOutbound {
                pendingOutbound.append(framed)
            }
            return
        }
        connection.send(content: framed, completion: .contentProcessed { _ in })
    }

    private func flushPendingOutbound() {
        guard let connection = remoteConnection else { return }
        let queued = pendingOutbound
        pendingOutbound.removeAll()
        for framed in queued {
            connection.send(content: framed, completion: .contentProcessed { _ in })
        }
    }

    private func receiveFromRemote(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self, !self.isStopped else { return }

            if let data = data, !data.isEmpty {
                self.inbound.append(contentsOf: data)
                self.drainFrames()
            }
            if isComplete || error != nil {
                self.scheduleReconnect(after: connection)
                return
            }
            self.receiveFromRemote(on: connection)
        }
    }

    // Pulls whole length-prefixed frames out of the reassembly buffer and hands
    // each one to WireGuard as a datagram.
    private func drainFrames() {
        var consumed = 0
        while inbound.count - consumed >= 2 {
            let length = Int(inbound[consumed]) << 8 | Int(inbound[consumed + 1])
            guard inbound.count - consumed - 2 >= length else { break }
            let start = consumed + 2
            let datagram = Data(inbound[start..<(start + length)])
            consumed = start + length
            if let local = localConnection, !datagram.isEmpty {
                local.send(content: datagram, completion: .contentProcessed { _ in })
            }
        }
        if consumed > 0 {
            inbound.removeFirst(consumed)
        }
    }
}

// Tracks the physical (non-tunnel) interface the obfuscated connection binds to,
// updating as the device moves between Wi-Fi, Ethernet and cellular. This
// mirrors the split-tunnel proxy's monitor, kept separate because that one lives
// in the macOS-only proxy extension while this must also work on iOS.
private final class PhysicalInterfaceMonitor {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "ObfuscationProxy.pathMonitor")
    private let lock = NSLock()
    private var interface: NWInterface?

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            let physical = path.availableInterfaces.first {
                $0.type == .wifi || $0.type == .wiredEthernet || $0.type == .cellular
            }
            self?.lock.lock()
            self?.interface = physical
            self?.lock.unlock()
        }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
    }

    var current: NWInterface? {
        lock.lock()
        defer { lock.unlock() }
        return interface
    }
}
