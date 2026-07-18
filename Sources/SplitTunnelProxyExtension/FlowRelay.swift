// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
import NetworkExtension

class FlowRelay: Hashable {
    var onFinish: ((FlowRelay) -> Void)?

    fileprivate let queue: DispatchQueue
    fileprivate var isFinished = false

    fileprivate init(label: String) {
        queue = DispatchQueue(label: label)
    }

    func start() {
    }

    func cancel() {
    }

    fileprivate func markFinished() {
        guard !isFinished else { return }
        isFinished = true
        onFinish?(self)
    }

    fileprivate static func connectionParameters(_ parameters: NWParameters, boundTo boundInterface: NWInterface?) -> NWParameters {
        // A full-tunnel WireGuard config owns the default route, so merely
        // prohibiting the utun interface leaves a relayed connection with no
        // usable path ("Network is down"). Positively binding to the physical
        // interface is what actually carries the traffic around the tunnel.
        if let boundInterface = boundInterface {
            parameters.requiredInterface = boundInterface
        } else {
            parameters.requiredInterfaceType = .wifi
        }
        parameters.prohibitedInterfaceTypes = [.other]
        parameters.preferNoProxies = true
        return parameters
    }

    static func == (lhs: FlowRelay, rhs: FlowRelay) -> Bool {
        return lhs === rhs
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }
}

final class TCPFlowRelay: FlowRelay {
    private let flow: NEAppProxyTCPFlow
    private let connection: NWConnection
    private var flowEOF = false
    private var connectionEOF = false

    init?(flow: NEAppProxyTCPFlow, remote: NWHostEndpoint, boundInterface: NWInterface?) {
        guard let port = NWEndpoint.Port(remote.port) else { return nil }
        self.flow = flow
        connection = NWConnection(host: NWEndpoint.Host(remote.hostname), port: port, using: FlowRelay.connectionParameters(.tcp, boundTo: boundInterface))
        super.init(label: "SplitTunnelProxy.tcp")
    }

    override func start() {
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.openFlow()
            case .failed, .cancelled:
                self.finishRelay(error: nil)
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    override func cancel() {
        queue.async {
            self.finishRelay(error: nil)
        }
    }

    private func openFlow() {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self = self else { return }
            self.queue.async {
                guard !self.isFinished else { return }
                if error != nil {
                    self.finishRelay(error: error)
                } else {
                    self.readFromFlow()
                    self.readFromConnection()
                }
            }
        }
    }

    private func readFromFlow() {
        flow.readData { [weak self] data, error in
            guard let self = self else { return }
            self.queue.async {
                guard !self.isFinished else { return }
                guard error == nil, let data = data else {
                    self.finishRelay(error: error)
                    return
                }
                guard !data.isEmpty else {
                    self.connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                    self.flowEOF = true
                    self.finishIfDrained()
                    return
                }
                self.connection.send(content: data, completion: .contentProcessed { [weak self] sendError in
                    guard let self = self else { return }
                    guard !self.isFinished else { return }
                    if sendError != nil {
                        self.finishRelay(error: sendError)
                    } else {
                        self.readFromFlow()
                    }
                })
            }
        }
    }

    private func readFromConnection() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 128 * 1024) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            guard !self.isFinished else { return }
            if error != nil {
                self.finishRelay(error: error)
                return
            }
            if let data = data, !data.isEmpty {
                self.flow.write(data) { [weak self] writeError in
                    guard let self = self else { return }
                    self.queue.async {
                        guard !self.isFinished else { return }
                        if writeError != nil {
                            self.finishRelay(error: writeError)
                        } else if isComplete {
                            self.connectionFinishedReading()
                        } else {
                            self.readFromConnection()
                        }
                    }
                }
            } else if isComplete {
                self.connectionFinishedReading()
            } else {
                self.readFromConnection()
            }
        }
    }

    private func connectionFinishedReading() {
        flow.closeWriteWithError(nil)
        connectionEOF = true
        finishIfDrained()
    }

    private func finishIfDrained() {
        if flowEOF && connectionEOF {
            finishRelay(error: nil)
        }
    }

    private func finishRelay(error: Error?) {
        guard !isFinished else { return }
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        connection.cancel()
        markFinished()
    }
}

final class UDPFlowRelay: FlowRelay {
    private static let maxConnections = 128

    private let flow: NEAppProxyUDPFlow
    private let boundInterface: NWInterface?
    private var connections = [String: NWConnection]()

    init(flow: NEAppProxyUDPFlow, boundInterface: NWInterface?) {
        self.flow = flow
        self.boundInterface = boundInterface
        super.init(label: "SplitTunnelProxy.udp")
    }

    override func start() {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard let self = self else { return }
            self.queue.async {
                guard !self.isFinished else { return }
                if error != nil {
                    self.finishRelay(error: error)
                } else {
                    self.readFromFlow()
                }
            }
        }
    }

    override func cancel() {
        queue.async {
            self.finishRelay(error: nil)
        }
    }

    private func readFromFlow() {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self else { return }
            self.queue.async {
                guard !self.isFinished else { return }
                guard error == nil, let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else {
                    self.finishRelay(error: error)
                    return
                }
                for (datagram, endpoint) in zip(datagrams, endpoints) {
                    guard let hostEndpoint = endpoint as? NWHostEndpoint, EndpointClassifier.isRelayable(host: hostEndpoint.hostname) else { continue }
                    self.connection(to: hostEndpoint)?.send(content: datagram, completion: .idempotent)
                }
                self.readFromFlow()
            }
        }
    }

    private func connection(to endpoint: NWHostEndpoint) -> NWConnection? {
        let key = "\(endpoint.hostname):\(endpoint.port)"
        if let existing = connections[key] {
            return existing
        }
        guard connections.count < UDPFlowRelay.maxConnections, let port = NWEndpoint.Port(endpoint.port) else { return nil }
        let connection = NWConnection(host: NWEndpoint.Host(endpoint.hostname), port: port, using: FlowRelay.connectionParameters(.udp, boundTo: boundInterface))
        connections[key] = connection
        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let self = self, let connection = connection else { return }
            switch state {
            case .ready:
                self.receive(from: connection, endpoint: endpoint)
            case .failed, .cancelled:
                self.connections.removeValue(forKey: key)
            default:
                break
            }
        }
        connection.start(queue: queue)
        return connection
    }

    private func receive(from connection: NWConnection, endpoint: NWHostEndpoint) {
        connection.receiveMessage { [weak self, weak connection] data, _, _, error in
            guard let self = self, let connection = connection else { return }
            guard !self.isFinished else { return }
            if let data = data, !data.isEmpty {
                self.flow.writeDatagrams([data], sentBy: [endpoint]) { _ in }
            }
            if error == nil {
                self.receive(from: connection, endpoint: endpoint)
            } else {
                connection.cancel()
            }
        }
    }

    private func finishRelay(error: Error?) {
        guard !isFinished else { return }
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        for connection in connections.values {
            connection.cancel()
        }
        connections.removeAll()
        markFinished()
    }
}

// Tracks the physical (non-tunnel) interface that relayed connections bind to,
// updating as the machine moves between Wi-Fi and Ethernet.
final class PhysicalInterfaceMonitor {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "SplitTunnelProxy.pathMonitor")
    private let lock = NSLock()
    private var interface: NWInterface?

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            let physical = path.availableInterfaces.first { $0.type == .wifi || $0.type == .wiredEthernet }
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

enum EndpointClassifier {
    // Multicast, broadcast and link-local destinations cannot be usefully
    // relayed through a bound connection; those flows stay on the normal path.
    static func isRelayable(host: String) -> Bool {
        guard !host.isEmpty else { return false }
        if let v4 = IPv4Address(host) {
            return !(v4.isMulticast || v4 == IPv4Address.broadcast || v4.isLinkLocal)
        }
        if let v6 = IPv6Address(host) {
            return !(v6.isMulticast || v6.isLinkLocal)
        }
        return true
    }
}
