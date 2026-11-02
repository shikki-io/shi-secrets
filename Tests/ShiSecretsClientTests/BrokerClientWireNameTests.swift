import Foundation
@testable import ShiSecretsClient
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// BrokerClientWireNameTests — verifies that each ProductionBrokerClient method
// sends the correct JSON-RPC wire method name to the broker socket.
//
// Strategy: bind a loopback Unix socket, run an in-process mock broker Task
// that accepts one connection and records the JSON-RPC method name, then
// drive the real ProductionBrokerClient through it.
//
// TCP-WN-01  ProductionBrokerClient.delete(name:) sends "secret.delete"
// TCP-WN-02  ProductionBrokerClient.set(name:value:) sends "secret.set"
// TCP-WN-03  ProductionBrokerClient.list(filter:) sends "secret.list"
// TCP-WN-04  ProductionBrokerClient.get(name:) sends "secret.get"

@Suite("BrokerClientWireNames")
struct BrokerClientWireNameTests {

    // MARK: - Helpers

    private static func tmpSocketPath() -> String {
        "/tmp/shi-wn-\(UUID().uuidString.prefix(8)).s"
    }

    /// Starts a loopback Unix-socket listener on `path`, runs a one-shot
    /// broker Task that accepts one connection, reads the first frame, sends
    /// `response` back, and returns the wire method name it observed.
    private func loopbackCapture(
        path: String,
        respondWith response: WireResponse
    ) -> Task<String?, Never> {
        Task.detached {
            defer { _ = unlink(path) }
            let listenFd = socket(AF_UNIX, Int32(SOCK_STREAM), 0)
            guard listenFd >= 0 else { return nil }
            defer { close(listenFd) }

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = Array(path.utf8)
            withUnsafeMutablePointer(to: &addr.sun_path) { p in
                p.withMemoryRebound(to: UInt8.self, capacity: 104) { raw in
                    for i in 0..<pathBytes.count { raw[i] = pathBytes[i] }
                    raw[pathBytes.count] = 0
                }
            }
            let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let rc = withUnsafePointer(to: &addr) { ap in
                ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFd, $0, addrLen) }
            }
            guard rc == 0 else { return nil }
            listen(listenFd, 1)

            let connFd = accept(listenFd, nil, nil)
            guard connFd >= 0 else { return nil }
            defer { close(connFd) }

            var buf = Data()
            var tmp = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = tmp.withUnsafeMutableBufferPointer { ptr in
                    read(connFd, ptr.baseAddress, ptr.count)
                }
                if n <= 0 { break }
                buf.append(tmp, count: n)
                guard let (frame, _) = extractNextFrame(from: buf) else { continue }
                guard let req = try? decodeWireRequest(frame) else { break }
                if let out = try? encodeWireFrame(response) {
                    _ = out.withUnsafeBytes { ptr in
                        write(connFd, ptr.baseAddress, out.count)
                    }
                }
                return req.method
            }
            return nil
        }
    }

    // MARK: - TCP-WN-01: delete sends "secret.delete"

    @Test("TCP-WN-01: delete(name:) sends secret.delete wire name")
    func test_delete_sendsSecretDeleteWireName() async throws {
        let path = Self.tmpSocketPath()
        let brokerTask = loopbackCapture(
            path: path,
            respondWith: WireResponse(id: "wn-01", result: .object(["ok": .bool(true)]))
        )
        // Yield briefly so the broker task can bind the socket before client connects.
        try await Task.sleep(nanoseconds: 10_000_000)
        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: path))
        _ = try? await client.delete(name: "test-key")
        let method = await brokerTask.value
        #expect(method == "secret.delete", "delete must send 'secret.delete' wire name; got \(method ?? "nil")")
    }

    // MARK: - TCP-WN-02: set sends "secret.set"

    @Test("TCP-WN-02: set(name:value:) sends secret.set wire name")
    func test_set_sendsSecretSetWireName() async throws {
        let path = Self.tmpSocketPath()
        let brokerTask = loopbackCapture(
            path: path,
            respondWith: WireResponse(id: "wn-02", result: .object(["ok": .bool(true)]))
        )
        try await Task.sleep(nanoseconds: 10_000_000)
        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: path))
        _ = try? await client.set(name: "k", value: "v")
        let method = await brokerTask.value
        #expect(method == "secret.set", "set must send 'secret.set' wire name; got \(method ?? "nil")")
    }

    // MARK: - TCP-WN-03: list sends "secret.list"

    @Test("TCP-WN-03: list(filter:) sends secret.list wire name")
    func test_list_sendsSecretListWireName() async throws {
        let path = Self.tmpSocketPath()
        let brokerTask = loopbackCapture(
            path: path,
            respondWith: WireResponse(id: "wn-03", result: .array([]))
        )
        try await Task.sleep(nanoseconds: 10_000_000)
        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: path))
        _ = try? await client.list(filter: nil)
        let method = await brokerTask.value
        #expect(method == "secret.list", "list must send 'secret.list' wire name; got \(method ?? "nil")")
    }

    // MARK: - TCP-WN-04: get sends "secret.get"

    @Test("TCP-WN-04: get(name:) sends secret.get wire name")
    func test_get_sendsSecretGetWireName() async throws {
        let path = Self.tmpSocketPath()
        let brokerTask = loopbackCapture(
            path: path,
            respondWith: WireResponse(id: "wn-04", result: .string("value"))
        )
        try await Task.sleep(nanoseconds: 10_000_000)
        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: path))
        _ = try? await client.get(name: "k")
        let method = await brokerTask.value
        #expect(method == "secret.get", "get must send 'secret.get' wire name; got \(method ?? "nil")")
    }

    // MARK: - TCP-WN-05: rotate sends "secret.rotate"

    @Test("TCP-WN-05: rotate(name:) sends secret.rotate wire name")
    func test_rotate_sendsSecretRotateWireName() async throws {
        let path = Self.tmpSocketPath()
        // Provide a valid RotationResult JSON so the client decode succeeds.
        let rotateResult: JSONValue = .object([
            "secretName":   .string("test-key"),
            "oldJtiSuffix": .string("abcd"),
            "invalidAt":    .string("2026-11-02T10:00:00Z"),
        ])
        let brokerTask = loopbackCapture(
            path: path,
            respondWith: WireResponse(id: "wn-05", result: rotateResult)
        )
        try await Task.sleep(nanoseconds: 10_000_000)
        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: path))
        _ = try? await client.rotate(name: "test-key")
        let method = await brokerTask.value
        #expect(method == "secret.rotate", "rotate must send 'secret.rotate' wire name; got \(method ?? "nil")")
    }
}
