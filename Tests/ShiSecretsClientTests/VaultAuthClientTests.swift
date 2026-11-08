import Foundation
@testable import ShiSecretsClient
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// VaultAuthClientTests - the client turns the named wire codes into
// BrokerClientError.vaultAuthRequired (carrying reason + remedy) and keeps
// every other broker error as brokerError. Real unix socket, canned broker.

@Suite("VaultAuthClient")
struct VaultAuthClientTests {

    /// Listens on a temp unix socket, answers ONE request with `response`.
    private func serveOnce(path: String, response: WireResponse) throws -> Task<Void, Never> {
        let fd = socket(AF_UNIX, Int32(SOCK_STREAM), 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            let bytes = Array(path.utf8) + [0]
            raw.copyBytes(from: bytes.prefix(raw.count))
        }
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, listen(fd, 1) == 0 else { close(fd); throw POSIXError(.EADDRINUSE) }
        return Task.detached {
            defer { close(fd); unlink(path) }
            let conn = accept(fd, nil, nil)
            guard conn >= 0 else { return }
            defer { close(conn) }
            var buffer = Data()
            var buf = [UInt8](repeating: 0, count: 4096)
            while extractNextFrame(from: buffer) == nil {
                let n = buf.withUnsafeMutableBufferPointer { read(conn, $0.baseAddress, $0.count) }
                if n <= 0 { return }
                buffer.append(buf, count: n)
            }
            guard let (frame, _) = extractNextFrame(from: buffer),
                  let req = try? decodeWireRequest(frame) else { return }
            let reply = WireResponse(id: req.id, error: response.error!)
            if let out = try? encodeWireFrame(reply) {
                _ = out.withUnsafeBytes { write(conn, $0.baseAddress, out.count) }
            }
        }
    }

    private func listError(_ wireError: WireError) async throws -> BrokerClientError {
        let path = "/tmp/sh-vac-\(UUID().uuidString.prefix(8)).s"
        let server = try serveOnce(path: path, response: WireResponse(id: nil, error: wireError))
        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: path))
        do {
            _ = try await client.list(filter: nil)
            Issue.record("list must throw")
            throw POSIXError(.EIO)
        } catch let e as BrokerClientError {
            await server.value
            return e
        }
    }

    @Test("vault_locked wire error becomes vaultAuthRequired(.locked)")
    func lockedMaps() async throws {
        let e = try await listError(VaultAuthRequired.locked.wireError())
        #expect(e == .vaultAuthRequired(.locked))
        #expect(e.vaultAuthRequired?.remedy == "shi secrets unlock")
    }

    @Test("not_logged_in wire error becomes vaultAuthRequired(.notLoggedIn)")
    func notLoggedInMaps() async throws {
        let e = try await listError(VaultAuthRequired.sessionExpired.wireError())
        #expect(e.vaultAuthRequired?.kind == .notLoggedIn)
    }

    @Test("an internal error stays brokerError(-32603)")
    func internalStaysBrokerError() async throws {
        let e = try await listError(WireError(code: WireErrorCode.internalError, message: "secret.list failed: boom"))
        #expect(e == .brokerError(code: -32603, message: "secret.list failed: boom"))
        #expect(e.vaultAuthRequired == nil)
    }

    @Test("CLI report returns the distinct exit code; other errors are left to the caller")
    func reportExitCodes() {
        #expect(reportVaultAuthRequired(BrokerClientError.vaultAuthRequired(.locked), json: true) == 3)
        #expect(reportVaultAuthRequired(BrokerClientError.vaultAuthRequired(.sessionExpired), json: true) == 4)
        #expect(reportVaultAuthRequired(BrokerClientError.brokerError(code: -32603, message: "x"), json: true) == nil)
        #expect(reportVaultAuthRequired(BrokerClientError.connectionClosed, json: true) == nil)
    }
}
