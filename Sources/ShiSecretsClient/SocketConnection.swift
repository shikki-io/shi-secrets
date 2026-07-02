// kagami-scope: exempt — resolver-exempt marker only (no behavioral change); package has no .kagami/scopes.yaml coverage.
import Foundation
import ShiSecretsKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// SocketConnection — minimal POSIX Unix-socket client wrapper.
//
// Phase 0.2 supporting layer. Opens a SOCK_STREAM connection to the
// broker socket, sends one wire frame, reads one wire frame, closes.
// New connection per request — simple, matches the broker's
// per-connection serveConnection loop (Phase 0.1).
//
// Single-frame request/response semantics — multi-frame conversations
// land in Phase 0.4 when streaming is needed.

public struct SocketConnection: Sendable {

    /// Default broker socket path. Operator-scoped path; production
    /// daemon-managed path is `/run/shikki-secrets.sock` per BR-D-02.
    ///
    /// Single source of truth: `BrokerSocketPath.resolve()` in ShiSecretsKit.
    /// Every other consumer (daemon, CLI verbs, doctor, wizard) references
    /// that same helper — see policy `dry_single_source_of_truth`.
    public static let defaultSocketPath: String = BrokerSocketPath.resolve()

    public let socketPath: String

    public init(socketPath: String = SocketConnection.defaultSocketPath) {
        self.socketPath = socketPath
    }

    /// Open a connection, send the request frame, read one response
    /// frame, close. Throws on socket open / IO / decode failure.
    public func roundTrip(_ request: WireRequest) async throws -> WireResponse {
        let fd = try openConnection(path: socketPath)
        defer { close(fd) }

        // Send framed request
        let outFrame = try encodeWireFrame(request)
        try writeAll(fd: fd, data: outFrame)

        // Read response frame
        let inFrame = try readFrame(fd: fd)
        let resp = try JSONDecoder().decode(WireResponse.self, from: inFrame)
        return resp
    }

    // MARK: - Internal IO

    private func openConnection(path: String) throws -> Int32 {
        let sock = socket(AF_UNIX, Int32(SOCK_STREAM), 0)
        guard sock >= 0 else {
            throw BrokerClientError.socketUnavailable(path: path, errno: errno)
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < cap else {
            close(sock)
            throw BrokerClientError.socketUnavailable(path: path, errno: ENAMETOOLONG)
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: cap) { raw in
                for i in 0..<pathBytes.count { raw[i] = pathBytes[i] }
                raw[pathBytes.count] = 0
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(sock, sockaddrPtr, addrLen)
            }
        }
        guard rc == 0 else {
            let e = errno
            close(sock)
            throw BrokerClientError.socketUnavailable(path: path, errno: e)
        }
        return sock
    }

    private func writeAll(fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { rawPtr in
            var remaining = data.count
            var cursor = rawPtr.baseAddress!
            while remaining > 0 {
                let n = write(fd, cursor, remaining)
                if n <= 0 {
                    throw BrokerClientError.socketUnavailable(path: socketPath, errno: errno)
                }
                cursor = cursor.advanced(by: n)
                remaining -= n
            }
        }
    }

    private func readFrame(fd: Int32) throws -> Data {
        var buffer = Data()
        var readBuf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = readBuf.withUnsafeMutableBufferPointer { ptr -> Int in
                read(fd, ptr.baseAddress, ptr.count)
            }
            if n == 0 {
                if buffer.isEmpty { throw BrokerClientError.connectionClosed }
                return buffer
            }
            if n < 0 {
                throw BrokerClientError.socketUnavailable(path: socketPath, errno: errno)
            }
            buffer.append(readBuf, count: n)
            if buffer.count > WireMaxFrameSize + 1 {
                throw BrokerClientError.wireDecodeFailed("frame > \(WireMaxFrameSize) bytes")
            }
            // Look for newline terminator
            if let (frame, _) = extractNextFrame(from: buffer) {
                return frame
            }
        }
    }
}
