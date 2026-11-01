// FakeVaultwardenServer — Hummingbird-backed loopback HTTP server for BrokerProcessE2ETests.
//
// Replaces the hand-rolled POSIX HTTP/1.1 server with the Hummingbird 2.x framework
// (TEST-ONLY dep — never linked into shi-secrets-brokerd or ShiSecretsKit).
//
// Endpoints served:
//   POST /identity/connect/token     — client_credentials token exchange
//   POST /identity/accounts/prelogin — KDF parameters
//   POST /api/ciphers                — create cipher (encrypted)
//   GET  /api/ciphers                — list ciphers
//   GET  /api/ciphers/:id            — fetch cipher
//   DELETE /api/ciphers/:id          — delete cipher
//
// Typed Codable models (VaultwardenWireModels.swift) are used for all
// encode/decode operations so server and client can't drift without a
// JSONDecoder failure catching the mismatch.
//
// Thread-safety: cipher state is protected by NSLock — no `await` is held
// while the lock is acquired, so there is no risk of actor re-entrancy.
// This keeps assertCiphersAreEncrypted() and start() synchronous (non-async)
// matching the original API contract consumed by BrokerProcessE2ETests.
//
// Ephemeral port: a POSIX socket is opened on 127.0.0.1:0 to have the kernel
// assign a free port; the fd is closed and that port is handed to Hummingbird.
// The TOCTOU window is microseconds — acceptable for test code.
//
// start() becomes async throws to poll until Hummingbird is accepting
// connections, giving the caller a reliable "server is ready" guarantee.

import Foundation
import Hummingbird
import NIOCore
import ShiSecretsKit

#if canImport(Darwin)
import Darwin
import Security
#endif

// MARK: - FakeVaultwardenServer

final class FakeVaultwardenServer: @unchecked Sendable {

    // MARK: Lifecycle

    private(set) var port: Int = 0
    private var serverTask: Task<Void, any Error>?

    // MARK: Cipher state (NSLock-protected, synchronous access)

    private let stateLock = NSLock()
    private var _ciphers: [String: CipherRow] = [:]

    struct CipherRow {
        let id: String
        let encName: String   // EncString wire form from client
        let encNotes: String  // EncString wire form from client
    }

    // MARK: Fixture (immutable after init)

    let accessToken: String
    let protectedKey: String     // serialized EncString valid for fixture credentials
    let kdfIterations: Int = 5_000
    let clientID: String
    let clientSecret: String

    // MARK: Init

    /// - Parameters:
    ///   - clientID:       OAuth client_id the server accepts
    ///   - clientSecret:   OAuth client_secret the server accepts
    ///   - masterPassword: Fixture master password; used to derive `protectedKey`
    ///   - email:          Fixture email (used as KDF salt)
    init(
        clientID: String,
        clientSecret: String,
        masterPassword: String,
        email: String
    ) throws {
        self.clientID     = clientID
        self.clientSecret = clientSecret
        self.accessToken  = "fake-e2e-tok-\(UUID().uuidString.prefix(8))"

        // Derive the stretched key from fixture credentials — real PBKDF2 crypto.
        let masterKey = try BitwardenCrypto.masterKey(
            masterPassword: masterPassword,
            email: email,
            kdf: .pbkdf2SHA256,
            iterations: kdfIterations
        )
        let stretched = BitwardenCrypto.stretchMasterKey(masterKey)

        // Generate a random 64-byte account key (32 encKey + 32 macKey).
        var raw = [UInt8](repeating: 0, count: 64)
        _ = SecRandomCopyBytes(kSecRandomDefault, 64, &raw)
        let userKeyData = Data(raw)

        // Encrypt account key with stretched master key → protectedKey wire form.
        let enc = try BitwardenCrypto.encrypt(userKeyData, using: stretched)
        self.protectedKey = enc.serialized
    }

    // MARK: Lifecycle

    /// Start the server. Async to poll until Hummingbird is accepting connections.
    func start() async throws {
        port = try Self.allocateEphemeralPort()

        // Capture immutable state for the Hummingbird closures.
        let capturedToken     = accessToken
        let capturedKey       = protectedKey
        let capturedKdfIter   = kdfIterations
        let capturedClientID  = clientID
        let capturedSecret    = clientSecret
        let capturedSelf      = self
        let capturedPort      = port

        serverTask = Task {
            let router = Router()

            // POST /identity/connect/token
            router.post("/identity/connect/token") { req, _ in
                try await capturedSelf.handleToken(
                    req,
                    token: capturedToken,
                    protectedKey: capturedKey,
                    kdfIter: capturedKdfIter,
                    clientID: capturedClientID,
                    clientSecret: capturedSecret
                )
            }

            // POST /identity/accounts/prelogin
            router.post("/identity/accounts/prelogin") { _, _ in
                try Self.makeJSONResponse(
                    VWPreloginResponse(Kdf: 0, KdfIterations: capturedKdfIter)
                )
            }

            // POST /api/ciphers
            router.post("/api/ciphers") { req, _ in
                try await capturedSelf.handleCreateCipher(req)
            }

            // GET /api/ciphers
            router.get("/api/ciphers") { _, _ in
                try capturedSelf.handleListCiphers()
            }

            // GET /api/ciphers/:id
            router.get("/api/ciphers/:id") { _, ctx in
                let id = String(ctx.parameters.get("id") ?? "")
                return try capturedSelf.handleGetCipher(id: id)
            }

            // DELETE /api/ciphers/:id
            router.delete("/api/ciphers/:id") { _, ctx in
                let id = String(ctx.parameters.get("id") ?? "")
                return try capturedSelf.handleDeleteCipher(id: id)
            }

            let app = Application(
                router: router,
                configuration: .init(address: .hostname("127.0.0.1", port: capturedPort))
            )
            try await app.run()
        }

        // Poll until the server is accepting connections (up to 5 s).
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if Self.isListening(on: port) { return }
            try await Task.sleep(nanoseconds: 20_000_000)  // 20 ms
        }
        // Timed out — cancel the server task and surface an error.
        serverTask?.cancel()
        serverTask = nil
        throw FakeServerError.startupTimeout
    }

    func stop() {
        serverTask?.cancel()
        serverTask = nil
    }

    // MARK: Assertions

    /// Asserts all stored ciphers carry EncStrings (not plaintext).
    /// Throws if any field does not carry the `2.` AES256_CBC_HMAC_SHA256 prefix.
    func assertCiphersAreEncrypted() throws {
        stateLock.lock()
        let rows = Array(_ciphers.values)
        stateLock.unlock()
        for row in rows {
            guard row.encName.hasPrefix("2.") else {
                throw FakeServerError.plaintextField("name", row.encName)
            }
            guard row.encNotes.hasPrefix("2.") else {
                throw FakeServerError.plaintextField("notes", row.encNotes)
            }
        }
    }

    // MARK: - Route handlers

    private func handleToken(
        _ req: Request,
        token: String,
        protectedKey: String,
        kdfIter: Int,
        clientID: String,
        clientSecret: String
    ) async throws -> Response {
        // Collect request body (form-encoded).
        var buffer = try await req.body.collect(upTo: 65_536)
        let data   = buffer.readData(length: buffer.readableBytes) ?? Data()
        let body   = String(data: data, encoding: .utf8) ?? ""

        // Parse application/x-www-form-urlencoded.
        var params: [String: String] = [:]
        for pair in body.components(separatedBy: "&") {
            let kv = pair.components(separatedBy: "=")
            guard kv.count >= 2 else { continue }
            let key = kv[0]
            let val = kv[1...].joined(separator: "=")
                              .replacingOccurrences(of: "+", with: " ")
                              .removingPercentEncoding ?? kv[1]
            params[key] = val
        }

        guard params["client_id"] == clientID,
              params["client_secret"] == clientSecret else {
            return try Self.makeErrorResponse(
                status: .badRequest,
                error: "invalid_client",
                description: "client credentials invalid"
            )
        }
        guard params["deviceType"] != nil,
              params["deviceIdentifier"] != nil else {
            return try Self.makeErrorResponse(
                status: .badRequest,
                error: "invalid_client",
                description: "Device field is required"
            )
        }

        return try Self.makeJSONResponse(VWTokenResponse(
            access_token: token,
            expires_in:   3600,
            token_type:   "Bearer",
            Key:          protectedKey,
            Kdf:          0,
            KdfIterations: kdfIter
        ))
    }

    private func handleCreateCipher(_ req: Request) async throws -> Response {
        var buffer = try await req.body.collect(upTo: 65_536)
        guard let data = buffer.readData(length: buffer.readableBytes) else {
            return try Self.makeErrorResponse(status: .badRequest, error: "empty_body")
        }
        let body: VWCipherCreateRequest
        do {
            body = try JSONDecoder().decode(VWCipherCreateRequest.self, from: data)
        } catch {
            return try Self.makeErrorResponse(status: .badRequest, error: "invalid_body")
        }

        let id = UUID().uuidString
        stateLock.lock()
        _ciphers[id] = CipherRow(id: id, encName: body.name, encNotes: body.notes)
        stateLock.unlock()

        return try Self.makeJSONResponse(VWCipherCreateResponse(id: id, name: body.name))
    }

    private func handleListCiphers() throws -> Response {
        stateLock.lock()
        let rows = Array(_ciphers.values)
        stateLock.unlock()
        let items = rows.map { VWCipherListItem(id: $0.id, name: $0.encName) }
        return try Self.makeJSONResponse(VWCipherListResponse(data: items))
    }

    private func handleGetCipher(id: String) throws -> Response {
        stateLock.lock()
        let row = _ciphers[id]
        stateLock.unlock()
        guard let row else {
            return try Self.makeErrorResponse(status: .notFound, error: "cipher_not_found")
        }
        return try Self.makeJSONResponse(
            VWCipherItemResponse(id: row.id, name: row.encName, notes: row.encNotes)
        )
    }

    private func handleDeleteCipher(id: String) throws -> Response {
        stateLock.lock()
        _ciphers.removeValue(forKey: id)
        stateLock.unlock()
        return try Self.makeJSONResponse(VWEmpty())
    }

    // MARK: - JSON response helpers

    private static func makeJSONResponse<T: Encodable>(_ value: T) throws -> Response {
        let data = try JSONEncoder().encode(value)
        var headers = HTTPFields()
        headers[.contentType] = "application/json"
        return Response(
            status: .ok,
            headers: headers,
            body: ResponseBody(byteBuffer: ByteBuffer(bytes: Array(data)))
        )
    }

    private static func makeErrorResponse(
        status: HTTPResponse.Status,
        error: String,
        description: String? = nil
    ) throws -> Response {
        let data = try JSONEncoder().encode(
            VWErrorBody(error: error, error_description: description)
        )
        var headers = HTTPFields()
        headers[.contentType] = "application/json"
        return Response(
            status: status,
            headers: headers,
            body: ResponseBody(byteBuffer: ByteBuffer(bytes: Array(data)))
        )
    }

    // MARK: - Port helpers

    /// Bind to 127.0.0.1:0 to have the kernel assign a free ephemeral port.
    /// Closes the fd immediately — Hummingbird re-binds to the same port.
    /// TOCTOU window is microseconds; acceptable in test code.
    private static func allocateEphemeralPort() throws -> Int {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw FakeServerError.portAlloc(errno) }
        defer { Darwin.close(fd) }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port   = 0
        sa.sin_addr   = in_addr(s_addr: Darwin.inet_addr("127.0.0.1"))
        memset(&sa.sin_zero, 0, MemoryLayout.size(ofValue: sa.sin_zero))

        let bindRC = withUnsafePointer(to: &sa) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRC == 0 else { throw FakeServerError.portAlloc(errno) }

        var bound    = sockaddr_in()
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &boundLen)
            }
        }
        return Int(UInt16(bigEndian: bound.sin_port))
    }

    /// Probe whether a TCP server is accepting connections on loopback:port.
    private static func isListening(on port: Int) -> Bool {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }

        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port   = in_port_t(UInt16(port).bigEndian)
        sa.sin_addr   = in_addr(s_addr: Darwin.inet_addr("127.0.0.1"))
        memset(&sa.sin_zero, 0, MemoryLayout.size(ofValue: sa.sin_zero))

        let rc = withUnsafePointer(to: &sa) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return rc == 0
    }
}

// MARK: - Errors

enum FakeServerError: Error, CustomStringConvertible {
    case portAlloc(Int32)
    case startupTimeout
    case plaintextField(String, String)

    var description: String {
        switch self {
        case .portAlloc(let e):
            return "FakeVaultwardenServer: port allocation failed, errno=\(e)"
        case .startupTimeout:
            return "FakeVaultwardenServer: server did not become ready within 5 s"
        case .plaintextField(let f, let v):
            return "FakeVaultwardenServer: field '\(f)' is plaintext: \(v.prefix(32))…"
        }
    }
}
