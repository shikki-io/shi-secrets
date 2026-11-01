// FakeVaultwardenServer — Vapor-backed loopback HTTP server for BrokerProcessE2ETests.
//
// Replaces the Hummingbird 2.x implementation with Vapor 4.x
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
//
// Port allocation: In Vapor 4.122.x, app.http.server.shared.localAddress
// returns nil after startup() because NIO's channel binding completes
// asynchronously. We pre-bind a POSIX socket to port 0 to get the OS-
// assigned ephemeral port, close it immediately, and tell Vapor to use that
// specific port. The tiny race window is acceptable in a loopback test.
//
// start() is async throws, using Application.make(.testing) async factory
// and app.startup() to bind the port and start the server.
//
// stop() is synchronous (called from defer blocks). It calls app.shutdown()
// (Vapor's sync lifecycle API) which runs lifecycle.shutdown() + lifecycle.wait(),
// stopping the ServeCommand and satisfying Vapor's deinit assertion.

import Foundation
import Vapor
import ShiSecretsKit

#if canImport(Darwin)
import Security
#endif

// MARK: - FakeVaultwardenServer

final class FakeVaultwardenServer: @unchecked Sendable {

    // MARK: Properties

    private var vaporApp: Application?
    private(set) var port: Int = 0

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

    /// Start the server on an ephemeral loopback port.
    ///
    /// Pre-binds a POSIX socket to port 0 to get the OS-assigned ephemeral port
    /// (Vapor 4.122.x does not reliably expose the port after startup via
    /// app.http.server.shared.localAddress — the NIO bind completes asynchronously
    /// and the property returns nil). The socket is closed before Vapor starts,
    /// leaving the port available. Loopback-only; tiny race window is acceptable.
    func start() async throws {
        let ephemeralPort = try Self.reserveEphemeralPort()

        var env = Environment.testing
        // Prevent ConsoleKit from reading the Swift Testing harness arguments
        // (e.g. --test-bundle-path) as unknown Vapor commands.
        env.arguments = ["vapor", "serve"]
        let app = try await Application.make(env)
        app.http.server.configuration.hostname = "127.0.0.1"
        app.http.server.configuration.port = ephemeralPort

        registerRoutes(on: app)
        do {
            try await app.startup()
        } catch {
            // asyncShutdown() is required here because shutdown() is noasync.
            // If startup() failed the ServeCommand was never set running, so
            // asyncShutdown() failing is acceptable — deinit assertion won't fire.
            try? await app.asyncShutdown()
            throw error
        }

        self.port = ephemeralPort
        self.vaporApp = app
    }

    /// Stop the server. Synchronous so it can be called from a defer block.
    ///
    /// Calling app.shutdown() (sync) from a cooperative pool thread deadlocks:
    /// lifecycle.wait() blocks while NIO's event loops need the same pool.
    /// Using Task.detached + DispatchSemaphore also deadlocks if all pool threads
    /// are occupied.
    ///
    /// Correct approach: call app.running?.stop(), which fires the closure
    /// registered by ServeCommand.run() that sets ServeCommand.running = false
    /// — this is the only flag the deinit assertion checks. The Application and
    /// its NIO event loop group are then released via ARC when vaporApp is nil.
    func stop() {
        guard let app = vaporApp else { return }
        vaporApp = nil
        app.running?.stop()   // sets ServeCommand.running = false → satisfies deinit assert
    }

    // MARK: - Port allocation

    /// Pre-bind a POSIX socket to port 0 to obtain an OS-assigned ephemeral port,
    /// then immediately close the socket. The caller uses the returned port number.
    private static func reserveEphemeralPort() throws -> Int {
        let sock = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { throw FakeServerError.portNotBound }
        defer { Darwin.close(sock) }

        var reuseAddr: Int32 = 1
        Darwin.setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = UInt32(bigEndian: INADDR_LOOPBACK)
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, addrLen) }
        }
        guard bindResult == 0 else { throw FakeServerError.portNotBound }

        let nameResult = withUnsafeMutablePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.getsockname(sock, $0, &addrLen) }
        }
        guard nameResult == 0 else { throw FakeServerError.portNotBound }

        return Int(addr.sin_port.bigEndian)
    }

    // MARK: Assertions

    /// Asserts all stored ciphers carry EncStrings (not plaintext).
    /// Throws if any field does not carry the `2.` AES256_CBC_HMAC_SHA256 prefix.
    func assertCiphersAreEncrypted() throws {
        let rows = stateLock.withLock { Array(_ciphers.values) }
        for row in rows {
            guard row.encName.hasPrefix("2.") else {
                throw FakeServerError.plaintextField("name", row.encName)
            }
            guard row.encNotes.hasPrefix("2.") else {
                throw FakeServerError.plaintextField("notes", row.encNotes)
            }
        }
    }

    // MARK: - Route registration

    private func registerRoutes(on app: Application) {
        let capturedSelf = self

        // POST /identity/connect/token
        app.post("identity", "connect", "token") { req async throws -> Response in
            try await capturedSelf.handleToken(req)
        }

        // POST /identity/accounts/prelogin
        app.post("identity", "accounts", "prelogin") { req async throws -> Response in
            try Self.makeJSONResponse(
                VWPreloginResponse(Kdf: 0, KdfIterations: capturedSelf.kdfIterations)
            )
        }

        // POST /api/ciphers
        app.post("api", "ciphers") { req async throws -> Response in
            try await capturedSelf.handleCreateCipher(req)
        }

        // GET /api/ciphers
        app.get("api", "ciphers") { req async throws -> Response in
            try capturedSelf.handleListCiphers()
        }

        // GET /api/ciphers/:id
        app.get("api", "ciphers", ":id") { req async throws -> Response in
            let id = req.parameters.get("id") ?? ""
            return try capturedSelf.handleGetCipher(id: id)
        }

        // DELETE /api/ciphers/:id
        app.delete("api", "ciphers", ":id") { req async throws -> Response in
            let id = req.parameters.get("id") ?? ""
            return try capturedSelf.handleDeleteCipher(id: id)
        }
    }

    // MARK: - Route handlers

    private func handleToken(_ req: Request) async throws -> Response {
        // Collect body; broker sends application/x-www-form-urlencoded.
        let maybeBuffer = try await req.body.collect(max: 65_536).get()
        let bodyString  = maybeBuffer.flatMap {
            $0.getString(at: $0.readerIndex, length: $0.readableBytes)
        } ?? ""

        // Parse application/x-www-form-urlencoded manually (robust to missing Content-Type).
        var params: [String: String] = [:]
        for pair in bodyString.components(separatedBy: "&") {
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
            return try Self.makeJSONResponse(
                VWErrorBody(error: "invalid_client", error_description: "client credentials invalid"),
                status: .badRequest
            )
        }
        guard params["deviceType"] != nil,
              params["deviceIdentifier"] != nil else {
            return try Self.makeJSONResponse(
                VWErrorBody(error: "invalid_client", error_description: "Device field is required"),
                status: .badRequest
            )
        }

        return try Self.makeJSONResponse(VWTokenResponse(
            access_token: accessToken,
            expires_in:   3600,
            token_type:   "Bearer",
            Key:          protectedKey,
            Kdf:          0,
            KdfIterations: kdfIterations
        ))
    }

    private func handleCreateCipher(_ req: Request) async throws -> Response {
        let maybeBuffer = try await req.body.collect(max: 65_536).get()
        guard let buffer = maybeBuffer else {
            return try Self.makeJSONResponse(
                VWErrorBody(error: "empty_body", error_description: nil),
                status: .badRequest
            )
        }
        let data = buffer.getData(at: buffer.readerIndex, length: buffer.readableBytes) ?? Data()
        let body: VWCipherCreateRequest
        do {
            body = try JSONDecoder().decode(VWCipherCreateRequest.self, from: data)
        } catch {
            return try Self.makeJSONResponse(
                VWErrorBody(error: "invalid_body", error_description: nil),
                status: .badRequest
            )
        }

        let id = UUID().uuidString
        stateLock.withLock {
            _ciphers[id] = CipherRow(id: id, encName: body.name, encNotes: body.notes)
        }

        return try Self.makeJSONResponse(VWCipherCreateResponse(id: id, name: body.name))
    }

    private func handleListCiphers() throws -> Response {
        let rows  = stateLock.withLock { Array(_ciphers.values) }
        let items = rows.map { VWCipherListItem(id: $0.id, name: $0.encName) }
        return try Self.makeJSONResponse(VWCipherListResponse(data: items))
    }

    private func handleGetCipher(id: String) throws -> Response {
        let row = stateLock.withLock { _ciphers[id] }
        guard let row else {
            return try Self.makeJSONResponse(
                VWErrorBody(error: "cipher_not_found", error_description: nil),
                status: .notFound
            )
        }
        return try Self.makeJSONResponse(
            VWCipherItemResponse(id: row.id, name: row.encName, notes: row.encNotes)
        )
    }

    private func handleDeleteCipher(id: String) throws -> Response {
        _ = stateLock.withLock { _ciphers.removeValue(forKey: id) }
        return try Self.makeJSONResponse(VWEmpty())
    }

    // MARK: - JSON response helpers

    private static func makeJSONResponse<T: Encodable>(
        _ value: T,
        status: HTTPStatus = .ok
    ) throws -> Response {
        let data = try JSONEncoder().encode(value)
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/json")
        return Response(
            status: status,
            headers: headers,
            body: .init(data: data)
        )
    }
}

// MARK: - Errors

enum FakeServerError: Error, CustomStringConvertible {
    case portNotBound
    case plaintextField(String, String)

    var description: String {
        switch self {
        case .portNotBound:
            return "FakeVaultwardenServer: Vapor did not bind a port after start()"
        case .plaintextField(let f, let v):
            return "FakeVaultwardenServer: field '\(f)' is plaintext: \(v.prefix(32))…"
        }
    }
}
