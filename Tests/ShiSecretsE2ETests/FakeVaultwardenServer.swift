// FakeVaultwardenServer — minimal loopback HTTP/1.1 server for BrokerProcessE2ETests.
//
// Implements the Bitwarden API subset that VaultwardenClient calls:
//   POST /identity/connect/token     — client_credentials token exchange
//   POST /identity/accounts/prelogin — KDF parameters
//   POST /api/ciphers                — create cipher (encrypted)
//   GET  /api/ciphers                — list ciphers
//   GET  /api/ciphers/{id}           — fetch cipher
//   DELETE /api/ciphers/{id}         — delete cipher
//
// Thread-safe: cipher state is protected by NSLock.
// Ephemeral port: bind to 127.0.0.1:0 → actual port in `port` after start().
//
// The protected key is pre-computed from the fixture masterPassword+email
// so VaultwardenClient.unlock() can decrypt it with real PBKDF2 crypto.

import Foundation
import ShiSecretsKit

#if canImport(Darwin)
import Darwin
import Security
#endif

// MARK: - FakeVaultwardenServer

final class FakeVaultwardenServer: @unchecked Sendable {

    // MARK: State

    private(set) var port: Int = 0
    private var listenFD: Int32 = -1
    private var _running = true

    private let stateLock  = NSLock()
    private var _ciphers: [String: CipherRow] = [:]

    struct CipherRow {
        let id: String
        let encName: String   // serialized EncString from client
        let encNotes: String  // serialized EncString from client
    }

    // MARK: Fixture

    let accessToken: String
    let protectedKey: String   // serialized EncString valid for fixture credentials
    let kdfIterations = 5_000

    // MARK: Credentials

    let clientID: String
    let clientSecret: String

    // MARK: Init

    /// - Parameters:
    ///   - clientID:       OAuth client_id the server accepts
    ///   - clientSecret:   OAuth client_secret the server accepts
    ///   - masterPassword: Fixture master password; used to compute `protectedKey`
    ///   - email:          Fixture email (used as KDF salt)
    init(
        clientID: String,
        clientSecret: String,
        masterPassword: String,
        email: String
    ) throws {
        self.clientID      = clientID
        self.clientSecret  = clientSecret
        self.accessToken   = "fake-e2e-tok-\(UUID().uuidString.prefix(8))"

        // Derive the stretched key from fixture credentials.
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

    func start() throws {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw FakeServerError.bind(errno) }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var sa = sockaddr_in()
        sa.sin_family  = sa_family_t(AF_INET)
        sa.sin_port    = 0  // OS picks ephemeral port
        sa.sin_addr    = in_addr(s_addr: Darwin.inet_addr("127.0.0.1"))
        memset(&sa.sin_zero, 0, MemoryLayout.size(ofValue: sa.sin_zero))

        let bindRC = withUnsafePointer(to: &sa) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRC == 0 else { Darwin.close(fd); throw FakeServerError.bind(errno) }

        // Read back actual port.
        var bound = sockaddr_in()
        var boundLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &boundLen)
            }
        }
        port = Int(UInt16(bigEndian: bound.sin_port))

        guard Darwin.listen(fd, 8) == 0 else { Darwin.close(fd); throw FakeServerError.bind(errno) }
        listenFD = fd

        Thread.detachNewThread { [weak self] in self?.acceptLoop() }
    }

    func stop() {
        _running = false
        if listenFD >= 0 { Darwin.close(listenFD); listenFD = -1 }
    }

    // MARK: Assertions

    /// Asserts all stored ciphers carry serialized EncStrings (not plaintext).
    /// Throws if any field looks like plaintext (missing the `2.` type prefix).
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

    // MARK: - Accept loop

    private func acceptLoop() {
        while _running {
            let clientFD = Darwin.accept(listenFD, nil, nil)
            if clientFD < 0 { break }
            Thread.detachNewThread { [weak self] in
                self?.handleConn(clientFD)
            }
        }
    }

    private func handleConn(_ fd: Int32) {
        defer { Darwin.close(fd) }
        guard let (method, path, body) = readHTTPRequest(fd) else { return }
        let (status, responseBody) = route(method: method, path: path, body: body)
        sendHTTPResponse(fd, status: status, body: responseBody)
    }

    // MARK: - HTTP read (minimal, not RFC-complete)

    private func readHTTPRequest(_ fd: Int32) -> (method: String, path: String, body: String)? {
        // Accumulate bytes until \r\n\r\n marks end of headers.
        var headerAccum = ""
        var oneByte = [UInt8](repeating: 0, count: 1)
        while !headerAccum.hasSuffix("\r\n\r\n") {
            guard Darwin.read(fd, &oneByte, 1) == 1 else { return nil }
            headerAccum.append(Character(UnicodeScalar(oneByte[0])))
            if headerAccum.count > 32_768 { return nil }  // guard against runaway
        }

        let lines = headerAccum.components(separatedBy: "\r\n")
        let requestLine = lines.first?.components(separatedBy: " ") ?? []
        guard requestLine.count >= 2 else { return nil }
        let method = requestLine[0]
        let path   = requestLine[1]

        // Parse Content-Length.
        var contentLength = 0
        for line in lines.dropFirst() {
            if line.lowercased().hasPrefix("content-length:") {
                let valStr = line.dropFirst("content-length:".count)
                    .trimmingCharacters(in: .whitespaces)
                contentLength = Int(valStr) ?? 0
            }
        }

        var body = ""
        if contentLength > 0 {
            var buf = [UInt8](repeating: 0, count: contentLength)
            var total = 0
            while total < contentLength {
                let n = Darwin.read(fd, &buf[total], contentLength - total)
                guard n > 0 else { break }
                total += n
            }
            body = String(bytes: buf.prefix(total), encoding: .utf8) ?? ""
        }

        return (method, path, body)
    }

    // MARK: - HTTP write

    private func sendHTTPResponse(_ fd: Int32, status: Int, body: String) {
        let statusText = status == 200 ? "OK" : (status == 400 ? "Bad Request" : "Not Found")
        let header = "HTTP/1.1 \(status) \(statusText)\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: \(body.utf8.count)\r\n" +
            "Connection: close\r\n\r\n"
        let bytes = Array((header + body).utf8)
        Darwin.write(fd, bytes, bytes.count)
    }

    // MARK: - Route dispatch

    private func route(method: String, path: String, body: String) -> (Int, String) {
        // Strip query string for routing.
        let cleanPath = path.components(separatedBy: "?").first ?? path

        switch (method, cleanPath) {
        case ("POST", let p) where p.hasSuffix("/identity/connect/token"):
            return handleConnectToken(body: body)
        case ("POST", let p) where p.hasSuffix("/identity/accounts/prelogin"):
            return handlePrelogin()
        case ("POST", "/api/ciphers"):
            return handleCreateCipher(body: body)
        case ("GET", "/api/ciphers"):
            return handleListCiphers()
        case ("GET", let p) where p.hasPrefix("/api/ciphers/"):
            return handleGetCipher(id: String(p.dropFirst("/api/ciphers/".count)))
        case ("DELETE", let p) where p.hasPrefix("/api/ciphers/"):
            return handleDeleteCipher(id: String(p.dropFirst("/api/ciphers/".count)))
        default:
            return (404, #"{"error":"not found","path":"\#(cleanPath)"}"#)
        }
    }

    // MARK: - Handlers

    private func handleConnectToken(body: String) -> (Int, String) {
        // Parse application/x-www-form-urlencoded.
        var params: [String: String] = [:]
        for pair in body.components(separatedBy: "&") {
            let kv = pair.components(separatedBy: "=")
            guard kv.count == 2 else { continue }
            let key = kv[0]
            let val = kv[1].replacingOccurrences(of: "+", with: " ")
                           .removingPercentEncoding ?? kv[1]
            params[key] = val
        }

        guard params["client_id"]     == clientID,
              params["client_secret"] == clientSecret else {
            return (400, #"{"error":"invalid_client","error_description":"client credentials invalid"}"#)
        }
        guard params["deviceType"] != nil,
              params["deviceIdentifier"] != nil else {
            return (400, #"{"error":"invalid_client","error_description":"Device field is required"}"#)
        }

        // Escape protectedKey for JSON embedding — it contains | and . but no " or \
        let json = """
        {"access_token":"\(accessToken)","expires_in":3600,"token_type":"Bearer",\
        "Key":"\(protectedKey)","Kdf":0,"KdfIterations":\(kdfIterations)}
        """
        return (200, json)
    }

    private func handlePrelogin() -> (Int, String) {
        return (200, #"{"Kdf":0,"KdfIterations":5000}"#)
    }

    private func handleCreateCipher(body: String) -> (Int, String) {
        guard let data = body.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let encName  = obj["name"]  as? String,
              let encNotes = obj["notes"] as? String else {
            return (400, #"{"error":"missing or invalid fields"}"#)
        }
        let id = UUID().uuidString
        stateLock.lock()
        _ciphers[id] = CipherRow(id: id, encName: encName, encNotes: encNotes)
        stateLock.unlock()
        // Response: {id, name} — client only reads `id` from CreateResponse.
        return (200, #"{"id":"\#(id)","name":"\#(encName)"}"#)
    }

    private func handleListCiphers() -> (Int, String) {
        stateLock.lock()
        let rows = Array(_ciphers.values)
        stateLock.unlock()
        // ListResponse: {data:[{id, name}]}
        let items = rows.map { #"{"id":"\#($0.id)","name":"\#($0.encName)"}"# }
                        .joined(separator: ",")
        return (200, #"{"data":[\#(items)]}"#)
    }

    private func handleGetCipher(id: String) -> (Int, String) {
        stateLock.lock()
        let row = _ciphers[id]
        stateLock.unlock()
        guard let row else {
            return (404, #"{"error":"cipher not found"}"#)
        }
        // CipherResponse: {id, name, notes}
        return (200, #"{"id":"\#(row.id)","name":"\#(row.encName)","notes":"\#(row.encNotes)"}"#)
    }

    private func handleDeleteCipher(id: String) -> (Int, String) {
        stateLock.lock()
        _ciphers.removeValue(forKey: id)
        stateLock.unlock()
        return (200, "{}")
    }
}

// MARK: - Errors

enum FakeServerError: Error, CustomStringConvertible {
    case bind(Int32)
    case plaintextField(String, String)

    var description: String {
        switch self {
        case .bind(let e):                  return "FakeVaultwardenServer: bind failed, errno=\(e)"
        case .plaintextField(let f, let v): return "FakeVaultwardenServer: field '\(f)' is plaintext: \(v.prefix(32))…"
        }
    }
}
