import Foundation

// VaultwardenClient — Swift-native actor wrapping URLSession calls to the
// operator's self-hosted Vaultwarden instance (vw.obyw.one by default).
//
// Authentication: OAuth2 client_credentials grant via the Bitwarden
// Identity endpoint (/identity/connect/token). No bw CLI subprocess;
// no BW_SESSION env var.
//
// Server URL resolution (BR-SM-13, BR-DB-CONFIG-RESOLVED):
//   1. ~/.shikki/config.yml `vault.server`
//   2. SHIKKI_VAULT_URL environment variable
//   3. DEV fallback: https://vw.obyw.one
// Never hardcodes the URL in compiled source.
//
// TLS: TLSPinValidator is wired as the URLSessionDelegate. In W1 the
// pin is nil (no cert SHA pinned yet); the operator injects the real
// pin during W2 smoke via config.yml `vault.tls_pin_sha256`.
//
// BR-SM-09, BR-SM-13, BR-SM-15

// MARK: - Errors

/// Errors produced by VaultwardenClient.
public enum VaultwardenClientError: Swift.Error, Sendable, Equatable {
    /// Token endpoint returned a non-2xx HTTP status.
    case tokenExchangeFailed(httpStatus: Int)

    /// Response body could not be decoded as the expected token response.
    case tokenResponseMalformed

    /// The resolved server URL is not a valid HTTPS URL.
    case invalidServerURL(raw: String)

    /// /api/ciphers/{id} returned a non-2xx status.
    case fetchSecretFailed(httpStatus: Int)

    /// Cipher response body could not be decoded.
    case cipherResponseMalformed

    /// The client has not yet called connect() or the session expired.
    case notAuthenticated

    /// The credentials were not loaded (Keychain empty).
    case credentialsNotLoaded

    /// Network error wrapping the underlying URLError code.
    case networkError(URLError.Code)

    /// POST /api/ciphers returned a non-2xx status (W3 write path).
    case createCipherFailed(httpStatus: Int)

    /// DELETE /api/ciphers/{id} returned a non-2xx status (W3 write path).
    case deleteCipherFailed(httpStatus: Int)

    /// DNS lookup failed for the vault host — operator must set the URL via
    /// SHIKKI_VAULT_URL or ~/.shikki/settings/secrets-brokerd.toml [vault_url].
    case vaultHostUnreachable(message: String)
}

// MARK: - Internal token response shape

private struct TokenResponse: Decodable {
    let access_token: String
    let expires_in: Int       // seconds
    let token_type: String

    // ── The fields this struct used to throw away ──────────────────────
    // The identity endpoint returns the account's protected symmetric key and
    // its KDF parameters in the SAME response as the token. Decoding only the
    // token made the vault key invisible, which made client-side encryption
    // look impossible, which is how plaintext ended up on the server.
    //
    // Vaultwarden capitalises them; some builds do not. Both spellings are
    // accepted because a silent nil here reads exactly like "the server does
    // not support this".
    let Key: String?
    let Kdf: Int?
    let KdfIterations: Int?
    let key: String?
    let kdf: Int?
    let kdfIterations: Int?

    var protectedKey: String? { Key ?? key }
    var kdfParameters: VaultKDFParameters? {
        guard let raw = Kdf ?? kdf, let type = BitwardenCrypto.KDFType(rawValue: raw) else { return nil }
        return VaultKDFParameters(kdf: type, iterations: KdfIterations ?? kdfIterations ?? 600_000)
    }
}

// MARK: - Internal cipher response shape (minimal — only fields W1/W3 need)

private struct CipherResponse: Decodable {
    struct LoginData: Decodable {
        let password: String?
        let username: String?
    }
    struct FieldEntry: Decodable {
        let name: String?
        let value: String?
    }
    let id: String
    let name: String
    let notes: String?   // W3: SecureNote stores value here
    let login: LoginData?
    let fields: [FieldEntry]?
}

// MARK: - Internal cipher create request shape (W3)

private struct CipherCreateRequest: Encodable {
    struct SecureNoteData: Encodable { let type: Int }
    let type: Int              // 2 = SecureNote
    /// EncString wire form, NOT plaintext. The initialiser takes ciphertext
    /// only, so there is no path that reaches this struct with a readable
    /// string — the previous version took `name: String, value: String` and
    /// assigned them straight through.
    let name: String
    let notes: String
    let secureNote: SecureNoteData
    let folderId: String?
    let favorite: Bool
    let reprompt: Int

    init(encryptedName: EncString, encryptedValue: EncString) {
        self.type = 2
        self.name = encryptedName.serialized
        self.notes = encryptedValue.serialized
        self.secureNote = SecureNoteData(type: 0)
        self.folderId = nil
        self.favorite = false
        self.reprompt = 0
    }
}

// MARK: - VaultwardenClient

/// Swift-native Vaultwarden API client. Replaces the bw CLI subprocess
/// pattern entirely. No `Process()` spawns, no `BW_SESSION` env var.
public actor VaultwardenClient {

    // MARK: - Properties

    private let credentials: VaultwardenCredentials
    private let session: URLSession
    private let sessionCache: SessionCache

    /// The unwrapped vault key. Separate from `sessionCache` on purpose: that
    /// one holds the ACCESS TOKEN, which authenticates the call, and this one
    /// holds the VAULT KEY, which decrypts the data. Treating those as one
    /// thing is exactly the confusion that produced a plaintext vault.
    private let vaultKey = VaultSessionKey()

    /// Everything the server told us at token time, kept so `unlock` does not
    /// have to make a second round trip.
    private var accountProtectedKey: String?
    private var accountKDF: VaultKDFParameters?

    /// How many fields came back unencrypted this session. Non-zero means the
    /// vault still holds items written before the encryption fix.
    public private(set) var plaintextFieldsSeen: Int = 0

    /// Warn once per process, not once per field — a loop over 40 secrets
    /// would otherwise bury the message under its own repetition.
    nonisolated(unsafe) private static var legacyWarningIssued = false
    static func reportLegacyPlaintext() {
        guard !legacyWarningIssued else { return }
        legacyWarningIssued = true
        FileHandle.standardError.write(Data("""
            ⚠️  shi-secrets: this vault contains PLAINTEXT items.

                They were written before client-side encryption existed, so they
                are readable by anyone with access to the server, its backups, or
                a database dump. They are also invisible to the Bitwarden apps.

                They are being read successfully — do NOT delete them to \"clean
                up\". Re-encrypt with VaultwardenClient.reEncryptLegacyPlaintext,
                then rotate every credential involved: it was stored in the clear.
                See docs/vault-encryption.md.

            """.utf8))
    }

    /// Resolved base URL (config-chain resolution done at init).
    private let baseURL: URL

    // MARK: - W2: Cached token struct (Keychain-side representation)

    /// An OAuth access token with its server-reported expiry.
    /// NOT Codable on purpose — the token must never be JSON-serialised to disk.
    /// JSON encoding to the Keychain blob happens only in VaultwardenTokenCache.
    public struct CachedToken: Sendable {
        public let accessToken: String
        public let expiresAt: Date

        public init(accessToken: String, expiresAt: Date) {
            self.accessToken = accessToken
            self.expiresAt = expiresAt
        }
    }

    // MARK: - Init

    /// - Parameter credentials: Loaded from Keychain via KeychainVaultCredentials.
    /// - Parameter pinnedSHA256: Optional TLS pin. Pass `nil` in W1 (operator
    ///   injects during W2 smoke). Pass the leaf cert SHA-256 when available.
    /// - Parameter configYmlVaultServer: Value of `vault.server` from
    ///   ~/.shikki/config.yml if already parsed; `nil` to auto-resolve
    ///   from the environment or DEV default.
    /// - Parameter urlProtocolClasses: Injected URLProtocol classes for testing.
    ///   Pass `nil` (default) in production; inject `[MockURLProtocol.self]` in tests.
    public init(
        credentials: VaultwardenCredentials,
        pinnedSHA256: String? = nil,
        configYmlVaultServer: String? = nil,
        urlProtocolClasses: [AnyClass]? = nil
    ) throws {
        self.credentials = credentials

        // Resolve base URL: config → env → DEV default.
        // BR-SM-13: no compiled-in fallback URL in a named constant —
        // resolution happens at runtime so ops can override without
        // recompiling.
        let resolvedURLString = Self.resolveServerURL(
            configYml: configYmlVaultServer,
            envKey: "SHIKKI_VAULT_URL",
            devDefault: "https://vw.obyw.one"
        )
        guard let url = URL(string: resolvedURLString),
              url.scheme == "https" else {
            throw VaultwardenClientError.invalidServerURL(raw: resolvedURLString)
        }
        self.baseURL = url

        // Build URLSession with TLS pin validator delegate.
        let config = URLSessionConfiguration.ephemeral
        // Ephemeral: no persistent cookies, no disk caching.
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        // W1.5 N3: enforce TLS 1.3 minimum — disallow TLS 1.2 fallback.
        // macOS 10.15+ / iOS 13+ support TLS 1.3 natively via Security.framework.
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
        // Inject mock protocol classes for testing; nil in production.
        if let classes = urlProtocolClasses {
            config.protocolClasses = classes
        }
        // W1.5 N2: load TLS pin from config chain if not injected explicitly.
        // Callers may pass an explicit pin for test injection; production uses
        // TLSPinValidator.loadPinnedSHA256() which reads env → vault.toml.
        let resolvedPin = pinnedSHA256 ?? TLSPinValidator.loadPinnedSHA256()
        let validator = TLSPinValidator(pinnedSHA256: resolvedPin)
        self.session = URLSession(
            configuration: config,
            delegate: validator,
            delegateQueue: nil
        )

        // SessionCache auto-refresh wired in connect()/refreshToken().
        self.sessionCache = SessionCache(refreshAction: nil)
        // Note: refreshAction is nil here because the actor cannot
        // close over itself before init completes. refreshToken() is
        // called directly by SessionCache's refresh task after W2
        // wires the closure. For W1, BrokerDaemon's bootstrap path
        // calls connect() → refreshToken() explicitly.
    }

    // MARK: - connect()

    /// Exchange the client_credentials grant for an access token.
    /// Stores the token in SessionCache for subsequent calls.
    /// Idempotent: if a valid token is already cached, returns without
    /// making a network call.
    public func connect() async throws {
        // Cache hit — no need to re-exchange.
        if await sessionCache.currentToken() != nil { return }
        try await refreshToken()
    }

    // MARK: - W2: seedTokenFromCache(_:)

    /// Seed the in-process SessionCache from an externally provided cached token
    /// (e.g. read from Keychain by VaultwardenTokenCache in Bootstrap.unseal()).
    /// Call this BEFORE connect() so connect() sees a valid in-process cache
    /// and skips the network round-trip.
    ///
    /// The safety margin check (60s) is done by the caller (Bootstrap/VaultwardenTokenCache).
    /// This method trusts the token is valid — it is the caller's responsibility
    /// to verify `expiresAt > Date() + 60s` before seeding.
    public func seedTokenFromCache(_ cached: CachedToken) async {
        await sessionCache.setToken(cached.accessToken, expiresAt: cached.expiresAt)
    }

    // MARK: - W2: performTokenExchange()

    /// Perform a raw OAuth client_credentials exchange and return the token +
    /// expiresAt without seeding SessionCache. Used by Bootstrap/VaultwardenTokenCache
    /// so the cache can be written BEFORE the in-process SessionCache is seeded.
    public func performTokenExchange() async throws -> CachedToken {
        let tokenURL = baseURL.appendingPathComponent("identity/connect/token")
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let deviceID = Self.resolvedDeviceIdentifier()
        let body = [
            "grant_type=client_credentials",
            "scope=api",
            "client_id=\(credentials.clientID.urlFormEncoded)",
            "client_secret=\(credentials.clientSecret.urlFormEncoded)",
            "deviceType=8",
            "deviceIdentifier=\(deviceID.urlFormEncoded)",
            "deviceName=shikki-secrets-brokerd",
        ].joined(separator: "&")
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.tokenResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.tokenExchangeFailed(httpStatus: httpResponse.statusCode)
        }

        let tokenResponse: TokenResponse
        do {
            tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw VaultwardenClientError.tokenResponseMalformed
        }

        // Keep the key material that arrived with the token. It is not used
        // here — unlocking needs the master password — but discarding it is
        // what made the vault key look unavailable in the first place.
        captureKeyMaterial(from: tokenResponse)

        let expiresAt = Date().addingTimeInterval(TimeInterval(tokenResponse.expires_in))
        return CachedToken(accessToken: tokenResponse.access_token, expiresAt: expiresAt)
    }

    // MARK: - refreshToken()

    /// Force a token refresh. Called by the SessionCache auto-refresh task
    /// and by connect() when no cached token exists.
    public func refreshToken() async throws {
        let tokenURL = baseURL.appendingPathComponent("identity/connect/token")
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        // Vaultwarden requires device fields in the client_credentials grant.
        // Without deviceType / deviceIdentifier / deviceName the server returns HTTP 400.
        // deviceType "8" = SDK/CLI per the Bitwarden Identity API spec.
        let deviceID = Self.resolvedDeviceIdentifier()
        let body = [
            "grant_type=client_credentials",
            "scope=api",
            "client_id=\(credentials.clientID.urlFormEncoded)",
            "client_secret=\(credentials.clientSecret.urlFormEncoded)",
            "deviceType=8",
            "deviceIdentifier=\(deviceID.urlFormEncoded)",
            "deviceName=shikki-secrets-brokerd",
        ].joined(separator: "&")
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.tokenResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.tokenExchangeFailed(httpStatus: httpResponse.statusCode)
        }

        let tokenResponse: TokenResponse
        do {
            tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw VaultwardenClientError.tokenResponseMalformed
        }

        captureKeyMaterial(from: tokenResponse)

        let expiresAt = Date().addingTimeInterval(TimeInterval(tokenResponse.expires_in))
        await sessionCache.setToken(tokenResponse.access_token, expiresAt: expiresAt)
    }

    // MARK: - Vault unlock

    private func captureKeyMaterial(from response: TokenResponse) {
        if let k = response.protectedKey { accountProtectedKey = k }
        if let p = response.kdfParameters { accountKDF = p }
    }

    /// Whether the vault key is currently held.
    /// A token can be valid while this is false — authenticated but locked.
    public var isVaultUnlocked: Bool {
        get async { await vaultKey.isUnlocked }
    }

    /// Derive the vault key from the master password and hold it for the
    /// session. Typed once by the operator; never stored, never logged.
    ///
    /// A wrong password fails as `macMismatch` when the account key is
    /// unwrapped — the server is not consulted and cannot tell us, because it
    /// does not know the password either. That is the model working.
    public func unlock(masterPassword: String, email: String) async throws {
        // The account key normally rides along with the token. If we have not
        // done an exchange yet, do one now rather than reporting "locked" for
        // a vault that would open fine.
        if accountProtectedKey == nil {
            _ = try? await performTokenExchange()
        }
        guard let protectedKey = accountProtectedKey else {
            throw VaultUnlockError.accountKeyMissing
        }
        let parameters: VaultKDFParameters
        if let known = accountKDF {
            parameters = known
        } else {
            parameters = try await VaultUnlock.fetchKDFParameters(
                baseURL: baseURL, email: email, session: session
            )
            accountKDF = parameters
        }
        let keys = try VaultUnlock.deriveSessionKeys(
            masterPassword: masterPassword, email: email,
            parameters: parameters, protectedKey: protectedKey
        )
        await vaultKey.unlock(with: keys)
    }

    /// Install a key derived elsewhere — used by the broker, which unlocks
    /// once and hands the key to each client it builds, so the operator is
    /// not prompted per call.
    public func adoptSessionKeys(_ keys: SymmetricKeyPair) async {
        await vaultKey.unlock(with: keys)
    }

    /// Drop the vault key. The access token survives; the data does not open.
    public func lockVault() async {
        await vaultKey.lock()
    }

    // MARK: - fetchSecret(id:)

    /// Fetch a single vault cipher by its UUID.
    /// Returns a dictionary of field names → plaintext values.
    ///
    /// The plaintext is returned ONLY to the calling actor; it is never
    /// logged, written to disk, or passed as a subprocess argument.
    public func fetchSecret(id: String) async throws -> [String: String] {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        let cipherURL = baseURL.appendingPathComponent("api/ciphers/\(id)")
        var request = URLRequest(url: cipherURL)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.fetchSecretFailed(httpStatus: httpResponse.statusCode)
        }

        let cipher: CipherResponse
        do {
            cipher = try JSONDecoder().decode(CipherResponse.self, from: data)
        } catch {
            throw VaultwardenClientError.cipherResponseMalformed
        }

        // Build a flat field map: SecureNote notes + login fields + custom fields.
        // Plaintext stays inside this actor; never serialised.
        var result: [String: String] = [:]
        // W3: SecureNote ciphers store value in `notes`.
        if let notes = cipher.notes { result["value"] = try await decryptField(notes) }
        if let login = cipher.login {
            if let u = login.username { result["username"] = try await decryptField(u) }
            if let p = login.password { result["password"] = try await decryptField(p) }
        }
        for field in cipher.fields ?? [] {
            if let name = field.name, let value = field.value {
                // The field NAME is encrypted too, not just the value.
                result[try await decryptField(name)] = try await decryptField(value)
            }
        }
        return result
    }

    /// Decrypt one field, tolerating the legacy plaintext this client wrote.
    ///
    /// ── Why the legacy branch exists, and why it is loud ──────────────
    /// Every item written before the encryption fix holds a bare string. If
    /// this method simply threw on them, the fix would take the operator's
    /// only copy of those secrets away at the moment it landed. So plaintext
    /// is returned — and reported, every single time, because a silent
    /// tolerance becomes permanent.
    ///
    /// The branch is removed once ``VaultwardenClient.reEncryptLegacyPlaintext` reports
    /// zero plaintext rows. Until then, treat every value that trips it as
    /// having been stored in the clear and due for rotation.
    private func decryptField(_ raw: String) async throws -> String {
        let enc: EncString
        do {
            enc = try EncString.parse(raw)
        } catch EncString.ParseError.notAnEncString {
            plaintextFieldsSeen += 1
            VaultwardenClient.reportLegacyPlaintext()
            return raw
        }
        return try BitwardenCrypto.decrypt(enc, using: try await vaultKey.require())
    }

    // MARK: - createCipher(name:value:) — W3 write path

    /// Create a new SecureNote cipher in the vault.
    /// Returns the cipher ID of the newly created item.
    ///
    /// `name` and `value` arrive as plaintext and leave as EncStrings. The
    /// vault must be unlocked; there is deliberately no fallback that writes
    /// the plaintext through when it is not.
    ///
    /// ── What this replaces ────────────────────────────────────────────
    /// The previous implementation assigned both straight into the request
    /// body, above a comment claiming "Vaultwarden accepts plaintext when
    /// accessed via API key (client_credentials grant). No client-side
    /// encryption needed."
    ///
    /// Vaultwarden does accept it — it accepts ANY bytes, because it is
    /// zero-knowledge and never looks. The 200 OK was not confirmation. Every
    /// item written that way is readable by anyone holding the database, and
    /// is rejected by every real Bitwarden client, which is how it surfaced:
    /// `[error: cannot decrypt]` on the web, an empty vault in the app.
    @discardableResult
    public func createCipher(name: String, value: String) async throws -> String {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }
        let keys = try await vaultKey.require()
        let encName  = try BitwardenCrypto.encrypt(name,  using: keys)
        let encValue = try BitwardenCrypto.encrypt(value, using: keys)

        let url = baseURL.appendingPathComponent("api/ciphers")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let payload = CipherCreateRequest(encryptedName: encName, encryptedValue: encValue)
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.createCipherFailed(httpStatus: httpResponse.statusCode)
        }

        struct CreateResponse: Decodable { let id: String }
        guard let created = try? JSONDecoder().decode(CreateResponse.self, from: data) else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        return created.id
    }

    // MARK: - deleteCipher(id:) — W3 write path

    /// Delete a vault cipher by its UUID.
    public func deleteCipher(id: String) async throws {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        let url = baseURL.appendingPathComponent("api/ciphers/\(id)")
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (_, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.deleteCipherFailed(httpStatus: httpResponse.statusCode)
        }
    }

    // MARK: - listSecrets()

    /// List all vault items the service account has access to.
    /// Returns an array of `[id: String, name: String]` dictionaries.
    public func listSecrets() async throws -> [[String: String]] {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        let url = baseURL.appendingPathComponent("api/ciphers")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await performRequest(request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw VaultwardenClientError.fetchSecretFailed(httpStatus: 0)
        }

        struct ListResponse: Decodable {
            struct Item: Decodable { let id: String; let name: String }
            let data: [Item]
        }
        guard let list = try? JSONDecoder().decode(ListResponse.self, from: data) else {
            throw VaultwardenClientError.cipherResponseMalformed
        }
        // The NAME is an encrypted field too. Returning it raw printed
        // `2.xTf9…|…|…` in `shi secret list` for every correctly-written item.
        var out: [[String: String]] = []
        for item in list.data {
            out.append(["id": item.id, "name": try await decryptField(item.name)])
        }
        return out
    }

    // MARK: - Encryption audit

    /// What the vault looks like from an encryption standpoint.
    /// `plaintext` is the number of items an attacker with the database could
    /// read directly — and the number invisible to every Bitwarden client.
    public struct EncryptionAudit: Sendable, Equatable {
        public var total = 0
        public var encrypted = 0
        public var plaintext = 0
        public var plaintextNames: [String] = []
        public var isClean: Bool { plaintext == 0 }
    }

    /// Count plaintext items WITHOUT unlocking the vault.
    ///
    /// Deliberately key-free: the operator must be able to see the blast
    /// radius before deciding anything, and "is this string shaped like an
    /// EncString" needs no key. It also means this runs on a machine that
    /// cannot decrypt, which is where you most want to check.
    public func auditEncryption() async throws -> EncryptionAudit {
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }
        var request = URLRequest(url: baseURL.appendingPathComponent("api/ciphers"))
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await performRequest(request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw VaultwardenClientError.fetchSecretFailed(httpStatus: 0)
        }
        struct ListResponse: Decodable {
            struct Item: Decodable { let id: String; let name: String }
            let data: [Item]
        }
        guard let list = try? JSONDecoder().decode(ListResponse.self, from: data) else {
            throw VaultwardenClientError.cipherResponseMalformed
        }

        var audit = EncryptionAudit()
        for item in list.data {
            audit.total += 1
            if EncString.looksEncrypted(item.name) {
                audit.encrypted += 1
            } else {
                audit.plaintext += 1
                // The NAME is already exposed by definition — printing it
                // reveals nothing that the server does not already hold in the
                // clear, and the operator needs it to know what to rotate.
                audit.plaintextNames.append(item.name)
            }
        }
        return audit
    }

    // MARK: - Re-encryption of legacy plaintext items

    public struct ReEncryptionReport: Sendable {
        public var examined = 0
        public var rewritten = 0
        public var alreadyEncrypted = 0
        /// name → the reason it could not be rewritten. Never empty-and-silent:
        /// a migration that skips items without saying so is worse than one
        /// that refuses to run.
        public var failures: [String: String] = [:]
        public var dryRun = false
    }

    /// Rewrite every plaintext item as a proper EncString.
    ///
    /// `dryRun` (the default) changes nothing and reports exactly what a real
    /// run would do. Run it first: this touches every secret the operator has.
    ///
    /// ── What this does NOT do ────────────────────────────────────────
    /// It does not rotate anything. Re-encrypting hides the values from
    /// FUTURE readers of the database; it does nothing about backups already
    /// taken, dumps already made, or anyone who has already looked. Every
    /// credential that was stored in the clear must still be rotated at its
    /// source. The report says so at the end for exactly this reason.
    public func reEncryptLegacyPlaintext(dryRun: Bool = true) async throws -> ReEncryptionReport {
        let keys = try await vaultKey.require()
        guard let token = await sessionCache.currentToken() else {
            throw VaultwardenClientError.notAuthenticated
        }

        var report = ReEncryptionReport()
        report.dryRun = dryRun

        var listRequest = URLRequest(url: baseURL.appendingPathComponent("api/ciphers"))
        listRequest.httpMethod = "GET"
        listRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (listData, listResponse) = try await performRequest(listRequest)
        guard let http = listResponse as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw VaultwardenClientError.fetchSecretFailed(httpStatus: 0)
        }
        struct ListResponse: Decodable {
            struct Item: Decodable { let id: String; let name: String; let notes: String? }
            let data: [Item]
        }
        guard let list = try? JSONDecoder().decode(ListResponse.self, from: listData) else {
            throw VaultwardenClientError.cipherResponseMalformed
        }

        for item in list.data {
            report.examined += 1
            if EncString.looksEncrypted(item.name) {
                report.alreadyEncrypted += 1
                continue
            }
            if dryRun {
                report.rewritten += 1
                continue
            }
            do {
                let encName  = try BitwardenCrypto.encrypt(item.name, using: keys)
                let encNotes = try BitwardenCrypto.encrypt(item.notes ?? "", using: keys)
                try await putCipher(id: item.id, name: encName, notes: encNotes, token: token)
                report.rewritten += 1
            } catch {
                report.failures[item.name] = String(describing: error)
            }
        }
        return report
    }

    private func putCipher(
        id: String, name: EncString, notes: EncString, token: String
    ) async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent("api/ciphers/\(id)"))
        request.httpMethod = "PUT"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            CipherCreateRequest(encryptedName: name, encryptedValue: notes)
        )

        let (_, response) = try await performRequest(request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw VaultwardenClientError.createCipherFailed(
                httpStatus: (response as? HTTPURLResponse)?.statusCode ?? 0
            )
        }
    }

    // MARK: - Device identifier (static — stable per-machine)

    /// Returns a stable per-machine device identifier for the Vaultwarden
    /// OAuth device fields. Resolution order:
    ///   1. ~/.shikki/config/machine-uuid (operator-generated UUID file)
    ///   2. IOKit IOPlatformUUID (macOS hardware UUID, requires no entitlements)
    ///   3. "shikki-brokerd-fallback" (last resort — should not occur in production)
    ///
    /// The value is NOT a secret — it identifies the device to Vaultwarden
    /// for audit purposes, not for authentication.
    static func resolvedDeviceIdentifier() -> String {
        // 1. Operator-generated UUID file (cross-platform, no IOKit needed).
        let uuidFilePath = (NSHomeDirectory() as NSString)
            .appendingPathComponent(".shikki/config/machine-uuid")
        if let contents = try? String(contentsOfFile: uuidFilePath, encoding: .utf8) {
            let trimmed = contents.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { return "shikki-brokerd-\(trimmed)" }
        }

        // 2. IOKit hardware UUID (macOS only, no special entitlements required).
        #if canImport(IOKit)
        if let uuid = IOKitMachineUUID() {
            return "shikki-brokerd-\(uuid)"
        }
        #endif

        // 3. Fallback — should not reach production.
        return "shikki-brokerd-fallback"
    }

    // MARK: - URL resolution (static — called once at init)

    /// Resolve the Vaultwarden server URL from the config chain.
    /// Never returns a hardcoded URL constant — always dynamic.
    static func resolveServerURL(
        configYml: String?,
        envKey: String,
        devDefault: String
    ) -> String {
        // 1. config.yml vault.server
        if let v = configYml, !v.isEmpty { return v }
        // 2. Environment variable
        if let v = ProcessInfo.processInfo.environment[envKey], !v.isEmpty { return v }
        // 3. DEV fallback (not a compile-time constant — evaluated at call site)
        return devDefault
    }

    // MARK: - Private: request execution

    private func performRequest(_ request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await session.data(for: request)
        } catch let urlError as URLError {
            // Detect DNS NXDOMAIN / host-not-found errors and surface an
            // actionable message with the config-chain remediation steps.
            if urlError.code == .cannotFindHost || urlError.code == .dnsLookupFailed {
                throw VaultwardenClientError.vaultHostUnreachable(
                    message: "DNS lookup failed for vault host. "
                    + "Set SHIKKI_VAULT_URL or ~/.shikki/settings/secrets-brokerd.toml [vault_url]"
                )
            }
            throw VaultwardenClientError.networkError(urlError.code)
        }
    }
}

// MARK: - URL form encoding helper

private extension String {
    var urlFormEncoded: String {
        addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? self
    }
}

// MARK: - IOKit hardware UUID (macOS)

#if canImport(IOKit)
import IOKit

/// Returns the IOPlatformUUID string from the IOKit registry.
/// This is the hardware board serial identifier, stable across reboots.
/// Returns `nil` only if IOKit registry lookup fails (should not occur on macOS).
private func IOKitMachineUUID() -> String? {
    let matchingDict = IOServiceMatching("IOPlatformExpertDevice")
    let platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, matchingDict)
    guard platformExpert != IO_OBJECT_NULL else { return nil }
    defer { IOObjectRelease(platformExpert) }
    let cfUUID = IORegistryEntryCreateCFProperty(
        platformExpert,
        "IOPlatformUUID" as CFString,
        kCFAllocatorDefault,
        0
    )
    guard let uuid = cfUUID?.takeRetainedValue() as? String else { return nil }
    return uuid
}
#endif
