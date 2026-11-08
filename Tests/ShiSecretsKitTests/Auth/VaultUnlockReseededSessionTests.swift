import Testing
@testable import ShiSecretsKit
import Foundation
import Crypto

// VaultUnlockReseededSessionTests — regression for the notAuthenticated P0 bug.
//
// Root cause (v0.8.0):
//   VaultwardenClient.unlock() contained:
//       if accountProtectedKey == nil {
//           _ = try? await performTokenExchange()
//       }
//   performTokenExchange() returns a CachedToken but NEVER seeds SessionCache.
//   The `try?` also silently swallowed any exchange failure.
//   Result: unlock() completed without error, vault key was derived and held —
//   BUT sessionCache.currentToken() was nil. Every call that needed a Bearer
//   token (listSecrets, createCipher, deleteCipher, fetchSecret) then threw
//   VaultwardenClientError.notAuthenticated even though brokerd status showed
//   "vault: unlocked".
//
// Fix: replace the guard with
//       if accountProtectedKey == nil || (await sessionCache.currentToken() == nil) {
//           try await refreshToken()
//       }
//   refreshToken() both captures key material AND seeds SessionCache.
//
// ── Red at v0.8.0 ──────────────────────────────────────────────────────────
// T-URG-01 fails at v0.8.0 because listSecrets() throws notAuthenticated
// immediately after a successful unlock().
//
// ── Green after fix ────────────────────────────────────────────────────────
// refreshToken() seeds the cache; listSecrets() returns [] (empty vault).

// MARK: - Mock URL protocol

/// Intercepts HTTPS requests to "mock-vault-unlock.test".
/// Handles token exchange, prelogin, and cipher list endpoints.
private final class VaultUnlockMockProtocol: URLProtocol, @unchecked Sendable {
    // Per-suite state — tests serialized by @Suite(.serialized).
    nonisolated(unsafe) static var tokenBody: Data?
    nonisolated(unsafe) static var preloginBody: Data?
    nonisolated(unsafe) static var ciphersBody: Data = #"{"data":[]}"#.data(using: .utf8)!

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host?.hasSuffix("mock-vault-unlock.test") == true
    }
    override class func canonicalRequest(for r: URLRequest) -> URLRequest { r }

    override func startLoading() {
        let path = request.url?.path ?? ""
        let (body, status): (Data, Int)

        if path.hasSuffix("connect/token") {
            body = Self.tokenBody ?? Data()
            status = Self.tokenBody != nil ? 200 : 400
        } else if path.contains("prelogin") {
            body = Self.preloginBody ?? Data()
            status = Self.preloginBody != nil ? 200 : 400
        } else if path.hasSuffix("/ciphers") {
            body = Self.ciphersBody
            status = 200
        } else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }

        let resp = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

// MARK: - Fixture helpers

private let fixturePassword  = "test-unlock-pw"
private let fixtureEmail     = "test@mock-vault-unlock.test"
private let fixtureIter      = 5_000   // reduced for test speed; real = 600_000

/// Generate a fixture protectedKey (Bitwarden `Key` EncString) for the
/// given credentials. Returns the serialized EncString and the user key pair.
private func makeFixtureProtectedKey() throws -> (protectedKey: String, userKeyPair: SymmetricKeyPair) {
    let master = try BitwardenCrypto.masterKey(
        masterPassword: fixturePassword, email: fixtureEmail,
        kdf: .pbkdf2SHA256, iterations: fixtureIter
    )
    let stretched = BitwardenCrypto.stretchMasterKey(master)
    let userKeyPair = SymmetricKeyPair(
        encKey: SymmetricKey(size: .bits256),
        macKey: SymmetricKey(size: .bits256)
    )
    let raw = userKeyPair.encKey.withUnsafeBytes { Data($0) }
            + userKeyPair.macKey.withUnsafeBytes { Data($0) }
    let protectedKey = try BitwardenCrypto.encrypt(raw, using: stretched).serialized
    return (protectedKey, userKeyPair)
}

/// Build a VaultwardenClient backed by VaultUnlockMockProtocol.
private func makeMockClient() throws -> VaultwardenClient {
    let creds = VaultwardenCredentials(
        clientID: "user.mock-unlock",
        clientSecret: "mock-secret",
        serverURL: URL(string: "https://mock-vault-unlock.test")!
    )
    return try VaultwardenClient(
        credentials: creds,
        configYmlVaultServer: "https://mock-vault-unlock.test",
        urlProtocolClasses: [VaultUnlockMockProtocol.self]
    )
}

/// Install mock token + prelogin responses for protectedKey + fixtureIter KDF.
private func installMockResponses(protectedKey: String) {
    VaultUnlockMockProtocol.tokenBody = """
    {
      "access_token": "mock-tok-\(UUID().uuidString)",
      "expires_in": 3600,
      "token_type": "Bearer",
      "Key": "\(protectedKey)",
      "Kdf": 0,
      "KdfIterations": \(fixtureIter)
    }
    """.data(using: .utf8)
    VaultUnlockMockProtocol.preloginBody = """
    {"kdf": 0, "kdfIterations": \(fixtureIter)}
    """.data(using: .utf8)
    VaultUnlockMockProtocol.ciphersBody = #"{"data":[]}"#.data(using: .utf8)!
}

// MARK: - Suite

/// Serialized: VaultUnlockMockProtocol has global mutable state.
@Suite("VaultUnlock — session cache reseeded after unlock (P0 regression)", .serialized)
struct VaultUnlockReseededSessionTests {

    // T-URG-01 ────────────────────────────────────────────────────────────
    // Scenario: Bootstrap used the Keychain token-cache (cache-hit) path,
    // which seeds SessionCache via seedTokenFromCache() but does NOT call
    // performTokenExchange(). So accountProtectedKey is nil and the session
    // token has expired (or the broker is fresh after cache-hit bootstrap).
    //
    // Expected: unlock() succeeds, listSecrets() succeeds (returns empty array).
    // At v0.8.0: listSecrets() throws VaultwardenClientError.notAuthenticated.
    @Test("T-URG-01: listSecrets after unlock — must not throw notAuthenticated")
    func test_urg01_listSecretsAfterUnlock_noNotAuthenticated() async throws {
        let (protectedKey, _) = try makeFixtureProtectedKey()
        installMockResponses(protectedKey: protectedKey)

        let vc = try makeMockClient()
        // Do NOT call connect() — simulates the cache-hit bootstrap path
        // (sessionCache is empty, accountProtectedKey is nil).

        try await vc.unlock(masterPassword: fixturePassword, email: fixtureEmail)

        // At v0.8.0: this throws notAuthenticated.
        // After fix: returns [] because the mock returns an empty cipher list.
        let secrets = try await vc.listSecrets()
        #expect(secrets.isEmpty, "fresh empty vault must return empty list after unlock")
    }

    // T-URG-02 ────────────────────────────────────────────────────────────
    // Scenario: session token expired AFTER Bootstrap did a full exchange
    // (accountProtectedKey is set, but the token is gone from the cache).
    //
    // In the old code: accountProtectedKey != nil → no performTokenExchange()
    // call at all. Vault key is re-derived. listSecrets() still gets nil token.
    //
    // After fix: the expired-token condition triggers refreshToken() regardless
    // of accountProtectedKey state.
    @Test("T-URG-02: expired session token is refreshed by unlock")
    func test_urg02_expiredToken_refreshedByUnlock() async throws {
        let (protectedKey, _) = try makeFixtureProtectedKey()
        installMockResponses(protectedKey: protectedKey)

        let vc = try makeMockClient()
        // Simulate: Bootstrap did a full exchange, seeded accountProtectedKey,
        // then the token expired. We seed the cache with an already-expired token.
        let past = Date(timeIntervalSinceNow: -7200)  // 2 hours ago
        await vc.seedTokenFromCache(
            VaultwardenClient.CachedToken(accessToken: "expired-tok", expiresAt: past)
        )
        // Also trigger a first exchange so accountProtectedKey gets set from
        // a token-like response (simulate what refreshToken() would have done
        // at Bootstrap time).
        //
        // We cannot set accountProtectedKey directly (private), so instead we
        // arrange for unlock() itself to call refreshToken() because the token
        // is expired — this is the path we are testing.

        try await vc.unlock(masterPassword: fixturePassword, email: fixtureEmail)

        let secrets = try await vc.listSecrets()
        #expect(secrets.isEmpty, "must succeed after unlock refreshes the expired token")
    }

    // T-URG-03 ────────────────────────────────────────────────────────────
    // A wrong password must fail — unlock must not silently succeed.
    @Test("T-URG-03: wrong master password is refused")
    func test_urg03_wrongPasswordIsRefused() async throws {
        let (protectedKey, _) = try makeFixtureProtectedKey()
        installMockResponses(protectedKey: protectedKey)

        let vc = try makeMockClient()

        await #expect(throws: (any Error).self) {
            try await vc.unlock(masterPassword: "WRONG-PASSWORD-\(UUID().uuidString)", email: fixtureEmail)
        }
    }

    // T-URG-04 ────────────────────────────────────────────────────────────
    // The connect() path (production Bootstrap exchange) followed by unlock().
    // This is the happy path; it should still work after the fix.
    @Test("T-URG-04: connect() then unlock() — nominal path still works")
    func test_urg04_connectThenUnlock_nominalPath() async throws {
        let (protectedKey, _) = try makeFixtureProtectedKey()
        installMockResponses(protectedKey: protectedKey)

        let vc = try makeMockClient()
        try await vc.connect()  // seeds cache + captures key material

        try await vc.unlock(masterPassword: fixturePassword, email: fixtureEmail)

        let secrets = try await vc.listSecrets()
        #expect(secrets.isEmpty, "nominal connect+unlock path: empty vault")
    }

    // T-URG-03 ────────────────────────────────────────────────────────────
    // The 17:00-works / 19:00-notAuthenticated regression (2026-11-08).
    // The vault was unlocked (key held), the 2 h access token then expired,
    // and nothing renews it in the background. No unlock() is called here:
    // the call itself must renew the token, because client_credentials needs
    // no master password.
    @Test("T-URG-03: expired token is renewed by the API call itself, no unlock needed")
    func test_urg03_expiredToken_renewedOnDemand() async throws {
        let (protectedKey, _) = try makeFixtureProtectedKey()
        installMockResponses(protectedKey: protectedKey)

        let vc = try makeMockClient()
        await vc.seedTokenFromCache(
            VaultwardenClient.CachedToken(
                accessToken: "expired-tok", expiresAt: Date(timeIntervalSinceNow: -7200)
            )
        )

        let secrets = try await vc.listSecrets()
        #expect(secrets.isEmpty, "listSecrets must renew the expired token, not throw notAuthenticated")
    }

    // T-URG-04 ────────────────────────────────────────────────────────────
    // Renewal must not mask a real failure: when the token exchange itself is
    // refused, the caller sees that, not a generic notAuthenticated.
    @Test("T-URG-04: a refused renewal surfaces tokenExchangeFailed, not notAuthenticated")
    func test_urg04_refusedRenewal_isNamed() async throws {
        VaultUnlockMockProtocol.tokenBody = nil   // mock answers HTTP 400
        defer { VaultUnlockMockProtocol.tokenBody = nil }

        let vc = try makeMockClient()
        do {
            _ = try await vc.listSecrets()
            Issue.record("listSecrets must throw when the token cannot be renewed")
        } catch let e as VaultwardenClientError {
            guard case .tokenExchangeFailed(let status) = e else {
                Issue.record("expected tokenExchangeFailed, got \(e)")
                return
            }
            #expect(status == 400)
        }
    }
}
