import Testing
@testable import ShiSecretsKit
import Foundation

// VaultTokenRenewalTests — proves a token renewal SUCCEEDS and the data call
// then works, not merely that it does not throw.
//
// VaultUnlockReseededSessionTests T-URG-03 only asserts `secrets.isEmpty`, and
// its mock answers /ciphers 200 for ANY bearer, so that test passes whether or
// not a renewal happened. This suite's server is strict instead:
//   - /identity/connect/token issues a NEW, unique token per call and counts it;
//   - /api/ciphers answers 200 ONLY for a bearer the token endpoint issued, and
//     401 for anything else (including the expired token the cache was seeded with).
// So "the data call completed" implies "a fresh token was minted and used", and
// the issue count proves the renewal was actually invoked.

// MARK: - Strict mock server

private final class RenewalMockProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var issued: [String] = []
    nonisolated(unsafe) private static var cipherBearers: [String] = []

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        issued = []
        cipherBearers = []
    }
    static var issuedTokens: [String] { lock.lock(); defer { lock.unlock() }; return issued }
    static var bearersSeenByCipherEndpoint: [String] { lock.lock(); defer { lock.unlock() }; return cipherBearers }

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host?.hasSuffix("mock-vault-renewal.test") == true
    }
    override class func canonicalRequest(for r: URLRequest) -> URLRequest { r }

    override func startLoading() {
        let path = request.url?.path ?? ""
        var status = 200
        var body = Data()

        if path.hasSuffix("connect/token") {
            let fresh = "issued-\(UUID().uuidString)"
            Self.lock.lock(); Self.issued.append(fresh); Self.lock.unlock()
            body = Data(#"{"access_token":"\#(fresh)","expires_in":7200,"token_type":"Bearer"}"#.utf8)
        } else if path.hasSuffix("/ciphers") {
            let auth = request.value(forHTTPHeaderField: "Authorization") ?? ""
            let bearer = auth.hasPrefix("Bearer ") ? String(auth.dropFirst("Bearer ".count)) : auth
            Self.lock.lock()
            Self.cipherBearers.append(bearer)
            let known = Self.issued.contains(bearer)
            Self.lock.unlock()
            if known {
                body = Data(#"{"data":[]}"#.utf8)
            } else {
                status = 401
                body = Data(#"{"error":"invalid_token"}"#.utf8)
            }
        } else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }

        let resp = HTTPURLResponse(
            url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

private func makeRenewalClient() throws -> VaultwardenClient {
    let creds = VaultwardenCredentials(
        clientID: "user.mock-renewal",
        clientSecret: "mock-secret",
        serverURL: URL(string: "https://mock-vault-renewal.test")!
    )
    return try VaultwardenClient(
        credentials: creds,
        configYmlVaultServer: "https://mock-vault-renewal.test",
        urlProtocolClasses: [RenewalMockProtocol.self]
    )
}

// MARK: - Suite

/// Serialized: RenewalMockProtocol keeps process-global request logs.
@Suite("VaultwardenClient — token renewal succeeds and the call then works", .serialized)
struct VaultTokenRenewalTests {

    // T-REN-01 ────────────────────────────────────────────────────────────
    // An EXPIRED token is replaced by a freshly issued one and the data call
    // goes out authenticated with it.
    @Test("T-REN-01: expired token -> one renewal, data call carries the fresh token")
    func test_ren01_expiredToken_isRenewedAndTheCallSucceeds() async throws {
        RenewalMockProtocol.reset()
        let vc = try makeRenewalClient()
        await vc.seedTokenFromCache(
            VaultwardenClient.CachedToken(accessToken: "expired-tok", expiresAt: Date(timeIntervalSinceNow: -7200))
        )

        let secrets = try await vc.listSecrets()

        #expect(secrets.isEmpty)
        let issued = RenewalMockProtocol.issuedTokens
        #expect(issued.count == 1, "the renewal must actually have hit the token endpoint exactly once")
        #expect(RenewalMockProtocol.bearersSeenByCipherEndpoint == issued,
                "the data call must authenticate with the token the renewal issued, not the expired one")
    }

    // T-REN-02 ────────────────────────────────────────────────────────────
    // ABSENT token (nothing ever seeded): same contract.
    @Test("T-REN-02: absent token -> one renewal, data call carries the fresh token")
    func test_ren02_absentToken_isRenewedAndTheCallSucceeds() async throws {
        RenewalMockProtocol.reset()
        let vc = try makeRenewalClient()

        let secrets = try await vc.listSecrets()

        #expect(secrets.isEmpty)
        let issued = RenewalMockProtocol.issuedTokens
        #expect(issued.count == 1)
        #expect(RenewalMockProtocol.bearersSeenByCipherEndpoint == issued)
    }

    // T-REN-03 ────────────────────────────────────────────────────────────
    // A still-valid token is used as is: renewing on every call would hammer
    // the identity endpoint. Guards the other half of "renews when needed".
    @Test("T-REN-03: valid token -> no renewal, the cached token is used")
    func test_ren03_validToken_isNotRenewed() async throws {
        RenewalMockProtocol.reset()
        let vc = try makeRenewalClient()
        try await vc.refreshToken()   // mints issued[0] and seeds the cache
        #expect(RenewalMockProtocol.issuedTokens.count == 1)

        _ = try await vc.listSecrets()
        _ = try await vc.listSecrets()

        #expect(RenewalMockProtocol.issuedTokens.count == 1, "a valid token must not trigger a renewal")
        #expect(RenewalMockProtocol.bearersSeenByCipherEndpoint == RenewalMockProtocol.issuedTokens + RenewalMockProtocol.issuedTokens)
    }

    // T-REN-04 ────────────────────────────────────────────────────────────
    // A burst of concurrent calls on an empty cache ALL succeed. This
    // deliberately does NOT assert "exactly one renewal": validToken() has no
    // in-flight coalescing (the actor re-enters at each await, and
    // SessionCache is only a token store), so a burst may renew more than
    // once. The contract here is correctness under concurrency: every call
    // completes and every call authenticates with a token the server issued.
    @Test("T-REN-04: concurrent burst on an empty cache -> every call succeeds with an issued token")
    func test_ren04_concurrentBurst_everyCallSucceeds() async throws {
        RenewalMockProtocol.reset()
        let vc = try makeRenewalClient()
        let burst = 8

        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<burst {
                group.addTask { try await vc.listSecrets().count }
            }
            for try await count in group { #expect(count == 0) }
        }

        let issued = Set(RenewalMockProtocol.issuedTokens)
        let bearers = RenewalMockProtocol.bearersSeenByCipherEndpoint
        #expect(!issued.isEmpty, "at least one renewal must have happened")
        #expect(bearers.count == burst)
        #expect(bearers.allSatisfy { issued.contains($0) }, "no call may go out with a token the server did not issue")
    }
}
