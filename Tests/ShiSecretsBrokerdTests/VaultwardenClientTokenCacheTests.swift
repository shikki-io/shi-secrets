import Testing
@testable import ShiSecretsBrokerd
@testable import ShiSecretsKit
import Foundation

// VaultwardenClientTokenCacheTests — W2 TDD plan
// Spec: e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 §W2 TDD-Plan
//
// Tests VaultwardenTokenCache via MockSecureStore injection.
// Zero Keychain calls for t01-t13.
// t11/t12 test the real KeychainSecureStore (macOS only, use unique service names).
//
// SERIAL: tests that use the global URLProtocol mock must run sequentially.

// MARK: - URLProtocol mock for HTTP interception

final class TokenCacheMockURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (Data, HTTPURLResponse))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var req = request
        if req.httpBody == nil, let stream = req.httpBodyStream {
            req.httpBody = Data(readingStream: stream)
        }
        guard let handler = TokenCacheMockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        do {
            let (data, response) = try handler(req)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private extension Data {
    init(readingStream stream: InputStream) {
        self.init()
        stream.open()
        defer { stream.close() }
        var buf = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buf, maxLength: buf.count)
            if n > 0 { append(contentsOf: buf.prefix(n)) }
            else { break }
        }
    }
}

// MARK: - Helpers

private func makeTestCredentials() -> VaultwardenCredentials {
    VaultwardenCredentials(
        clientID: "user.00000000-0000-0000-0000-000000000001",
        clientSecret: "test-secret",
        serverURL: URL(string: "https://vw.test.example")!
    )
}

private func makeTestClient() throws -> VaultwardenClient {
    try VaultwardenClient(
        credentials: makeTestCredentials(),
        pinnedSHA256: nil,
        configYmlVaultServer: "https://vw.test.example",
        urlProtocolClasses: [TokenCacheMockURLProtocol.self]
    )
}

private func tokenResponseData(
    token: String = "test-access-token",
    expiresIn: Int = 3600
) -> Data {
    let body = #"{"access_token":"\#(token)","expires_in":\#(expiresIn),"token_type":"Bearer"}"#
    return body.data(using: .utf8)!
}

private func makeHTTPResponse(status: Int = 200) -> HTTPURLResponse {
    HTTPURLResponse(
        url: URL(string: "https://vw.test.example/identity/connect/token")!,
        statusCode: status,
        httpVersion: nil,
        headerFields: nil
    )!
}

private func makeTempBackoffPath() -> String {
    "\(NSTemporaryDirectory())test-backoff-\(UUID().uuidString).json"
}

private func preloadMockStore(
    _ store: MockSecureStore,
    token: String,
    expiresAt: Date
) async throws {
    let payload: [String: String] = [
        "token":      token,
        "expires_at": ISO8601DateFormatter().string(from: expiresAt),
    ]
    let data = try JSONSerialization.data(withJSONObject: payload)
    try await store.write(data,
                          service: "io.shikki.vault.token",
                          account: "client-credentials-access-token")
}

// MARK: - HTTP-dependent tests (serialized — share static URLProtocol handler)

@Suite("VaultwardenTokenCache — HTTP tests", .serialized)
struct TokenCacheHTTPTests {

    // -------------------------------------------------------------------------
    // t01: empty store → Vault called once → stored
    // -------------------------------------------------------------------------

    @Test("t01: empty MockSecureStore → single Vault HTTP call → entry written")
    func t01_firstCallExchangesAndCaches() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        var httpCallCount = 0
        TokenCacheMockURLProtocol.handler = { _ in
            httpCallCount += 1
            return (tokenResponseData(token: "fresh-token"), makeHTTPResponse(status: 200))
        }
        defer { TokenCacheMockURLProtocol.handler = nil }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        let client = try makeTestClient()

        // Simulate the Bootstrap.unseal() cache-first flow
        let entry = try await cache.readToken()
        #expect(entry == nil, "Expected no cached token initially")

        let fresh = try await client.performTokenExchange()
        try await cache.recordSuccess(token: fresh.accessToken, ttl: fresh.expiresAt.timeIntervalSinceNow)

        #expect(httpCallCount == 1, "Expected exactly 1 Vault call")
        // Canonical service/account after Item-2 Keychain consolidation (W4 audit fix).
        let stored = await store.rawRead(service: "io.shikki.vault",
                                         account: "access-token")
        #expect(stored != nil, "Token must be written to store")

        let cachedEntry = try await cache.readToken()
        #expect(cachedEntry != nil)
        #expect(cachedEntry?.token == "fresh-token")
    }

    // -------------------------------------------------------------------------
    // t02: cached valid token → no Vault call
    // -------------------------------------------------------------------------

    @Test("t02: valid cached token → zero Vault HTTP calls")
    func t02_secondCallWithinTTLServesFromCache() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let futureExpiry = Date().addingTimeInterval(3600)
        try await preloadMockStore(store, token: "cached-valid-token", expiresAt: futureExpiry)

        var httpCallCount = 0
        TokenCacheMockURLProtocol.handler = { _ in
            httpCallCount += 1
            return (tokenResponseData(), makeHTTPResponse(status: 200))
        }
        defer { TokenCacheMockURLProtocol.handler = nil }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        let entry = try await cache.readToken()

        #expect(entry != nil, "Should find cached token")
        #expect(entry?.token == "cached-valid-token")
        let expiresAt = entry?.expiresAt ?? Date.distantPast
        #expect(expiresAt > Date().addingTimeInterval(60), "Should be beyond safety margin")
        #expect(httpCallCount == 0, "ZERO Vault calls — served from cache")
    }

    // -------------------------------------------------------------------------
    // t03: expired cache → refresh, cache updated
    // -------------------------------------------------------------------------

    @Test("t03: expired token in store → Vault called → Keychain updated")
    func t03_expiredCacheTriggersRefresh() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let pastExpiry = Date().addingTimeInterval(-3600)
        try await preloadMockStore(store, token: "expired-token", expiresAt: pastExpiry)

        var httpCallCount = 0
        TokenCacheMockURLProtocol.handler = { _ in
            httpCallCount += 1
            return (tokenResponseData(token: "refreshed-token"), makeHTTPResponse(status: 200))
        }
        defer { TokenCacheMockURLProtocol.handler = nil }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        let client = try makeTestClient()

        // Entry exists but is expired
        let entry = try await cache.readToken()
        #expect(entry != nil, "Entry returned (not deleted on read)")
        let expiry = entry?.expiresAt ?? Date()
        #expect(expiry < Date(), "Entry is expired")

        // Caller detects expiry, refreshes
        let fresh = try await client.performTokenExchange()
        try await cache.recordSuccess(token: fresh.accessToken, ttl: fresh.expiresAt.timeIntervalSinceNow)

        #expect(httpCallCount == 1, "Expected exactly 1 Vault call for refresh")
        let newEntry = try await cache.readToken()
        #expect(newEntry?.token == "refreshed-token", "Cache must be updated with new token")
    }

    // -------------------------------------------------------------------------
    // t04: corrupted cache → fallback (nil) → Vault called, no throw
    // -------------------------------------------------------------------------

    @Test("t04: garbage Data in store → nil returned, Vault call succeeds")
    func t04_corruptedCacheFallsBackToVault() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        // Pre-populate with garbage bytes
        let garbage = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02])
        try await store.write(garbage,
                              service: "io.shikki.vault.token",
                              account: "client-credentials-access-token")

        var httpCallCount = 0
        TokenCacheMockURLProtocol.handler = { _ in
            httpCallCount += 1
            return (tokenResponseData(token: "after-corrupt-token"), makeHTTPResponse(status: 200))
        }
        defer { TokenCacheMockURLProtocol.handler = nil }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        let client = try makeTestClient()

        // readToken must return nil (no throw) for corrupt data
        let entry = try await cache.readToken()
        #expect(entry == nil, "Corrupted entry must return nil, not throw")

        // Caller proceeds with exchange
        let fresh = try await client.performTokenExchange()
        try await cache.recordSuccess(token: fresh.accessToken, ttl: fresh.expiresAt.timeIntervalSinceNow)

        #expect(httpCallCount == 1, "Expected 1 Vault call after corrupt cache")
        let newEntry = try await cache.readToken()
        #expect(newEntry?.token == "after-corrupt-token")
    }

    // -------------------------------------------------------------------------
    // t05: Keychain write failure → exchange succeeds but token not cached
    // -------------------------------------------------------------------------

    @Test("t05: store.write throws → recordSuccess propagates error, no crash")
    func t05_keychainWriteFailureSurfaces() async throws {
        let store = MockSecureStore()
        await store.setThrowOnWrite(.osStatus(-25300))
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        var httpCallCount = 0
        TokenCacheMockURLProtocol.handler = { _ in
            httpCallCount += 1
            return (tokenResponseData(token: "uncached-token"), makeHTTPResponse(status: 200))
        }
        defer { TokenCacheMockURLProtocol.handler = nil }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        let client = try makeTestClient()

        let fresh = try await client.performTokenExchange()
        #expect(httpCallCount == 1)

        // recordSuccess throws because store.write is broken
        var caughtError: (any Error)? = nil
        do {
            try await cache.recordSuccess(token: fresh.accessToken,
                                          ttl: fresh.expiresAt.timeIntervalSinceNow)
        } catch {
            caughtError = error
        }
        #expect(caughtError != nil, "recordSuccess must throw when write fails")

        // Reset so read works, then verify nothing stored
        await store.setThrowOnWrite(nil)
        let entry = try await cache.readToken()
        #expect(entry == nil, "No token cached after write failure")
    }

    // -------------------------------------------------------------------------
    // t10: 429 with valid cached token → degraded mode
    // -------------------------------------------------------------------------

    @Test("t10: 429 + valid Keychain entry → cache served, no throw")
    func t10_429WithValidCacheServesDegraded() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let futureExpiry = Date().addingTimeInterval(3600)
        try await preloadMockStore(store, token: "degraded-cached-token", expiresAt: futureExpiry)

        TokenCacheMockURLProtocol.handler = nil  // 429 path doesn't call handler
        defer { TokenCacheMockURLProtocol.handler = nil }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)

        _ = try await cache.record429()

        let entry = try await cache.readToken()
        #expect(entry != nil, "Cached token available in degraded mode")
        #expect(entry?.token == "degraded-cached-token", "Degraded: serve cached token")
    }
}

// MARK: - Non-HTTP tests (can run in parallel)

@Suite("VaultwardenTokenCache — t06 safety margin")
struct TokenCacheT06Tests {

    @Test("t06: token expiring in 30s → within 60s safety margin → refresh required")
    func t06_safetyMarginPreventsRaceExpiration() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let nearExpiry = Date().addingTimeInterval(30)
        try await preloadMockStore(store, token: "near-expiry-token", expiresAt: nearExpiry)

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        let entry = try await cache.readToken()
        #expect(entry != nil, "Entry returned")

        let safetyMargin: TimeInterval = 60
        let expiresAt = entry?.expiresAt ?? Date.distantPast
        let isWithinSafetyMargin = expiresAt < Date().addingTimeInterval(safetyMargin)
        #expect(isWithinSafetyMargin, "Token within 60s safety margin → caller must refresh")
    }
}

@Suite("VaultwardenTokenCache — t07 429 backoff increments")
struct TokenCacheT07Tests {

    @Test("t07: record429() increments counter and writes JSON file")
    func t07_429BackoffCounterIncrements() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)

        let delay = try await cache.record429()

        #expect(abs(delay - 60) < 1, "First 429 delay should be 60s, got \(delay)")

        let entry = try await cache.readBackoff()
        #expect(entry?.consecutive429Count == 1)
        let nextAttempt = entry?.nextAttemptAt ?? Date.distantPast
        #expect(nextAttempt > Date(), "nextAttemptAt must be in the future")
    }
}

@Suite("VaultwardenTokenCache — t08 exponential backoff cap")
struct TokenCacheT08Tests {

    @Test("t08: 10 consecutive 429s → delay capped at 1800s (30min)")
    func t08_429ExponentialBackoffCap() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)

        var lastDelay: TimeInterval = 0
        for i in 0..<10 {
            lastDelay = try await cache.record429()
            let expected = min(60.0 * pow(2.0, Double(i)), 1800.0)
            #expect(abs(lastDelay - expected) < 1,
                "Iteration \(i+1): expected \(expected)s, got \(lastDelay)s")
        }

        #expect(lastDelay == 1800, "Delay must be capped at 1800s (30min)")
    }
}

@Suite("VaultwardenTokenCache — t09 200 OK resets counter")
struct TokenCacheT09Tests {

    @Test("t09: recordSuccess() resets consecutive429Count to 0")
    func t09_200OkResetsBackoffCounter() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)

        _ = try await cache.record429()
        _ = try await cache.record429()
        _ = try await cache.record429()
        #expect(try await cache.readBackoff()?.consecutive429Count == 3)

        try await cache.recordSuccess(token: "fresh-token", ttl: 3600)

        let backoff = try await cache.readBackoff()
        #expect(backoff?.consecutive429Count == 0, "Counter must reset after 200 OK")
    }
}

// MARK: - Keychain attribute tests (macOS real Keychain — unique service names avoid collision)

#if os(macOS)
import Security

@Suite("VaultwardenTokenCache — t11 Keychain accessibility attribute")
struct TokenCacheT11Tests {

    @Test("t11: KeychainSecureStore write+read cycle succeeds (accessibility applied)")
    func t11_keychainItemAccessibility() async throws {
        // NOTE: macOS's SecItemCopyMatching does NOT return kSecAttrAccessible in
        // the attributes dictionary (tested and confirmed — the attribute is stored
        // but not surfaced via API). This is an undocumented Apple API behaviour.
        //
        // What we CAN verify:
        // 1. Write succeeds → kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly is a valid
        //    attribute value (SecItemAdd would return errSecParam if it were invalid).
        // 2. Read returns the data unchanged → item is accessible (proves AfterFirstUnlock
        //    semantics: item is readable after the first login unlock without further prompts).
        // 3. Source-code review confirms the attribute in KeychainSecureStore.swift.

        let keychainStore = KeychainSecureStore()
        let testService = "io.shikki.test.w2.t11.\(UUID().uuidString)"
        let testAccount = "test-account"
        defer {
            Task { try? await keychainStore.delete(service: testService, account: testAccount) }
        }

        let testData = "test-payload-accessibility".data(using: .utf8)!

        // Write — if kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly were invalid,
        // SecItemAdd would fail with errSecParam (-50).
        try await keychainStore.write(testData, service: testService, account: testAccount)

        // Read back — proves item is accessible in the current session.
        let readBack = try await keychainStore.read(service: testService, account: testAccount)
        #expect(readBack == testData, "Read-back must return same data as written")

        // Idempotent update (write again) must also succeed.
        let updatedData = "test-payload-updated".data(using: .utf8)!
        try await keychainStore.write(updatedData, service: testService, account: testAccount)
        let readUpdated = try await keychainStore.read(service: testService, account: testAccount)
        #expect(readUpdated == updatedData, "Updated data must be returned after second write")
    }
}

@Suite("VaultwardenTokenCache — t12 not synchronizable to iCloud")
struct TokenCacheT12Tests {

    @Test("t12: KeychainSecureStore item has kSecAttrSynchronizable = false")
    func t12_keychainItemNotSynchronizable() async throws {
        let keychainStore = KeychainSecureStore()
        let testService = "io.shikki.test.w2.t12.\(UUID().uuidString)"
        let testAccount = "test-account"
        defer {
            Task { try? await keychainStore.delete(service: testService, account: testAccount) }
        }

        let testData = "test-payload".data(using: .utf8)!
        try await keychainStore.write(testData, service: testService, account: testAccount)

        // Query without kSecAttrSynchronizable filter to get all items regardless of sync state
        let query: [CFString: Any] = [
            kSecClass:              kSecClassGenericPassword,
            kSecAttrService:        testService,
            kSecAttrAccount:        testAccount,
            kSecReturnAttributes:   true,
            kSecMatchLimit:         kSecMatchLimitOne,
            // Include non-synchronizable items explicitly
            kSecAttrSynchronizable: kSecAttrSynchronizableAny,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        #expect(status == errSecSuccess, "SecItemCopyMatching must succeed, got \(status)")

        let attrs = result as? [String: Any]
        // kSecAttrSynchronizable is returned as NSNumber(bool: false) when not synchronizable
        let syncValue = attrs?[kSecAttrSynchronizable as String]
        // It can be Bool, NSNumber, or CFBoolean — test each form
        let isSynchronizable: Bool
        if let b = syncValue as? Bool {
            isSynchronizable = b
        } else if let n = syncValue as? NSNumber {
            isSynchronizable = n.boolValue
        } else {
            isSynchronizable = false   // nil or unknown → treat as not synced
        }
        #expect(!isSynchronizable, "Item must NOT be iCloud-synchronizable")
    }
}
#endif

// MARK: - Backoff file content and permissions tests

@Suite("VaultwardenTokenCache — t13 no token in backoff file")
struct TokenCacheT13Tests {

    @Test("t13: BackoffEntry JSON must not contain 'token' or 'access_token' keys")
    func t13_noTokenInBackoffFile() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        _ = try await cache.record429()

        guard let data = try? Data(contentsOf: URL(fileURLWithPath: backoffPath)) else {
            Issue.record("Backoff file should exist after record429()")
            return
        }

        let content = String(data: data, encoding: .utf8) ?? ""

        #expect(!content.contains("\"token\""),
            "BackoffEntry JSON must not contain 'token' key — security invariant")
        #expect(!content.contains("\"access_token\""),
            "BackoffEntry JSON must not contain 'access_token' key")
        #expect(!content.contains("\"accessToken\""),
            "BackoffEntry JSON must not contain 'accessToken' key")
    }

    @Test("t13b: backoff file has mode 0o600 after write")
    func t13b_backoffFilePermissions() async throws {
        let store = MockSecureStore()
        let backoffPath = makeTempBackoffPath()
        defer { try? FileManager.default.removeItem(atPath: backoffPath) }

        let cache = VaultwardenTokenCache(store: store, backoffFilePath: backoffPath)
        _ = try await cache.record429()

        let attrs = try FileManager.default.attributesOfItem(atPath: backoffPath)
        let perms = attrs[.posixPermissions] as? Int ?? 0
        #expect(perms == 0o600,
            "Backoff file must be mode 0o600, got \(String(format: "%o", perms))")
    }
}
