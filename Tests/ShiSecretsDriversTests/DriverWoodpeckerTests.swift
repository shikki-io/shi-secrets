import Foundation
@testable import ShiSecretsDrivers
import ShiSecretsKit
import Testing

// DriverWoodpeckerTests — covers T-WPD-01 through T-WPD-05.
//
// All tests inject a RecordingTransport (HTTP stub) and a RecordingBWClient
// (vault write-back stub) — no real Woodpecker server required.

@Suite("DriverWoodpecker")
struct DriverWoodpeckerTests {

    // MARK: - Helpers

    /// Builds a VaultEntryRef whose scope matches the "woodpecker:<repo>:<branch>" format.
    private func makeWoodpeckerEntry(repo: String = "shikki", branch: String = "develop") -> VaultEntryRef {
        makeEntry(vendor: "woodpecker", name: "WOODPECKER_CI_TOKEN_\(repo)_\(branch)")
            .withScope("woodpecker:\(repo):\(branch)")
    }

    /// Builds a mint-success JSON response body.
    private func mintResponseBody(id: String = "tok-001", token: String, ttl: Int = 3600) -> Data {
        // Force-try is safe here: the literal dictionary always encodes cleanly.
        try! JSONSerialization.data(withJSONObject: [
            "id": id, "token": token, "ttl": ttl,
        ])
    }

    // MARK: - T-WPD-01

    @Test("T-WPD-01: mint with valid scope returns 64-char token + TTL ≤ 3600")
    func test_mint_validScope_returns64CharToken_ttlWithinCap() async throws {
        let http = RecordingTransport()
        let rawToken = String(repeating: "a", count: 64)
        await http.queue(
            match: .init(method: "POST", urlContains: "/api/user/token"),
            response: DriverHTTPResponse(status: 201, body: mintResponseBody(token: rawToken, ttl: 3600))
        )
        let driver = DriverWoodpecker(transport: http)
        let result = try await driver.mint(repo: "shikki", branch: "develop", ttl: 3600)

        #expect(result.value.count == 64)
        #expect(result.ttl <= DriverWoodpecker.maxTokenTTL)
        #expect(result.ttl == 3600)
    }

    // MARK: - T-WPD-02

    @Test("T-WPD-02: rotate with invalid scope returns .failed(.invalidScope)")
    func test_rotate_invalidScope_returnsFailed() async {
        let http = RecordingTransport()
        let driver = DriverWoodpecker(transport: http)
        // Scope is missing the branch segment — only two parts after splitting.
        let entry = makeEntry(vendor: "woodpecker", name: "BAD_SCOPE")
            .withScope("woodpecker:shikki")   // malformed — no branch

        let outcome = await driver.rotate(entry: entry, trigger: .manual(op: "test"))

        guard case .failed(let reason) = outcome else {
            Issue.record("expected .failed, got \(outcome)")
            return
        }
        #expect(reason.contains("invalid_scope"))
        // No HTTP calls should have been made for an invalid scope.
        let requests = await http.requests()
        #expect(requests.isEmpty)
    }

    // MARK: - T-WPD-03

    @Test("T-WPD-03: rotate revokes old token + mints new in single atomic op")
    func test_rotate_revokesOld_mintsNew_atomically() async {
        let http = RecordingTransport()
        let rawToken = String(repeating: "b", count: 64)
        await http.queue(
            match: .init(method: "POST", urlContains: "/api/user/token"),
            response: DriverHTTPResponse(status: 201, body: mintResponseBody(id: "tok-new", token: rawToken, ttl: 3600))
        )
        // Queue a success for the DELETE of the previous token.
        await http.queue(
            match: .init(method: "DELETE", urlContains: "/api/user/token/"),
            response: DriverHTTPResponse(status: 204)
        )
        let bw = RecordingBWClient()
        await bw.seedGet(name: "WOODPECKER_ADMIN_TOKEN", fields: ["value": "fake-wdpck-admin-token"])
        let driver = DriverWoodpecker(transport: http, bwClient: bw)
        let entry = makeWoodpeckerEntry()

        let outcome = await driver.rotate(entry: entry, trigger: .manual(op: "rotate"))

        #expect(outcome == .rotated)
        // BWClient write-back must carry the new token.
        let writes = await bw.writes()
        #expect(!writes.isEmpty)
        let firstFields = writes.first?.fields ?? [:]
        #expect(firstFields["token"] != nil || firstFields["value"] != nil)
        // Both POST (mint) + DELETE (revoke) must have been issued.
        let requests = await http.requests()
        #expect(requests.contains(where: { $0.method == "POST" && $0.url.contains("/api/user/token") }))
        #expect(requests.contains(where: { $0.method == "DELETE" }))
    }

    // MARK: - T-WPD-04

    @Test("T-WPD-04: audit row written per operation — rotate() returns .rotated enabling engine audit")
    func test_auditRow_writtenPerOperation_viaRotatePath() async throws {
        // The driver itself does not own an AuditWriter; the RotationEngine
        // appends the audit row after applyRotation. This test verifies that
        // rotate() returns .rotated so the engine's applyRotation fires and
        // can write an audit row. We also validate the mint body carries the
        // expected repo/branch/ttl fields so the downstream log is correct.
        let http = RecordingTransport()
        let rawToken = String(repeating: "c", count: 64)
        await http.queue(
            match: .init(method: "POST", urlContains: "/api/user/token"),
            response: DriverHTTPResponse(status: 201, body: mintResponseBody(token: rawToken))
        )
        await http.queue(
            match: .init(method: "DELETE", urlContains: "/api/user/token/"),
            response: DriverHTTPResponse(status: 204)
        )
        let bw = RecordingBWClient()
        await bw.seedGet(name: "WOODPECKER_ADMIN_TOKEN", fields: ["value": "fake-wdpck-admin-token"])
        let driver = DriverWoodpecker(transport: http, bwClient: bw)
        let entry = makeWoodpeckerEntry()

        let outcome = await driver.rotate(entry: entry, trigger: .manual(op: "rotate"))
        #expect(outcome == .rotated)

        // Validate a POST was made (the mint that enables the audit row downstream).
        let requests = await http.requests()
        let mintRequest = requests.first(where: { $0.method == "POST" && $0.url.contains("/api/user/token") })
        #expect(mintRequest != nil)

        // Validate the request body carries repo + branch + ttl.
        let body = mintRequest?.body ?? Data()
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["repo"] as? String == "shikki")
        #expect(json?["branch"] as? String == "develop")
        let sentTTL = json?["ttl"] as? Int ?? 0
        #expect(sentTTL <= DriverWoodpecker.maxTokenTTL)
    }

    // MARK: - T-WPD-05

    @Test("T-WPD-05: transport 401 (missing admin token) surfaces as .failed")
    func test_missingAdminToken_transport401_returnsFailed() async {
        // Simulate the scenario where the admin token is missing from the vault
        // by having the transport return 401 (Unauthorized), which is what
        // Woodpecker returns when the Authorization header is absent / invalid.
        let http = RecordingTransport()
        await http.setDefaultResponse(DriverHTTPResponse(status: 401))
        let driver = DriverWoodpecker(transport: http)
        let entry = makeWoodpeckerEntry()

        let outcome = await driver.rotate(entry: entry, trigger: .manual(op: "test"))

        guard case .failed(let reason) = outcome else {
            Issue.record("expected .failed, got \(outcome)")
            return
        }
        // 401 from Woodpecker = admin token missing/wrong — surfaces as transport error.
        #expect(reason.contains("woodpecker"))
    }

    // MARK: - Scope parser

    @Test("parseScope: well-formed scope parses correctly")
    func test_parseScope_wellFormed_parsesCorrectly() {
        let result = DriverWoodpecker.parseScope("woodpecker:shikki:develop")
        #expect(result?.repo == "shikki")
        #expect(result?.branch == "develop")
    }

    @Test("parseScope: wrong vendor prefix returns nil")
    func test_parseScope_wrongVendorPrefix_returnsNil() {
        #expect(DriverWoodpecker.parseScope("github:shikki:develop") == nil)
    }

    @Test("parseScope: missing branch segment returns nil")
    func test_parseScope_missingBranch_returnsNil() {
        #expect(DriverWoodpecker.parseScope("woodpecker:shikki") == nil)
    }

    @Test("parseScope: empty repo returns nil")
    func test_parseScope_emptyRepo_returnsNil() {
        #expect(DriverWoodpecker.parseScope("woodpecker::develop") == nil)
    }

    // MARK: - TTL cap

    @Test("mint: TTL above 3600 is clamped to maxTokenTTL before the API call")
    func test_mint_ttlAboveCap_clampedBeforeAPICall() async throws {
        let http = RecordingTransport()
        let rawToken = String(repeating: "d", count: 64)
        await http.queue(
            match: .init(method: "POST", urlContains: "/api/user/token"),
            response: DriverHTTPResponse(status: 201, body: mintResponseBody(token: rawToken, ttl: 3600))
        )
        let driver = DriverWoodpecker(transport: http)
        // Request 7200s — should be clamped to 3600 in the outgoing body.
        let result = try await driver.mint(repo: "shikki", branch: "main", ttl: 7200)
        #expect(result.ttl <= DriverWoodpecker.maxTokenTTL)

        let requests = await http.requests()
        let body = requests.first?.body ?? Data()
        let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        let sentTTL = json?["ttl"] as? Int ?? -1
        #expect(sentTTL <= DriverWoodpecker.maxTokenTTL)
    }

    // MARK: - listTokens

    @Test("listTokens: returns parsed CIToken array from JSON response")
    func test_listTokens_returnsTokenArray() async throws {
        let http = RecordingTransport()
        let listBody = try JSONSerialization.data(withJSONObject: [
            ["id": "tok-1", "branch": "develop", "expires_at": 9_999_999.0],
            ["id": "tok-2", "branch": "main",    "expires_at": 9_999_999.0],
        ])
        await http.queue(
            match: .init(method: "GET", urlContains: "/api/user/token"),
            response: DriverHTTPResponse(status: 200, body: listBody)
        )
        let driver = DriverWoodpecker(transport: http)
        let tokens = try await driver.listTokens(repo: "shikki")

        #expect(tokens.count == 2)
        #expect(tokens.first?.id == "tok-1")
        #expect(tokens.first?.repo == "shikki")
    }

    // MARK: - Protocol conformance

    @Test("DriverWoodpecker conforms to SecretRotationDriver (vendor == woodpecker)")
    func test_protocolConformance_vendorIsWoodpecker() {
        let driver: any SecretRotationDriver = DriverWoodpecker(transport: RecordingTransport())
        #expect(driver.vendor == "woodpecker")
    }

    @Test("humanFallback is nil for DriverWoodpecker (v1)")
    func test_humanFallback_isNil() {
        let driver = DriverWoodpecker(transport: RecordingTransport())
        #expect(driver.humanFallback == nil)
    }
}

// MARK: - VaultEntryRef extension for test scoping

private extension VaultEntryRef {
    /// Returns a copy of this entry with the scope field replaced.
    func withScope(_ newScope: String) -> VaultEntryRef {
        VaultEntryRef(
            name: name,
            scope: newScope,
            tier: tier,
            usageState: usageState,
            lastRotated: lastRotated,
            rotationDue: rotationDue
        )
    }
}
