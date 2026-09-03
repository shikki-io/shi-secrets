import Foundation
@testable import ShiSecretsBrokerd
@testable import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// SecretsLifecycleRealVaultwardenTests — W3 end-to-end tests against a
// mock Vaultwarden server that faithfully implements /api/ciphers CRUD.
//
// Two test modes:
//
//   1. MockVaultwardenServer (default, no external deps) — in-process
//      URLProtocol intercept that responds to cipher CRUD with realistic
//      JSON. Covers the full BWClient.{set,get,list,delete} call graph
//      without a real network.
//
//   2. Live Vaultwarden (opt-in via VAULTWARDEN_LIVE_TEST=1 env var) —
//      exercises the real vw.obyw.one endpoint using credentials from
//      the macOS Keychain. Skipped by default in CI.
//
// TP-LC-R01  full lifecycle: set → get → list → delete → list (absent)
// TP-LC-R02  set is idempotent (upsert: second set replaces, not duplicates)
// TP-LC-R03  delete non-existent is no-op (no error)
// TP-LC-R04  list is empty after all keys deleted

// MARK: - Mock Vaultwarden URLProtocol

/// In-process mock server for the Vaultwarden cipher CRUD API.
/// Stores ciphers in-memory; responds with realistic JSON envelopes.
final class MockVaultwardenProtocol: URLProtocol, @unchecked Sendable {

    // Shared in-memory state — tests must run serialized (@Suite(.serialized)).
    // nonisolated(unsafe): access is serialized by the @Suite(.serialized) contract.
    nonisolated(unsafe) static var ciphers: [String: MockCipher] = [:]

    struct MockCipher: Sendable {
        let id: String
        let name: String
        let notes: String
    }

    static func reset() { ciphers = [:] }

    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url?.absoluteString else { return false }
        return url.contains("mock-vw.test")
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = client, let req = self.request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }

        let path = req.path
        let method = self.request.httpMethod ?? "GET"

        // POST /api/ciphers — create
        if method == "POST" && path == "/api/ciphers" {
            handleCreate(url: url)
        }
        // GET /api/ciphers — list
        else if method == "GET" && path == "/api/ciphers" {
            handleList(url: url)
        }
        // GET /api/ciphers/{id}
        else if method == "GET" && path.hasPrefix("/api/ciphers/") {
            let id = String(path.dropFirst("/api/ciphers/".count))
            handleGet(id: id, url: url)
        }
        // DELETE /api/ciphers/{id}
        else if method == "DELETE" && path.hasPrefix("/api/ciphers/") {
            let id = String(path.dropFirst("/api/ciphers/".count))
            handleDelete(id: id, url: url)
        }
        // POST /identity/connect/token — return fake access_token
        else if method == "POST" && path.contains("/identity/connect/token") {
            handleTokenExchange(url: url)
        }
        else {
            respond(url: url, status: 404, body: Data())
        }
    }

    override func stopLoading() {}

    private func handleTokenExchange(url: URLProtocolClient) {
        let json = """
        {"access_token":"mock-token-valid","expires_in":3600,"token_type":"Bearer","scope":"api"}
        """.data(using: .utf8)!
        respond(url: url, status: 200, body: json)
    }

    private func handleCreate(url: URLProtocolClient) {
        // URLProtocol may deliver body via httpBody or httpBodyStream.
        let bodyData: Data?
        if let d = self.request.httpBody {
            bodyData = d
        } else if let stream = self.request.httpBodyStream {
            stream.open()
            var data = Data()
            let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
            defer { buf.deallocate() }
            while stream.hasBytesAvailable {
                let n = stream.read(buf, maxLength: 4096)
                if n > 0 { data.append(buf, count: n) }
            }
            stream.close()
            bodyData = data
        } else {
            bodyData = nil
        }
        guard let body = bodyData,
              let decoded = try? JSONDecoder().decode(CipherCreateBody.self, from: body) else {
            respond(url: url, status: 400, body: Data())
            return
        }
        let id = UUID().uuidString
        MockVaultwardenProtocol.ciphers[id] = MockCipher(id: id, name: decoded.name, notes: decoded.notes ?? "")
        let json = cipherJSON(id: id, name: decoded.name, notes: decoded.notes ?? "").data(using: .utf8)!
        respond(url: url, status: 200, body: json)
    }

    private func handleList(url: URLProtocolClient) {
        let items = MockVaultwardenProtocol.ciphers.values.map { c in
            """
            {"id":"\(c.id)","name":"\(c.name)","type":2,"notes":"\(c.notes)","object":"cipherDetails",
             "login":null,"fields":[],"card":null,"identity":null,"secureNote":{"type":0},
             "favorite":false,"edit":true,"collectionIds":[]}
            """
        }.joined(separator: ",")
        let json = """
        {"object":"list","data":[\(items)],"continuationToken":null}
        """.data(using: .utf8)!
        respond(url: url, status: 200, body: json)
    }

    private func handleGet(id: String, url: URLProtocolClient) {
        guard let c = MockVaultwardenProtocol.ciphers[id] else {
            respond(url: url, status: 404, body: Data())
            return
        }
        respond(url: url, status: 200, body: cipherJSON(id: c.id, name: c.name, notes: c.notes).data(using: .utf8)!)
    }

    private func handleDelete(id: String, url: URLProtocolClient) {
        MockVaultwardenProtocol.ciphers.removeValue(forKey: id)
        respond(url: url, status: 200, body: Data())
    }

    private func cipherJSON(id: String, name: String, notes: String) -> String {
        """
        {"id":"\(id)","name":"\(name)","type":2,"notes":"\(notes)","object":"cipherDetails",
         "login":null,"fields":[],"card":null,"identity":null,"secureNote":{"type":0},
         "favorite":false,"edit":true,"collectionIds":[]}
        """
    }

    private func respond(url: URLProtocolClient, status: Int, body: Data) {
        let resp = HTTPURLResponse(
            url: self.request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        url.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        url.urlProtocol(self, didLoad: body)
        url.urlProtocolDidFinishLoading(self)
    }

    private struct CipherCreateBody: Decodable {
        let name: String
        let notes: String?
        let type: Int
    }
}

// MARK: - Mock VaultwardenClient factory

private func mockVaultwardenClient() async throws -> VaultwardenClient {
    let creds = VaultwardenCredentials(
        clientID: "user.mock",
        clientSecret: "mock-secret",
        serverURL: URL(string: "https://mock-vw.test")!
    )
    let client = try VaultwardenClient(
        credentials: creds,
        configYmlVaultServer: "https://mock-vw.test",
        urlProtocolClasses: [MockVaultwardenProtocol.self]
    )
    // The vault must be UNLOCKED before anything can be written, because the
    // write path now encrypts. These tests used to pass without this step —
    // that is precisely the defect: `createCipher` accepted plaintext and the
    // mock server, like the real one, stored it without complaint.
    //
    // Unlocking here means the mock exercises the real encrypt-on-write /
    // decrypt-on-read path end to end: whatever the mock server holds is
    // ciphertext, and `get` only returns the original if both halves work.
    await client.adoptSessionKeys(mockSessionKeys)
    return client
}

/// A fixed key pair for the mock. Deterministic so a failure is reproducible;
/// it protects nothing, because the mock server lives in this process.
private let mockSessionKeys = try! SymmetricKeyPair(
    userKey: Data(repeating: 0xA5, count: 32) + Data(repeating: 0x5A, count: 32)
)

// MARK: - TP-LC-R01..04 (mock server)

@Suite("SecretsLifecycleRealVaultwardenTests", .serialized)
struct SecretsLifecycleRealVaultwardenTests {

    // TP-LC-R01 — full lifecycle via mock Vaultwarden server
    @Test("TP-LC-R01: set → get → list → delete → list(absent) — mock Vaultwarden")
    func test_lcr01_fullLifecycle_mockVaultwarden() async throws {
        MockVaultwardenProtocol.reset()
        let vc = try await mockVaultwardenClient()
        try await vc.connect()

        let bw = ProductionBWClient()
        await bw.wire(client: vc)

        let key = "test-shikki-r01"
        let value = "test-value-r01"

        // 1. set
        try await bw.set(name: key, value: value)

        // 1b. WHAT THE SERVER ACTUALLY HOLDS.
        //
        // The whole original defect passes every assertion in this test except
        // this one: set/get/list/delete are all self-consistent when the client
        // writes plaintext and reads plaintext back. Only by looking at the
        // server's own copy does the bug become visible.
        //
        // The mock stores exactly the bytes it was sent, like the real
        // Vaultwarden — which never inspects a cipher and so never objected.
        let stored = MockVaultwardenProtocol.ciphers.values.first
        #expect(stored != nil, "the mock server should hold the item we just wrote")
        if let stored {
            #expect(stored.name != key,
                    "the item NAME reached the server in plaintext")
            #expect(stored.notes != value,
                    "the SECRET reached the server in plaintext")
            #expect(EncString.looksEncrypted(stored.name),
                    "name is not a well-formed EncString: \(stored.name.prefix(24))")
            #expect(EncString.looksEncrypted(stored.notes),
                    "notes is not a well-formed EncString: \(stored.notes.prefix(24))")
            #expect(!stored.notes.contains(value),
                    "the plaintext secret appears inside the stored ciphertext")
        }

        // 2. get — returns ["value": value] via SecureNote notes field
        let got = try await bw.get(name: key)
        #expect(got["value"] == value, "get after set must return stored value")

        // 3. list — must include the key
        let list = try await bw.list()
        #expect(list.contains(key), "list after set must include key")

        // 4. delete
        try await bw.delete(name: key)

        // 5. list — must NOT include key after delete
        let listAfter = try await bw.list()
        #expect(!listAfter.contains(key), "list after delete must NOT include key")
    }

    // TP-LC-R02 — set is idempotent (upsert: second set replaces)
    @Test("TP-LC-R02: set twice — list does not duplicate; get returns latest value")
    func test_lcr02_setIsIdempotent_noduplicates() async throws {
        MockVaultwardenProtocol.reset()
        let vc = try await mockVaultwardenClient()
        try await vc.connect()
        let bw = ProductionBWClient()
        await bw.wire(client: vc)

        let key = "test-shikki-r02"

        try await bw.set(name: key, value: "value-first")
        try await bw.set(name: key, value: "value-second")

        let list = try await bw.list()
        let matching = list.filter { $0 == key }
        #expect(matching.count == 1, "set twice must not duplicate — upsert semantics")

        let got = try await bw.get(name: key)
        #expect(got["value"] == "value-second", "get after double-set must return latest value")

        // cleanup
        try await bw.delete(name: key)
    }

    // TP-LC-R03 — delete non-existent is no-op
    @Test("TP-LC-R03: delete non-existent key — no error")
    func test_lcr03_deleteNonexistent_noOp() async throws {
        MockVaultwardenProtocol.reset()
        let vc = try await mockVaultwardenClient()
        try await vc.connect()
        let bw = ProductionBWClient()
        await bw.wire(client: vc)

        // Should not throw
        try await bw.delete(name: "key-that-does-not-exist-r03")
    }

    // TP-LC-R04 — list empty after all keys deleted
    @Test("TP-LC-R04: set two keys, delete both — list is empty")
    func test_lcr04_listEmptyAfterAllDeleted() async throws {
        MockVaultwardenProtocol.reset()
        let vc = try await mockVaultwardenClient()
        try await vc.connect()
        let bw = ProductionBWClient()
        await bw.wire(client: vc)

        try await bw.set(name: "key-a-r04", value: "va")
        try await bw.set(name: "key-b-r04", value: "vb")

        var list = try await bw.list()
        #expect(list.count == 2)

        try await bw.delete(name: "key-a-r04")
        try await bw.delete(name: "key-b-r04")

        list = try await bw.list()
        #expect(list.isEmpty, "list must be empty after all keys deleted")
    }

    // TP-LC-R05 — BrokerWireDispatcher end-to-end via in-process dispatch
    @Test("TP-LC-R05: BrokerWireDispatcher.secret.set → secret.get (InMemoryBWClient)")
    func test_lcr05_wireDispatcher_setThenGetViaInMemory() async throws {
        let stack = try await E2ESupport.make(
            scopeAllowlist: ["ci/*", "foo/*"]
        )
        defer { Task { await E2ESupport.tearDown(stack) } }
        try await stack.daemon.start()

        let dispatcher = BrokerWireDispatcher(daemon: stack.daemon, bridge: await stack.daemon.bridge)

        // secret.set
        let setReq = WireRequest(
            method: "secret.set",
            params: .object([
                "name": .string("test-wire-key"),
                "value": .string("test-wire-value"),
            ]),
            id: "r05-set"
        )
        let setResp = await dispatcher.dispatch(setReq, peerUid: UInt32(geteuid()))
        #expect(setResp.error == nil, "secret.set must not return error; got: \(String(describing: setResp.error))")
        if case .object(let obj) = setResp.result {
            #expect(obj["ok"] == .bool(true), "secret.set result.ok must be true")
        }

        // secret.list — Bug-2 fix: returns [VaultEntryRef] objects, not bare strings.
        // Extract "name" field from each object to check membership.
        let listReq = WireRequest(method: "secret.list", params: nil, id: "r05-list")
        let listResp = await dispatcher.dispatch(listReq, peerUid: UInt32(geteuid()))
        #expect(listResp.error == nil, "secret.list must not error")
        if case .array(let items) = listResp.result {
            let names = items.compactMap { item -> String? in
                guard case .object(let obj) = item,
                      case .string(let n) = obj["name"] else { return nil }
                return n
            }
            #expect(names.contains("test-wire-key"), "list must include set key; names=\(names)")
        }

        // secret.delete
        let delReq = WireRequest(
            method: "secret.delete",
            params: .object(["name": .string("test-wire-key")]),
            id: "r05-del"
        )
        let delResp = await dispatcher.dispatch(delReq, peerUid: UInt32(geteuid()))
        #expect(delResp.error == nil, "secret.delete must not error")

        // secret.list after delete — must not contain key
        let listReq2 = WireRequest(method: "secret.list", params: nil, id: "r05-list2")
        let listResp2 = await dispatcher.dispatch(listReq2, peerUid: UInt32(geteuid()))
        if case .array(let items2) = listResp2.result {
            let names2 = items2.compactMap { item -> String? in
                guard case .object(let obj) = item,
                      case .string(let n) = obj["name"] else { return nil }
                return n
            }
            #expect(!names2.contains("test-wire-key"), "list after delete must not include key; names=\(names2)")
        }
    }
}

// MARK: - Live Vaultwarden tests (VAULTWARDEN_LIVE_TEST=1 only)

// These tests round-trip against the real vw.obyw.one. Skipped by default.
// Run with: VAULTWARDEN_LIVE_TEST=1 kagami test --scope ShiSecretsE2E
// Requires vault credentials in macOS Keychain (run `shi secrets setup` first).

@Suite("SecretsLiveVaultwardenTests", .serialized)
struct SecretsLiveVaultwardenTests {

    private var liveTestEnabled: Bool {
        ProcessInfo.processInfo.environment["VAULTWARDEN_LIVE_TEST"] == "1"
    }

    @Test("TP-LC-LIVE-01: full lifecycle against real Vaultwarden (VAULTWARDEN_LIVE_TEST=1 required)")
    func test_live_fullLifecycle() async throws {
        guard liveTestEnabled else {
            // Not a failure — just not configured.
            return
        }

        // Load real credentials from Keychain (set by `shi secrets setup`).
        let keychainCreds = try KeychainVaultCredentials().load()
        let vc = try VaultwardenClient(
            credentials: keychainCreds,
            configYmlVaultServer: keychainCreds.serverURL.absoluteString
        )
        try await vc.connect()

        let bw = ProductionBWClient()
        await bw.wire(client: vc)

        let key = "test-shikki-live-\(Int(Date().timeIntervalSince1970))"
        let value = "live-test-value-\(UUID().uuidString.prefix(8))"

        // 1. set
        try await bw.set(name: key, value: value)

        // 2. get
        let got = try await bw.get(name: key)
        #expect(got["value"] == value, "live get after set must return stored value")

        // 3. list
        let list = try await bw.list()
        #expect(list.contains(key), "live list after set must include key")

        // 4. delete
        try await bw.delete(name: key)

        // 5. list after delete
        let listAfter = try await bw.list()
        #expect(!listAfter.contains(key), "live list after delete must NOT include key")
    }
}
