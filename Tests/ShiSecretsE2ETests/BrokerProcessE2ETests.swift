// BrokerProcessE2ETests — real process-level E2E for shi-secrets-brokerd.
//
// WHAT MAKES THIS REAL:
//   - shi-secrets-brokerd binary is spawned as a separate OS process
//   - Tests communicate over a real Unix socket via ProductionBrokerClient
//   - No @testable import ShiSecretsBrokerd — pure black-box
//   - FakeVaultwardenServer handles HTTP on loopback so no live Vaultwarden needed
//   - No Keychain access; no real secrets; no macOS dialogs
//
// BROKER LAUNCH MODE:
//   --dry-run --socket <path>
//   + env: SHIKKI_E2E_CLIENT_ID, SHIKKI_E2E_CLIENT_SECRET, SHIKKI_E2E_VAULT_URL
//
// KAGAMI SCOPE: ShiSecretsBrokerProcessE2E
//
// v0.8.0 REGRESSION PROOF:
//   The vault.unlock bug (session cache not seeded after unlock) caused
//   subsequent secret.set to throw notAuthenticated. The fix calls
//   refreshToken() instead of performTokenExchange(), which seeds the cache.
//   This test suite proves secret.set succeeds immediately after vault.unlock.

import Foundation
import ShiSecretsClient
import ShiSecretsKit
import Testing

// kagami-scope: ShiSecretsBrokerProcessE2E

@Suite("ShiSecretsBrokerProcessE2E", .serialized, .timeLimit(.minutes(4)))
struct ShiSecretsBrokerProcessE2E {

    // MARK: - Fixtures

    static let fixtureClientID     = "e2e-client-id"
    static let fixtureClientSecret = "e2e-client-secret-bbbbbbb"
    static let fixturePassword     = "FixtureMasterPw42!"
    static let fixtureEmail        = "fixture@e2e.local"

    // MARK: - Main scenario

    @Test("process round-trip: vault unlock → set → list → get")
    func test_roundTrip() async throws {
        let (server, client, broker, socketPath) = try await Self.setup()
        defer { broker.terminate(); server.stop() }
        defer { try? FileManager.default.removeItem(atPath: socketPath) }

        // vault.status → locked at startup
        let status1 = try await client.vaultStatus()
        #expect(status1.locked == true, "vault must start locked")

        // secret.set before unlock → error (notAuthenticated or locked)
        do {
            try await client.set(name: "premature", value: "x")
            Issue.record("secret.set before unlock must throw")
        } catch BrokerClientError.vaultAuthRequired(let auth) {
            // A locked / logged-out vault is a named state with a remedy,
            // never an internal -32603.
            #expect(auth.remedy.hasPrefix("shi secrets"), "remedy must be a shi command, got: \(auth.remedy)")
        } catch BrokerClientError.brokerError(_, let msg) {
            #expect(
                msg.lowercased().contains("notauthenticated") ||
                msg.lowercased().contains("locked") ||
                msg.lowercased().contains("vault"),
                "pre-unlock error must describe auth/lock state, got: \(msg)"
            )
        } catch {
            // Any error is acceptable — the key requirement is that it does not succeed.
        }

        // vault.unlock with correct password
        try await client.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )

        // vault.status → unlocked
        let status2 = try await client.vaultStatus()
        #expect(status2.locked == false, "vault must report unlocked after vault.unlock")

        // secret.set succeeds (v0.8.0 regression: this would throw notAuthenticated)
        try await client.set(name: "e2e-key", value: "e2e-value")

        // secret.list shows the key
        let list = try await client.list(filter: nil)
        #expect(list.contains(where: { $0.name == "e2e-key" }),
                "list must contain key we just set")

        // secret.get returns value
        let got = try await client.get(name: "e2e-key")
        #expect(got == "e2e-value", "get must return the stored value")

        // Verify the server stored ciphertext, not plaintext
        // (regression proof for the "wrote plaintext to Vaultwarden" bug)
        try server.assertCiphersAreEncrypted()
    }

    // MARK: - v0.8.0 regression focused test

    @Test("v0.8.0 regression: session seeded after vault.unlock — set succeeds")
    func test_v080_sessionSeededAfterUnlock() async throws {
        let (server, client, broker, socketPath) = try await Self.setup()
        defer { broker.terminate(); server.stop() }
        defer { try? FileManager.default.removeItem(atPath: socketPath) }

        // v0.8.0 bug: unlock appeared to succeed but sessionCache was never
        // seeded, so the NEXT bwClient call threw notAuthenticated.
        // Proof at head: unlock + immediate set both succeed.
        try await client.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )
        // This line is the regression gate — at v0.8.0 it would throw.
        try await client.set(name: "reg-key", value: "reg-value")
        let value = try await client.get(name: "reg-key")
        #expect(value == "reg-value",
                "v0.8.0 regression: set+get must succeed post-unlock")
    }

    // MARK: - Wrong password test

    @Test("the fake server refuses a request without the Bearer token, and an unknown id")
    func test_fakeServerEnforcesAuthAndIDs() async throws {
        let (server, _, broker, socketPath) = try await Self.setup()
        defer { broker.terminate(); server.stop() }
        defer { try? FileManager.default.removeItem(atPath: socketPath) }

        var components = URLComponents()
        components.scheme = "http"
        components.host = "127.0.0.1"
        components.port = server.port
        let ciphers = try #require(components.url)
            .appendingPathComponent("api")
            .appendingPathComponent("ciphers")

        let (_, noToken) = try await URLSession.shared.data(from: ciphers)
        #expect((noToken as? HTTPURLResponse)?.statusCode == 401)

        var delete = URLRequest(url: ciphers.appendingPathComponent("no-such-id"))
        delete.httpMethod = "DELETE"
        delete.setValue("Bearer \(server.accessToken)", forHTTPHeaderField: "Authorization")
        let (_, unknown) = try await URLSession.shared.data(for: delete)
        #expect((unknown as? HTTPURLResponse)?.statusCode == 404)
    }

    @Test("secret.delete: an entry leaves the list, and an unknown name is refused")
    func test_deleteRemovesTheEntry() async throws {
        let (server, client, broker, socketPath) = try await Self.setup()
        defer { broker.terminate(); server.stop() }
        defer { try? FileManager.default.removeItem(atPath: socketPath) }

        try await client.vaultUnlock(masterPassword: Self.fixturePassword, email: Self.fixtureEmail)
        try await client.set(name: "to-delete", value: "gone-soon")
        #expect(try await client.list(filter: nil).map(\.name).contains("to-delete"))

        try await client.delete(name: "to-delete")
        #expect(try await !client.list(filter: nil).map(\.name).contains("to-delete"))

        await #expect(throws: (any Error).self) {
            try await client.delete(name: "to-delete")
        }
    }

    @Test("vault.unlock with wrong password returns error")
    func test_wrongPassword_returnsError() async throws {
        let (server, client, broker, socketPath) = try await Self.setup()
        defer { broker.terminate(); server.stop() }
        defer { try? FileManager.default.removeItem(atPath: socketPath) }

        do {
            try await client.vaultUnlock(
                masterPassword: "totally-wrong-password",
                email: Self.fixtureEmail
            )
            Issue.record("unlock with wrong password must throw")
        } catch {
            // Any error is acceptable — wrong-password must not silently succeed.
        }
    }

    // MARK: - Socket cleanup test

    @Test("broker SIGTERM removes socket file")
    func test_sigterm_removesSocket() async throws {
        let (server, client, broker, socketPath) = try await Self.setup()
        server.stop()
        _ = client  // suppress warning

        #expect(FileManager.default.fileExists(atPath: socketPath),
                "socket must exist while broker is running")

        broker.terminate()

        // Wait up to 3s for the socket to disappear.
        for _ in 0..<30 {
            try await Task.sleep(nanoseconds: 100_000_000)
            if !FileManager.default.fileExists(atPath: socketPath) { break }
        }
        #expect(!FileManager.default.fileExists(atPath: socketPath),
                "socket must be removed after broker SIGTERM")
    }

    // MARK: - Restart test

    @Test("broker restart: vault returns to locked state after restart")
    func test_restartReturnsToLocked() async throws {
        let (server, client, broker, socketPath) = try await Self.setup()
        defer { server.stop() }
        defer { try? FileManager.default.removeItem(atPath: socketPath) }

        // Unlock the vault — the in-memory session key is now held by broker1.
        try await client.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )
        let status1 = try await client.vaultStatus()
        #expect(status1.locked == false, "vault must be unlocked before restart")

        // Terminate broker1 and wait for the socket to disappear.
        broker.terminate()
        for _ in 0..<30 {
            try await Task.sleep(nanoseconds: 100_000_000)
            if !FileManager.default.fileExists(atPath: socketPath) { break }
        }
        #expect(!FileManager.default.fileExists(atPath: socketPath),
                "socket must vanish before restart")

        // Launch broker2 on the same socket path — fresh process, no session state.
        let binaryPath = try Self.resolveBinary()
        let env: [String: String] = [
            "SHIKKI_E2E_CLIENT_ID":     Self.fixtureClientID,
            "SHIKKI_E2E_CLIENT_SECRET": Self.fixtureClientSecret,
            "SHIKKI_E2E_VAULT_URL":     "http://127.0.0.1:\(server.port)",
            "SHIKKI_BROKER_SOCKET":     socketPath,
            "HOME":                     NSHomeDirectory(),
            "PATH":                     "/usr/bin:/bin:/usr/local/bin",
        ]
        let broker2 = Process()
        broker2.executableURL  = URL(fileURLWithPath: binaryPath)
        broker2.arguments      = ["--dry-run", "--socket", socketPath]
        broker2.environment    = env
        broker2.standardOutput = FileHandle.nullDevice
        broker2.standardError  = FileHandle.nullDevice
        defer { broker2.terminate() }
        try broker2.run()

        // Wait for broker2's socket (up to 10 s).
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: socketPath) { break }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            throw E2EError.socketTimeout(socketPath)
        }

        // The fresh process holds no session key — vault must start locked.
        // SocketConnection opens a new connection per request, so no stale handle.
        let status2 = try await client.vaultStatus()
        #expect(status2.locked == true,
                "vault must be locked after restart — process restart must not persist session state")
    }

    // MARK: - Helpers

    private static func setup() async throws
        -> (server: FakeVaultwardenServer,
            client: ProductionBrokerClient,
            broker: Process,
            socketPath: String)
    {
        let server = try FakeVaultwardenServer(
            clientID:       fixtureClientID,
            clientSecret:   fixtureClientSecret,
            masterPassword: fixturePassword,
            email:          fixtureEmail
        )
        try await server.start()

        let binaryPath = try resolveBinary()
        let socketPath = "/tmp/e2e-brkr-\(UUID().uuidString.prefix(8)).sock"

        let env: [String: String] = [
            "SHIKKI_E2E_CLIENT_ID":     fixtureClientID,
            "SHIKKI_E2E_CLIENT_SECRET": fixtureClientSecret,
            "SHIKKI_E2E_VAULT_URL":     "http://127.0.0.1:\(server.port)",
            "SHIKKI_BROKER_SOCKET":     socketPath,
            "HOME":                     NSHomeDirectory(),
            "PATH":                     "/usr/bin:/bin:/usr/local/bin",
        ]

        let broker = Process()
        broker.executableURL  = URL(fileURLWithPath: binaryPath)
        broker.arguments      = ["--dry-run", "--socket", socketPath]
        broker.environment    = env
        broker.standardOutput = FileHandle.nullDevice
        broker.standardError  = FileHandle.nullDevice
        try broker.run()

        // Wait for socket to appear (up to 10 s).
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: socketPath) { break }
            try await Task.sleep(nanoseconds: 100_000_000)  // 100 ms
        }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            broker.terminate()
            server.stop()
            throw E2EError.socketTimeout(socketPath)
        }

        let client = ProductionBrokerClient(
            socket: SocketConnection(socketPath: socketPath)
        )
        return (server, client, broker, socketPath)
    }

    /// Resolve the broker binary path.
    /// If missing, attempts `swift build --product shi-secrets-brokerd`
    /// then fails the test (not skips) if still absent.
    private static func resolveBinary() throws -> String {
        let cwd = FileManager.default.currentDirectoryPath
        let path = (cwd as NSString).appendingPathComponent(".build/debug/shi-secrets-brokerd")
        if !FileManager.default.fileExists(atPath: path) {
            let build = Process()
            build.executableURL    = URL(fileURLWithPath: "/usr/bin/swift")
            build.arguments        = ["build", "--product", "shi-secrets-brokerd"]
            build.currentDirectoryURL = URL(fileURLWithPath: cwd)
            build.standardOutput   = FileHandle.nullDevice
            // Keep stderr so build errors appear in test output.
            try build.run()
            build.waitUntilExit()
        }
        guard FileManager.default.fileExists(atPath: path) else {
            throw E2EError.binaryMissing(path)
        }
        return path
    }

    // MARK: - Error types

    enum E2EError: Error, CustomStringConvertible {
        case binaryMissing(String)
        case socketTimeout(String)

        var description: String {
            switch self {
            case .binaryMissing(let p):
                return "shi-secrets-brokerd binary not found at \(p). " +
                       "Run `swift build --product shi-secrets-brokerd` first."
            case .socketTimeout(let p):
                return "broker socket did not appear at \(p) within 10 s"
            }
        }
    }
}
