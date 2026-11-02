// VaultReencryptE2ETests — process-level E2E for vault status reason and reencrypt count.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W4.
// Harness: real shi-secrets-brokerd binary, FakeVaultwardenServer,
//          --dry-run, file-backed custody (SHIKKI_E2E_CUSTODY_FILE).
//
// Tests:
//   T-04: corruptedCustodyReportsReasonInStatus — BR-08
//   T-07: reencryptReturnsEntryCount            — BR-10
//
// No real Keychain; no real broker; no vw.obyw.one.
// KAGAMI SCOPE: ShiSecretsE2ETests

import Foundation
import ShiSecretsClient
import ShiSecretsKit
import Testing

// kagami-scope: ShiSecretsE2ETests

@Suite("VaultReencryptE2ETests", .serialized, .timeLimit(.minutes(4)))
struct VaultReencryptE2ETests {

    // MARK: - Fixtures

    static let fixtureClientID     = "e2e-reencrypt-id"
    static let fixtureClientSecret = "e2e-reencrypt-secret-xxxxxxx"
    static let fixturePassword     = "ReencryptMasterPw99!"
    static let fixtureEmail        = "reencrypt@e2e.local"

    // MARK: - T-04: corrupted custody file → vault.status carries lockReason (BR-08)

    @Test("T-04: corrupted custody file is reported as lockReason in vault.status")
    func test_T04_corruptedCustodyReportsReasonInStatus() async throws {
        let tmpDir = makeTmpDir(tag: "t04")
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let custodyFile = (tmpDir as NSString).appendingPathComponent("vault.key")
        let socketPath1 = (tmpDir as NSString).appendingPathComponent("broker1.sock")
        let socketPath2 = (tmpDir as NSString).appendingPathComponent("broker2.sock")

        let server = try FakeVaultwardenServer(
            clientID:       Self.fixtureClientID,
            clientSecret:   Self.fixtureClientSecret,
            masterPassword: Self.fixturePassword,
            email:          Self.fixtureEmail
        )
        try await server.start()
        defer { server.stop() }

        let binaryPath = try VaultCustodyE2ETests.resolveBinary()
        let baseEnv: [String: String] = [
            "SHIKKI_E2E_CLIENT_ID":     Self.fixtureClientID,
            "SHIKKI_E2E_CLIENT_SECRET": Self.fixtureClientSecret,
            "SHIKKI_E2E_VAULT_URL":     "http://127.0.0.1:\(server.port)",
            "SHIKKI_E2E_CUSTODY_FILE":  custodyFile,
            "HOME":                     NSHomeDirectory(),
            "PATH":                     "/usr/bin:/bin:/usr/local/bin",
        ]

        // ── Phase 1: unlock vault so custody file is written ───────────────
        var env1 = baseEnv
        env1["SHIKKI_BROKER_SOCKET"] = socketPath1

        let broker1 = Process()
        broker1.executableURL  = URL(fileURLWithPath: binaryPath)
        broker1.arguments      = ["--dry-run", "--socket", socketPath1]
        broker1.environment    = env1
        broker1.standardOutput = FileHandle.nullDevice
        broker1.standardError  = FileHandle.nullDevice
        try broker1.run()
        defer {
            broker1.terminate()
            try? FileManager.default.removeItem(atPath: socketPath1)
        }
        try await waitForSocket(socketPath1, timeout: 25)

        let client1 = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath1))
        try await client1.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )
        #expect(
            FileManager.default.fileExists(atPath: custodyFile),
            "custody file must exist after unlock"
        )
        broker1.terminate()
        try await Task.sleep(nanoseconds: 200_000_000) // 200 ms for clean shutdown

        // ── Phase 2: corrupt the custody file ─────────────────────────────
        let garbage = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0xAB, 0xCD])
        try garbage.write(to: URL(fileURLWithPath: custodyFile))

        // ── Phase 3: start fresh broker — restore will fail ────────────────
        var env2 = baseEnv
        env2["SHIKKI_BROKER_SOCKET"] = socketPath2

        let broker2 = Process()
        broker2.executableURL  = URL(fileURLWithPath: binaryPath)
        broker2.arguments      = ["--dry-run", "--socket", socketPath2]
        broker2.environment    = env2
        broker2.standardOutput = FileHandle.nullDevice
        broker2.standardError  = FileHandle.nullDevice
        try broker2.run()
        defer {
            broker2.terminate()
            try? FileManager.default.removeItem(atPath: socketPath2)
        }
        try await waitForSocket(socketPath2, timeout: 25)

        // Give the broker time to attempt (and fail) the custody restore.
        try await Task.sleep(nanoseconds: 500_000_000) // 500 ms

        let client2 = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath2))

        // BR-08: failed store read → locked with a non-nil reason.
        let status = try await client2.vaultStatus()
        #expect(status.locked == true, "vault must be locked after corrupted custody")
        #expect(
            status.reason != nil && !(status.reason ?? "").isEmpty,
            "BR-08: vault.status must carry a lockReason when custody read fails; got: \(String(describing: status.reason))"
        )
    }

    // MARK: - T-07: vault.reencrypt re-encrypts plaintext entries and asserts ciphertext (BR-10)

    @Test("T-07: vault.reencrypt re-encrypts plaintext entries and server stores ciphertext")
    func test_T07_reencryptWritesCiphertextOnServer() async throws {
        let tmpDir = makeTmpDir(tag: "t07")
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let custodyFile = (tmpDir as NSString).appendingPathComponent("vault.key")
        let socketPath  = (tmpDir as NSString).appendingPathComponent("broker.sock")

        let server = try FakeVaultwardenServer(
            clientID:       Self.fixtureClientID,
            clientSecret:   Self.fixtureClientSecret,
            masterPassword: Self.fixturePassword,
            email:          Self.fixtureEmail
        )
        try await server.start()
        defer { server.stop() }

        // Seed 3 plaintext entries directly on the server (bypassing client encryption).
        // These simulate legacy ciphers written before the encryption fix (#47).
        let plainCount = 3
        for i in 1...plainCount {
            _ = server.seedPlaintextCipher(name: "legacy-secret-\(i)", notes: "plainvalue-\(i)")
        }

        let binaryPath = try VaultCustodyE2ETests.resolveBinary()
        let env: [String: String] = [
            "SHIKKI_E2E_CLIENT_ID":     Self.fixtureClientID,
            "SHIKKI_E2E_CLIENT_SECRET": Self.fixtureClientSecret,
            "SHIKKI_E2E_VAULT_URL":     "http://127.0.0.1:\(server.port)",
            "SHIKKI_BROKER_SOCKET":     socketPath,
            "SHIKKI_E2E_CUSTODY_FILE":  custodyFile,
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
        defer {
            broker.terminate()
            try? FileManager.default.removeItem(atPath: socketPath)
        }
        try await waitForSocket(socketPath, timeout: 25)

        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath))

        // Unlock vault first — required to derive the session key used for encryption.
        try await client.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )

        // BR-10: vault.reencrypt re-encrypts the legacy plaintext ciphers.
        let result = try await client.vaultReencrypt()
        #expect(
            result.count == plainCount,
            "BR-10: vault.reencrypt must re-encrypt \(plainCount) plaintext items, got count=\(result.count)"
        )
        #expect(
            result.failures.isEmpty,
            "BR-10: vault.reencrypt must succeed for all items, failures=\(result.failures)"
        )

        // Assert server now holds EncStrings (name and notes both start with "2.").
        // FakeVaultwardenServer.assertCiphersAreEncrypted() throws if any field is plaintext.
        try server.assertCiphersAreEncrypted()
    }

    // MARK: - Helpers

    private func makeTmpDir(tag: String) -> String {
        let path = "/tmp/shi-reencrypt-e2e-\(tag)-\(UUID().uuidString.prefix(8))"
        try? FileManager.default.createDirectory(
            atPath: path, withIntermediateDirectories: true
        )
        return path
    }

    private func waitForSocket(_ path: String, timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: path) { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw ReencryptE2EError.socketTimeout(path)
    }

    enum ReencryptE2EError: Error, CustomStringConvertible {
        case socketTimeout(String)
        var description: String {
            switch self {
            case .socketTimeout(let p): return "socket did not appear at \(p)"
            }
        }
    }
}
