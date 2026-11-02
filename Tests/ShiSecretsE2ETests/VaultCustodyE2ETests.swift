// VaultCustodyE2ETests — process-level E2E for vault key custody.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W0.
// Harness: real shi-secrets-brokerd binary, FakeVaultwardenServer,
//          --dry-run, file-backed custody (SHIKKI_E2E_CUSTODY_FILE).
//
// Tests:
//   T-01: unlockPersistsKeyThenRestartOpensWithoutPassword  — BR-04
//   T-03: lockClearsMemoryAndStore                          — BR-06
//   T-06: masterPasswordIsNeverWritten                      — BR-01
//
// KAGAMI SCOPE: ShiSecretsE2ETests
// All tests run through FakeVaultwardenServer; no real Keychain; no vw.obyw.one.

import Foundation
import ShiSecretsClient
import ShiSecretsKit
import Testing

// kagami-scope: ShiSecretsE2ETests

@Suite("VaultCustodyE2ETests", .serialized, .timeLimit(.minutes(4)))
struct VaultCustodyE2ETests {

    // MARK: - Fixtures (same as ShiSecretsBrokerProcessE2E)

    static let fixtureClientID     = "e2e-custody-id"
    static let fixtureClientSecret = "e2e-custody-secret-xxxxxxx"
    static let fixturePassword     = "CustodyMasterPw99!"
    static let fixtureEmail        = "custody@e2e.local"

    // MARK: - T-01: unlock persists key; restart opens without password (BR-04)

    @Test("T-01: unlock persists key; broker restart opens without master password")
    func test_T01_unlockPersistsKey_restartOpensWithoutPassword() async throws {
        let tmpDir = makeTmpDir()
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

        let binaryPath = try Self.resolveBinary()
        let baseEnv: [String: String] = [
            "SHIKKI_E2E_CLIENT_ID":     Self.fixtureClientID,
            "SHIKKI_E2E_CLIENT_SECRET": Self.fixtureClientSecret,
            "SHIKKI_E2E_VAULT_URL":     "http://127.0.0.1:\(server.port)",
            "SHIKKI_BROKER_SOCKET":     socketPath,
            "SHIKKI_E2E_CUSTODY_FILE":  custodyFile,
            "HOME":                     NSHomeDirectory(),
            "PATH":                     "/usr/bin:/bin:/usr/local/bin",
        ]

        // ── Launch broker1 ──────────────────────────────────────────────────
        let broker1 = Process()
        broker1.executableURL  = URL(fileURLWithPath: binaryPath)
        broker1.arguments      = ["--dry-run", "--socket", socketPath]
        broker1.environment    = baseEnv
        broker1.standardOutput = FileHandle.nullDevice
        broker1.standardError  = FileHandle.nullDevice
        try broker1.run()
        try await waitForSocket(socketPath, timeout: 15)

        let client1 = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath))

        // Vault starts locked.
        let s1 = try await client1.vaultStatus()
        #expect(s1.locked == true, "vault must start locked before unlock")

        // Unlock the vault.
        try await client1.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )
        let s2 = try await client1.vaultStatus()
        #expect(s2.locked == false, "vault must be unlocked after unlock")

        // Verify custody file was written.
        #expect(
            FileManager.default.fileExists(atPath: custodyFile),
            "custody file must exist after unlock"
        )

        // Kill broker1.
        broker1.terminate()
        try await waitForSocketGone(socketPath, timeout: 5)
        try? FileManager.default.removeItem(atPath: socketPath)

        // ── Launch broker2 on same custody file ────────────────────────────
        let broker2 = Process()
        broker2.executableURL  = URL(fileURLWithPath: binaryPath)
        broker2.arguments      = ["--dry-run", "--socket", socketPath]
        broker2.environment    = baseEnv
        broker2.standardOutput = FileHandle.nullDevice
        broker2.standardError  = FileHandle.nullDevice
        defer { broker2.terminate() }
        try broker2.run()
        try await waitForSocket(socketPath, timeout: 15)

        let client2 = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath))

        // BR-04: vault must be unlocked without a master-password call.
        let s3 = try await client2.vaultStatus()
        #expect(
            s3.locked == false,
            "vault must open unlocked after restart when custody file holds the key (BR-04)"
        )
    }

    // MARK: - T-03: lock clears memory AND store (BR-06)

    @Test("T-03: vault.lock clears memory and custody file; restart sees locked vault")
    func test_T03_lockClearsMemoryAndStore() async throws {
        let tmpDir = makeTmpDir()
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

        let binaryPath = try Self.resolveBinary()
        let env: [String: String] = [
            "SHIKKI_E2E_CLIENT_ID":     Self.fixtureClientID,
            "SHIKKI_E2E_CLIENT_SECRET": Self.fixtureClientSecret,
            "SHIKKI_E2E_VAULT_URL":     "http://127.0.0.1:\(server.port)",
            "SHIKKI_BROKER_SOCKET":     socketPath,
            "SHIKKI_E2E_CUSTODY_FILE":  custodyFile,
            "HOME":                     NSHomeDirectory(),
            "PATH":                     "/usr/bin:/bin:/usr/local/bin",
        ]

        let broker1 = Process()
        broker1.executableURL  = URL(fileURLWithPath: binaryPath)
        broker1.arguments      = ["--dry-run", "--socket", socketPath]
        broker1.environment    = env
        broker1.standardOutput = FileHandle.nullDevice
        broker1.standardError  = FileHandle.nullDevice
        try broker1.run()
        try await waitForSocket(socketPath, timeout: 15)
        defer { broker1.terminate() }

        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath))

        // Unlock then lock.
        try await client.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )
        let afterUnlock = try await client.vaultStatus()
        #expect(afterUnlock.locked == false, "vault must be unlocked before lock test")

        // Verify custody file exists after unlock.
        #expect(
            FileManager.default.fileExists(atPath: custodyFile),
            "custody file must exist after unlock"
        )

        // Lock the vault.
        try await client.vaultLock()

        // Memory: must report locked immediately.
        let afterLock = try await client.vaultStatus()
        #expect(afterLock.locked == true, "vault must be locked after vault.lock")

        // Store: custody file must be gone.
        #expect(
            !FileManager.default.fileExists(atPath: custodyFile),
            "custody file must be deleted after vault.lock (BR-06)"
        )

        // Restart and confirm the vault is still locked (no key in custody).
        broker1.terminate()
        try await waitForSocketGone(socketPath, timeout: 5)
        try? FileManager.default.removeItem(atPath: socketPath)

        let broker2 = Process()
        broker2.executableURL  = URL(fileURLWithPath: binaryPath)
        broker2.arguments      = ["--dry-run", "--socket", socketPath]
        broker2.environment    = env
        broker2.standardOutput = FileHandle.nullDevice
        broker2.standardError  = FileHandle.nullDevice
        defer { broker2.terminate() }
        try broker2.run()
        try await waitForSocket(socketPath, timeout: 15)

        let client2 = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath))
        let afterRestart = try await client2.vaultStatus()
        #expect(
            afterRestart.locked == true,
            "vault must stay locked after restart — custody was cleared (BR-06)"
        )
    }

    // MARK: - T-06: master password never written (BR-01)

    @Test("T-06: master password is never written to any file in the test directory")
    func test_T06_masterPasswordIsNeverWritten() async throws {
        let tmpDir = makeTmpDir()
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

        let binaryPath = try Self.resolveBinary()
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
        try await waitForSocket(socketPath, timeout: 15)
        defer { broker.terminate() }

        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath))
        try await client.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )

        // Scan every file in tmpDir for the master password.
        // BR-01: the password must NEVER be written to any file.
        let password = Self.fixturePassword
        var violatingPaths: [String] = []
        let enumerator = FileManager.default.enumerator(atPath: tmpDir)
        while let name = enumerator?.nextObject() as? String {
            let path = (tmpDir as NSString).appendingPathComponent(name)
            var isDir: ObjCBool = false
            FileManager.default.fileExists(atPath: path, isDirectory: &isDir)
            guard !isDir.boolValue else { continue }
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { continue }
            // Try text decoding; if it fails the file is binary and can't contain the password.
            if let text = String(data: data, encoding: .utf8), text.contains(password) {
                violatingPaths.append(path)
            }
        }
        // Also check the custody file bytes for the password as UTF-8.
        if FileManager.default.fileExists(atPath: custodyFile),
           let custodyData = try? Data(contentsOf: URL(fileURLWithPath: custodyFile)),
           let text = String(data: custodyData, encoding: .utf8),
           text.contains(password) {
            violatingPaths.append(custodyFile + " (custody)")
        }

        #expect(
            violatingPaths.isEmpty,
            "BR-01: master password found in files: \(violatingPaths)"
        )
    }

    // MARK: - Helpers

    private func makeTmpDir() -> String {
        // Use /tmp directly — NSTemporaryDirectory() expands to
        // /var/folders/.../T/ which can produce paths near the 104-char
        // Unix domain socket limit on macOS.
        let path = "/tmp/shi-custody-e2e-\(UUID().uuidString.prefix(8))"
        try? FileManager.default.createDirectory(
            atPath: path, withIntermediateDirectories: true
        )
        return path
    }

    private func waitForSocket(_ path: String, timeout: TimeInterval) async throws {
        // Delegates to the shared helper that serialises broker process startups
        // across all E2E suites via BrokerProcessGate, preventing socket-wait
        // timeouts under CPU contention.
        try await E2ESupport.waitForBrokerSocket(path, timeout: timeout)
    }

    private func waitForSocketGone(_ path: String, timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if !FileManager.default.fileExists(atPath: path) { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        // Not fatal — caller cleans up manually.
    }

    static func resolveBinary() throws -> String {
        let cwd = FileManager.default.currentDirectoryPath
        let path = (cwd as NSString).appendingPathComponent(".build/debug/shi-secrets-brokerd")
        if !FileManager.default.fileExists(atPath: path) {
            let build = Process()
            build.executableURL     = URL(fileURLWithPath: "/usr/bin/swift")
            build.arguments         = ["build", "--product", "shi-secrets-brokerd"]
            build.currentDirectoryURL = URL(fileURLWithPath: cwd)
            build.standardOutput    = FileHandle.nullDevice
            try build.run()
            build.waitUntilExit()
        }
        guard FileManager.default.fileExists(atPath: path) else {
            throw CustodyE2EError.binaryMissing(path)
        }
        return path
    }

    enum CustodyE2EError: Error, CustomStringConvertible {
        case binaryMissing(String)
        case socketTimeout(String)
        var description: String {
            switch self {
            case .binaryMissing(let p):
                return "shi-secrets-brokerd not found at \(p)"
            case .socketTimeout(let p):
                return "socket did not appear at \(p)"
            }
        }
    }
}
