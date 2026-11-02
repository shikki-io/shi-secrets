// DeviceLockE2ETests — process-level E2E for screen-lock / screen-unlock vault behaviour.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W2.
// Harness: real shi-secrets-brokerd binary, FakeVaultwardenServer,
//          --dry-run, file-backed custody (SHIKKI_E2E_CUSTODY_FILE).
//
// Tests:
//   T-02: deviceLockDropsKeyWithin2s_unlockRestoresFromCustody — BR-03, BR-04
//
// Wire: vault.simulate.device_lock / vault.simulate.device_unlock are
//       only available in --dry-run mode (ManualDeviceLockSignalSource).
//
// KAGAMI SCOPE: ShiSecretsE2ETests
// All tests run through FakeVaultwardenServer; no real Keychain; no vw.obyw.one.

import Foundation
import ShiSecretsClient
import ShiSecretsKit
import Testing

// kagami-scope: ShiSecretsE2ETests

@Suite("DeviceLockE2ETests", .serialized, .timeLimit(.minutes(4)))
struct DeviceLockE2ETests {

    // MARK: - Fixtures

    static let fixtureClientID     = "e2e-devlock-id"
    static let fixtureClientSecret = "e2e-devlock-secret-xxxxxxx"
    static let fixturePassword     = "DevLockMasterPw99!"
    static let fixtureEmail        = "devlock@e2e.local"

    // MARK: - T-02: device lock drops key within 2 s; unlock restores from custody (BR-03, BR-04)

    @Test("T-02: device lock drops key within 2 s; device unlock restores from custody without password")
    func test_T02_deviceLockDropsKeyWithin2s_unlockRestoresFromCustody() async throws {
        let sandbox = try BrokerSandbox()
        defer { sandbox.cleanUp() }
        let custodyFile = sandbox.custodyFile
        let socketPath  = sandbox.makeSocketPath()

        let server = try FakeVaultwardenServer(
            clientID:       Self.fixtureClientID,
            clientSecret:   Self.fixtureClientSecret,
            masterPassword: Self.fixturePassword,
            email:          Self.fixtureEmail
        )
        try await server.start()
        defer { server.stop() }

        let binaryPath = try await VaultCustodyE2ETests.resolveBinary()
        let env = sandbox.brokerEnvironment(clientID: Self.fixtureClientID, clientSecret: Self.fixtureClientSecret, vaultPort: server.port, socketPath: socketPath)

        // ── Launch broker in --dry-run mode ────────────────────────────────
        let broker = try sandbox.launchBroker(binaryPath: binaryPath, socketPath: socketPath, environment: env)
        defer {
            broker.terminate()
            try? FileManager.default.removeItem(atPath: socketPath)
        }
        try await waitForSocket(socketPath, timeout: 15)

        let client = ProductionBrokerClient(socket: SocketConnection(socketPath: socketPath))

        // Vault starts locked.
        let s0 = try await client.vaultStatus()
        #expect(s0.locked == true, "vault must start locked before unlock")

        // Unlock the vault — this writes the custody file.
        try await client.vaultUnlock(
            masterPassword: Self.fixturePassword,
            email: Self.fixtureEmail
        )
        let s1 = try await client.vaultStatus()
        #expect(s1.locked == false, "vault must be unlocked after unlock")
        #expect(
            FileManager.default.fileExists(atPath: custodyFile),
            "custody file must exist after unlock"
        )

        // ── Fire simulated device-lock ─────────────────────────────────────
        // BR-03: screen lock drops key within 2 seconds.
        // The simulation verb fires the event synchronously inside the broker
        // actor; the 50 ms sleep in BrokerWireDispatch ensures the lock has
        // been applied before the response returns.
        try await client.simulateDeviceLock()

        // Poll for locked state (must transition within 2 s per BR-03).
        let lockDeadline = Date().addingTimeInterval(2.0)
        var vaultLockedAfterDeviceLock = false
        while Date() < lockDeadline {
            let st = try await client.vaultStatus()
            if st.locked {
                vaultLockedAfterDeviceLock = true
                break
            }
            try await Task.sleep(nanoseconds: 50_000_000) // 50 ms
        }
        #expect(vaultLockedAfterDeviceLock, "BR-03: vault must be locked within 2 s of device-lock event")

        // Custody file must still exist (only the in-memory key is dropped by lock;
        // the file is cleared by vault.lock (BR-06), not by device-lock).
        #expect(
            FileManager.default.fileExists(atPath: custodyFile),
            "custody file must survive a device-lock (only in-memory key is dropped)"
        )

        // ── Fire simulated device-unlock ───────────────────────────────────
        // BR-04: screen unlock restores key from custody without a password prompt.
        // The simulation verb fires the event and the 100 ms sleep in BrokerWireDispatch
        // ensures the restore has been attempted before the response returns.
        try await client.simulateDeviceUnlock()

        // Poll for unlocked state.
        let unlockDeadline = Date().addingTimeInterval(3.0)
        var vaultUnlockedAfterDeviceUnlock = false
        while Date() < unlockDeadline {
            let st = try await client.vaultStatus()
            if !st.locked {
                vaultUnlockedAfterDeviceUnlock = true
                break
            }
            try await Task.sleep(nanoseconds: 50_000_000) // 50 ms
        }
        #expect(vaultUnlockedAfterDeviceUnlock, "BR-04: vault must be unlocked after device-unlock (custody restore)")
    }

    // MARK: - Helpers

    private func waitForSocket(_ path: String, timeout: TimeInterval) async throws {
        // Delegates to the shared helper that serialises broker startups via
        // BrokerProcessGate, preventing socket-wait timeouts under CPU contention.
        try await E2ESupport.waitForBrokerSocket(path, timeout: timeout)
    }

    enum DevLockE2EError: Error, CustomStringConvertible {
        case socketTimeout(String)
        var description: String {
            switch self {
            case .socketTimeout(let p): return "socket did not appear at \(p)"
            }
        }
    }
}
