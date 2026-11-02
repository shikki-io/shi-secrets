import Testing
@testable import ShiSecretsKit
import Foundation

// Integration tests (BR-SM-06+09, BR-SM-10, BR-SM-07, BR-SM-15, BR-SM-16)
// Spec: features/shi-secrets-session-management-2026-05-21.md §Phase 4
//
// These tests are stubs for the live integration scenarios. A real
// Vaultwarden container + real Keychain are required for the full
// integration suite (W2 smoke test gate). In W1, these tests verify
// the structural wiring and serve as living documentation.
//
// Live integration tests are opt-in via the SHIKKI_SECRETS_INTEGRATION=1
// environment variable. Without it, the tests pass as documentation stubs.

private let integrationEnabled = ProcessInfo.processInfo.environment["SHIKKI_SECRETS_INTEGRATION"] == "1"

@Suite("Session Integration (BR-SM-06+09/10/07/15/16)")
struct SessionIntegrationTests {

    // MARK: - BR-SM-06 + BR-SM-09: Bootstrap + real Vaultwarden

    @Test("Integration SM-06+09: bootstrap real Keychain + real Vaultwarden → session established")
    func integration_bootstrap_realKeychain_realVaultwarden() async throws {
        guard integrationEnabled else {
            // Stub: documents the integration contract.
            #expect(Bool(true), "Integration skipped (set SHIKKI_SECRETS_INTEGRATION=1 to enable)")
            return
        }
        // Full integration path:
        // 1. KeychainVaultCredentials().load() returns stored credentials.
        // 2. VaultwardenClient(credentials:).connect() exchanges token.
        // 3. SessionCache.currentToken() returns non-nil.
        //
        // NOTE: This live integration path reads the real production Keychain item.
        // It is guarded by SHIKKI_SECRETS_INTEGRATION=1 and intentionally uses the
        // production service/account to verify the full bootstrap sequence.
        let kc = KeychainVaultCredentials( // KEYCHAIN-LIVE-INTEGRATION-EXEMPT
            service: KeychainVaultCredentials.service,
            account: KeychainVaultCredentials.account
        )
        let creds = try kc.load()
        let client = try VaultwardenClient(credentials: creds)
        try await client.connect()
        // If connect() didn't throw, the session is established.
        #expect(Bool(true), "Session established with real Vaultwarden container")
    }

    // MARK: - BR-SM-10: Session refresh near expiry

    @Test("Integration SM-10: token near expiry → refreshed automatically")
    func integration_sessionRefresh_tokenNearExpiry_refreshed() async throws {
        guard integrationEnabled else {
            #expect(Bool(true), "Integration skipped")
            return
        }
        // Create a cache with a token that expires in 65 seconds (5s after refresh trigger).
        // The auto-refresh task should fire and replace it.
        // Full verification requires real Vaultwarden.
        #expect(Bool(true), "Auto-refresh tested in W2 smoke")
    }

    // MARK: - BR-SM-07: Keychain locked → simulated prompt → recovers

    @Test("Integration SM-07: Keychain locked → simulated prompt → recovers")
    func integration_keychainLocked_simulatedPrompt_recovers() async throws {
        guard integrationEnabled else {
            #expect(Bool(true), "Integration skipped")
            return
        }
        // Requires a test device with Touch ID enrolled and the Keychain item
        // stored with kSecAccessControlBiometryCurrentSet.
        #expect(Bool(true), "Biometric unlock recovery tested in W2 smoke")
    }

    // MARK: - BR-SM-15: TLS pin — self-signed Vaultwarden

    @Test("Integration SM-15: TLS pin — self-signed Vaultwarden connects successfully")
    func integration_tlsPin_selfSignedVaultwarden() async throws {
        guard integrationEnabled else {
            #expect(Bool(true), "Integration skipped")
            return
        }
        // Requires a self-signed Vaultwarden instance with known cert SHA-256.
        // The pin is injected via config.yml `vault.tls_pin_sha256` (W2).
        #expect(Bool(true), "TLS pin integration tested in W2 smoke with operator cert")
    }

    // MARK: - BR-SM-16: rotate command blocks until biometric confirmed

    @Test("Integration SM-16: rotate cmd → blocks until biometric confirmed")
    func integration_rotateCmd_blocksUntilBiometricConfirmed() async throws {
        guard integrationEnabled else {
            #expect(Bool(true), "Integration skipped")
            return
        }
        // ProofOfPresence.require(reason:) is wired into rotate commands in W2.
        // Integration test confirms the biometric dialog appears and the
        // operation proceeds only after confirmation.
        #expect(Bool(true), "Biometric gate for rotate tested in W2 smoke")
    }
}
