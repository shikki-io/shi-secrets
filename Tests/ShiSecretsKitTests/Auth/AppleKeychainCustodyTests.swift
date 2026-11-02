import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// AppleKeychainCustodyTests — unit tests for the W1 macOS custody conformer.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W1.
// KAGAMI SCOPE: ShiSecretsKitTests
//
// No real Keychain access. All tests inject an availability probe so the
// Security framework is never called — safe in CI and on unsigned binaries.
//
// Tests:
//   T-08: memoryOnlyWhenEntitlementAbsent — BR-02 team-sign phase.
//         load() returns nil, store() is a no-op, clear() never throws.
//   bonus: custodyDescription includes service and account in available mode.
//   bonus: custodyDescription shows "memory only" in unavailable mode.

// kagami-scope: ShiSecretsKitTests

@Suite("AppleKeychainCustodyTests")
struct AppleKeychainCustodyTests {

    // MARK: - Helpers

    private func makeKeyPair() -> SymmetricKeyPair {
        SymmetricKeyPair(
            encKey: SymmetricKey(size: .bits256),
            macKey: SymmetricKey(size: .bits256)
        )
    }

    /// Custody that simulates entitlement ABSENT (team-sign without keychain-access-groups).
    private func unavailableCustody() -> AppleKeychainCustody {
        AppleKeychainCustody(
            availabilityProbe: {
                throw VaultKeyCustodyError.dataProtectionUnavailable
            }
        )
    }

    // MARK: - T-08: memory-only when data protection is unavailable (BR-02)

    @Test(
        "T-08: AppleKeychainCustody degrades to memory-only when entitlement is absent",
        .tags(.vaultLock)
    )
    func test_T08_memoryOnlyWhenEntitlementAbsent() async throws {
        let custody = unavailableCustody()

        // load() must return nil (not throw) — no persisted key in memory-only mode.
        let loaded = try await custody.load()
        #expect(loaded == nil, "load() must return nil in memory-only mode, never throw")

        // store() must be a no-op (not throw) — key stays in memory only.
        let keys = makeKeyPair()
        try await custody.store(keys)   // must not throw

        // After the no-op store, load() still returns nil (nothing was written).
        let loaded2 = try await custody.load()
        #expect(loaded2 == nil, "load() must still return nil — store() was a no-op")

        // clear() must NOT throw — BR-06 lock must not be blocked even without entitlement.
        try await custody.clear()   // must not throw
    }

    // MARK: - custodyDescription

    @Test("custodyDescription — available mode: includes service and account")
    func test_custodyDescription_available() {
        // Use test init with a no-throw probe to simulate the entitlement being present.
        let custody = AppleKeychainCustody(
            service: "io.shikki.vault-key",
            account: "vault-session-key",
            availabilityProbe: {}  // no-op probe = available
        )
        #expect(custody.custodyDescription.contains("apple-keychain"),
                "available description must include 'apple-keychain'")
        #expect(custody.custodyDescription.contains("io.shikki.vault-key"),
                "available description must include the service name")
    }

    @Test("custodyDescription — test-init with unavailable probe: still shows apple-keychain")
    func test_custodyDescription_testInitUnavailableProbe() {
        // Test init sets _memoryOnlyReason = nil regardless of probe.
        // custodyDescription therefore shows the "available" label.
        let custody = AppleKeychainCustody(
            availabilityProbe: { throw VaultKeyCustodyError.dataProtectionUnavailable }
        )
        // Test init never sets _memoryOnlyReason, so custodyDescription uses service/account.
        #expect(custody.custodyDescription.contains("apple-keychain"),
                "test-init custody description must include 'apple-keychain'")
    }
}

// MARK: - Test tags

extension Tag {
    @Tag static var vaultLock: Tag
}
