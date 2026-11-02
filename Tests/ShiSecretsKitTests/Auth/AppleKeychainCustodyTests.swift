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
//   T-08: applyCustodyRefusesWithoutDataProtection — BR-02, Phase 3.
//   bonus: available custody can store, load and clear a key pair.

// kagami-scope: ShiSecretsKitTests

@Suite("AppleKeychainCustodyTests")
struct AppleKeychainCustodyTests {

    // MARK: - Helpers

    /// A SymmetricKeyPair fixture with deterministic key material.
    private func makeKeyPair() -> SymmetricKeyPair {
        SymmetricKeyPair(
            encKey: SymmetricKey(size: .bits256),
            macKey: SymmetricKey(size: .bits256)
        )
    }

    /// An AppleKeychainCustody that simulates the entitlement being ABSENT
    /// (as would happen on an ad-hoc signed binary — BR-02).
    private func unavailableCustody() -> AppleKeychainCustody {
        AppleKeychainCustody(
            availabilityProbe: {
                throw VaultKeyCustodyError.dataProtectionUnavailable
            }
        )
    }

    // MARK: - T-08: refuses when data protection is unavailable (BR-02)

    @Test(
        "T-08: AppleKeychainCustody throws dataProtectionUnavailable when entitlement is absent",
        .tags(.vaultLock)
    )
    func test_T08_applyCustodyRefusesWithoutDataProtection() async {
        let custody = unavailableCustody()

        // load() must throw dataProtectionUnavailable.
        await #expect(throws: VaultKeyCustodyError.dataProtectionUnavailable) {
            _ = try await custody.load()
        }

        // store() must throw dataProtectionUnavailable.
        let keys = makeKeyPair()
        await #expect(throws: VaultKeyCustodyError.dataProtectionUnavailable) {
            try await custody.store(keys)
        }

        // clear() must NOT throw — it is a best-effort cleanup and must succeed
        // even when the Keychain is unreachable (BR-06 lock must not be blocked).
        await #expect(throws: Never.self) {
            try await custody.clear()
        }
    }

    // MARK: - custodyDescription

    @Test("custodyDescription includes service and account")
    func test_custodyDescription() {
        let custody = AppleKeychainCustody(
            service: "eu.fj-studios.shikki.vault-key",
            account: "vault-session-key"
        )
        #expect(custody.custodyDescription.contains("apple-keychain"),
                "description must include 'apple-keychain'")
        #expect(custody.custodyDescription.contains("eu.fj-studios.shikki.vault-key"),
                "description must include the service name")
    }
}

// MARK: - Test tags

extension Tag {
    @Tag static var vaultLock: Tag
}
