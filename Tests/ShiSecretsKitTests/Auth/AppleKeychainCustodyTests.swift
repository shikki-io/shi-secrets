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

    /// Resolve the keychain seam through the DI container, the way production
    /// does, but with the in-memory store registered: the real Keychain is
    /// unreachable from this suite.
    private func makeCustody(
        memoryOnlyReason: String? = nil,
        service: String = "io.shikki.vault-key",
        account: String = "vault-session-key"
    ) throws -> AppleKeychainCustody {
        let container = DIContainer()
        container.registerSingleton(
            (any KeychainStore).self,
            InMemoryKeychainStore(memoryOnlyReason: memoryOnlyReason)
        )
        return AppleKeychainCustody(
            service: service,
            account: account,
            keychain: try container.resolve((any KeychainStore).self)
        )
    }

    /// Custody that simulates entitlement ABSENT (team-sign without keychain-access-groups).
    private func unavailableCustody() throws -> AppleKeychainCustody {
        try makeCustody(memoryOnlyReason: "keychain-access-groups not present")
    }

    // MARK: - T-08: memory-only when data protection is unavailable (BR-02)

    @Test(
        "T-08: AppleKeychainCustody degrades to memory-only when entitlement is absent",
        .tags(.vaultLock)
    )
    func test_T08_memoryOnlyWhenEntitlementAbsent() async throws {
        let custody = try unavailableCustody()

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

    // MARK: - Round trip through the seam

    @Test("available store: store() then load() round-trips; clear() removes it")
    func test_roundTripWhenAvailable() async throws {
        let custody = try makeCustody()
        let keys = makeKeyPair()
        try await custody.store(keys)
        let loaded = try await custody.load()
        #expect(loaded != nil, "available store must persist the key")
        try await custody.clear()
        #expect(try await custody.load() == nil, "clear() must remove the item")
    }

    // MARK: - custodyDescription

    @Test("custodyDescription — available mode: includes service and account")
    func test_custodyDescription_available() throws {
        let custody = try makeCustody()
        #expect(custody.custodyDescription.contains("apple-keychain"))
        #expect(custody.custodyDescription.contains("io.shikki.vault-key"))
    }

    @Test("custodyDescription — unavailable store: memory only with the reason")
    func test_custodyDescription_unavailable() throws {
        let custody = try unavailableCustody()
        #expect(custody.custodyDescription.hasPrefix("memory only"))
    }
}

// MARK: - Test tags

extension Tag {
    @Tag static var vaultLock: Tag
}
