import Crypto
import Foundation

// AppleKeychainCustody — macOS/iOS VaultKeyCustody implementation.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W1.
//
// BR-02: uses kSecAttrAccessibleWhenUnlockedThisDeviceOnly +
//         kSecUseDataProtectionKeychain so the vault key is only accessible
//         when the screen is unlocked and never leaves the device.
//
// ENTITLEMENT REQUIREMENT (data-protection Keychain):
//   A binary carrying `keychain-access-groups` enables persistent custody.
//   Without it, checkAvailability() receives errSecMissingEntitlement from
//   kSecUseDataProtectionKeychain and the custody silently degrades:
//     - load()  → nil (no persisted key; vault starts locked)
//     - store() → no-op (key stays memory-only after unlock)
//     - custodyDescription → "memory only — <reason>"
//   vault.status shows the backend as "memory only — …" when unlocked.
//   Re-entry of the master password is required after each daemon restart.
//   This is the team-sign phase behaviour; the .app follow-up restores
//   persistence by registering keychain-access-groups in the Portal.
//
// Non-Apple platforms: always throw tpmUnavailable("Apple Keychain not available").

// MARK: - Apple platform implementation

#if canImport(Security) && (os(macOS) || os(iOS) || os(tvOS) || os(watchOS))

public struct AppleKeychainCustody: VaultKeyCustody, Sendable {

    // Keychain identity (service + account uniquely identify the item).
    private let service: String
    private let account: String
    /// Optional keychain-access-group (used once the entitlement is registered).
    private let accessGroup: String?
    /// The Keychain seam. Production resolves `SystemKeychainStore` from the
    /// DI container; tests register an in-memory store. Custody never touches
    /// the Security framework itself.
    private let keychain: any KeychainStore
    /// Non-nil when the data-protection Keychain is unavailable (no entitlement).
    /// Probed once at init through the seam.
    private let memoryOnlyReason: String?

    // MARK: - Init

    /// The single init. Probes the injected store once; when it reports a
    /// reason, load()/store() degrade silently without touching the Keychain.
    public init(
        service: String = "io.shikki.vault-key",
        account: String = "vault-session-key",
        accessGroup: String? = nil,
        keychain: any KeychainStore
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.keychain = keychain
        self.memoryOnlyReason = keychain.memoryOnlyReason(service: service, accessGroup: accessGroup)
    }

    // MARK: - VaultKeyCustody

    /// Load the vault key from the data-protection Keychain.
    ///
    /// Returns nil if:
    ///   - The binary lacks keychain-access-groups (memory-only mode).
    ///   - No item exists yet (first run or after a clear).
    /// Throws on unexpected Keychain errors (malformed data, etc.).
    public func load() async throws -> SymmetricKeyPair? {
        if memoryOnlyReason != nil { return nil }
        guard let data = try keychain.read(service: service, account: account, accessGroup: accessGroup) else {
            return nil
        }
        return try deserializeVaultKeyPair(data)
    }

    /// Persist the vault key in the data-protection Keychain.
    ///
    /// No-op when the binary lacks keychain-access-groups (memory-only mode).
    public func store(_ keys: SymmetricKeyPair) async throws {
        if memoryOnlyReason != nil { return }   // memory-only: no-op
        try keychain.write(
            serializeVaultKeyPair(keys), service: service, account: account, accessGroup: accessGroup
        )
    }

    /// Delete the vault key item. No-op if the item does not exist.
    ///
    /// Does NOT check availability — BR-06 vault.lock must not be blocked by
    /// a missing entitlement or an unreachable Keychain.
    public func clear() async throws {
        keychain.delete(service: service, account: account, accessGroup: accessGroup)
    }

    public nonisolated var custodyDescription: String {
        if let reason = memoryOnlyReason {
            return "memory only — \(reason)"
        }
        return "apple-keychain (\(service)/\(account))"
    }
}

// MARK: - Non-Apple stub

#else

/// Stub for non-Apple platforms — always throws `tpmUnavailable`.
public struct AppleKeychainCustody: VaultKeyCustody, Sendable {
    public init() {}

    public func load() async throws -> SymmetricKeyPair? {
        throw VaultKeyCustodyError.tpmUnavailable(
            reason: "Apple Keychain not available on this platform"
        )
    }

    public func store(_ keys: SymmetricKeyPair) async throws {
        throw VaultKeyCustodyError.tpmUnavailable(
            reason: "Apple Keychain not available on this platform"
        )
    }

    public func clear() async throws {
        throw VaultKeyCustodyError.tpmUnavailable(
            reason: "Apple Keychain not available on this platform"
        )
    }

    public nonisolated var custodyDescription: String { "apple-keychain (unavailable on this platform)" }
}

#endif
