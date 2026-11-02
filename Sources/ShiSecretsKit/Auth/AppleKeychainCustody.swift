import Crypto
import Foundation

// AppleKeychainCustody — macOS/iOS VaultKeyCustody implementation.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W1.
//
// BR-02: uses kSecAttrAccessibleWhenUnlockedThisDeviceOnly, so the 64-byte
//         vault key is only accessible when the screen is unlocked and never
//         leaves the device (no iCloud sync, no backup).
//
// Entitlement requirement: the binary must be team-signed with SH7MZH647S
// and carry the keychain-access-groups entitlement (see
// ShikkiSecretsBrokerd.entitlements). An ad-hoc signed binary will get
// errSecMissingEntitlement → checkAvailability() throws dataProtectionUnavailable
// → store() is a no-op (key stays memory-only).
//
// Carry-over: the old items (io.shikki.vault / vault-credentials,
// io.shikki.vault.token / client-credentials-access-token) are left alone;
// this item lives at a distinct service+account pair so nothing breaks during
// the migration period.
//
// Non-Apple platforms: always throw tpmUnavailable("Apple Keychain not available").

// MARK: - Apple platform implementation

#if canImport(Security) && (os(macOS) || os(iOS) || os(tvOS) || os(watchOS))
import Security

public struct AppleKeychainCustody: VaultKeyCustody, Sendable {

    // Keychain identity (service + account uniquely identify the item).
    private let service: String
    private let account: String
    /// Optional keychain-access-group (needed once the entitlement is set).
    private let accessGroup: String?
    /// Overridable availability probe — inject for tests (avoids real Keychain).
    /// nil → real `SecItemAdd` probe against kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
    private let availabilityProbe: (@Sendable () throws -> Void)?

    /// Production init.
    public init(
        service: String = "io.shikki.vault-key",
        account: String = "vault-session-key",
        accessGroup: String? = nil
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.availabilityProbe = nil
    }

    /// Test-only init — inject a probe that drives availability check behaviour.
    ///
    /// Probe semantics:
    ///   - throw VaultKeyCustodyError.dataProtectionUnavailable  → simulates missing entitlement
    ///   - return normally                                        → simulates entitlement present
    public init(
        service: String = "io.shikki.vault-key",
        account: String = "vault-session-key",
        accessGroup: String? = nil,
        availabilityProbe: @escaping @Sendable () throws -> Void
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.availabilityProbe = availabilityProbe
    }

    // MARK: - VaultKeyCustody

    /// Load the vault key from the data protection Keychain.
    ///
    /// Returns nil if no item exists (first run or after a clear).
    /// Throws VaultKeyCustodyError.dataProtectionUnavailable if the
    /// binary lacks the keychain-access-groups entitlement.
    public func load() async throws -> SymmetricKeyPair? {
        try checkAvailability()
        var query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData:  true,
            kSecMatchLimit:  kSecMatchLimitOne,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            // Any other Keychain error → report as malformed so the broker
            // logs "locked with reason" rather than silently staying locked.
            throw VaultKeyCustodyError.malformedData(expectedBytes: 64, gotBytes: 0)
        }
        guard let data = result as? Data else {
            throw VaultKeyCustodyError.malformedData(expectedBytes: 64, gotBytes: 0)
        }
        return try deserializeVaultKeyPair(data)
    }

    /// Persist the vault key in the data protection Keychain.
    ///
    /// Uses kSecAttrAccessibleWhenUnlockedThisDeviceOnly so the item is:
    ///   - inaccessible while the screen is locked (BR-03 hardware assist)
    ///   - not synced to iCloud, not backed up (BR-02)
    ///
    /// Attempts an update first; if the item does not exist, adds it.
    /// Throws VaultKeyCustodyError.dataProtectionUnavailable if the
    /// binary is ad-hoc signed (errSecMissingEntitlement).
    public func store(_ keys: SymmetricKeyPair) async throws {
        try checkAvailability()
        let data = serializeVaultKeyPair(keys)
        var query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }

        // Try update first (item might already exist from a previous run).
        let updateAttrs: [CFString: Any] = [
            kSecValueData:      data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess { return }

        // Item not found — add it.
        var addQuery = query
        addQuery[kSecValueData]      = data as AnyObject
        addQuery[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess { return }

        // Map Keychain errors that indicate a missing entitlement.
        if addStatus == errSecMissingEntitlement {
            throw VaultKeyCustodyError.dataProtectionUnavailable
        }
        // Generic Keychain failure — surface as dataProtectionUnavailable so
        // the broker stays memory-only rather than crashing.
        throw VaultKeyCustodyError.dataProtectionUnavailable
    }

    /// Delete the vault key item. No-op if the item does not exist.
    ///
    /// Does NOT check availability — called by vault.lock which must always
    /// attempt cleanup even when the Keychain is unreachable (BR-06).
    public func clear() async throws {
        var query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        let status = SecItemDelete(query as CFDictionary)
        // errSecItemNotFound is not an error — there is nothing to clear.
        // All other failures are ignored: the in-memory key is already dropped
        // by VaultwardenClient.lockVault() before clear() is called (BR-06).
        _ = status
    }

    public nonisolated var custodyDescription: String {
        "apple-keychain (\(service)/\(account))"
    }

    // MARK: - Availability check

    /// Probe the data protection Keychain to confirm the binary holds the
    /// keychain-access-groups entitlement required by BR-02.
    ///
    /// Uses the injected probe when set (test seam), otherwise performs a
    /// real `SecItemAdd` / `SecItemDelete` round-trip with a UUID-keyed
    /// temporary item.
    private func checkAvailability() throws {
        if let probe = availabilityProbe {
            try probe()
            return
        }
        // Real probe: add a throwaway item with the same accessibility class
        // to confirm the entitlement is present.
        let probeAccount = "availability-probe-\(UUID().uuidString)"
        var probeQuery: [CFString: Any] = [
            kSecClass:          kSecClassGenericPassword,
            kSecAttrService:    service,
            kSecAttrAccount:    probeAccount,
            kSecValueData:      Data([0x00]),
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        if let group = accessGroup { probeQuery[kSecAttrAccessGroup] = group }
        let addStatus = SecItemAdd(probeQuery as CFDictionary, nil)
        if addStatus == errSecMissingEntitlement {
            throw VaultKeyCustodyError.dataProtectionUnavailable
        }
        // Clean up the probe item (best-effort; a leftover probe is harmless).
        if addStatus == errSecSuccess {
            var deleteQuery: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: probeAccount,
            ]
            if let group = accessGroup { deleteQuery[kSecAttrAccessGroup] = group }
            _ = SecItemDelete(deleteQuery as CFDictionary)
        }
        // Any other status (errSecDuplicateItem from a race, etc.) is treated
        // as "available" — the real add/update/load will surface the real error.
    }
}

// MARK: - Non-Apple stub

#else

/// Stub for non-Apple platforms — always throws `tpmUnavailable`.
///
/// Ships so Linux targets that import ShiSecretsKit can still link; all
/// callers must branch on platform before instantiating this type.
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
