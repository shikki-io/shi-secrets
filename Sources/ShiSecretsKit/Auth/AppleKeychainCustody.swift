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
import Security

public struct AppleKeychainCustody: VaultKeyCustody, Sendable {

    // Keychain identity (service + account uniquely identify the item).
    private let service: String
    private let account: String
    /// Optional keychain-access-group (used once the entitlement is registered).
    private let accessGroup: String?
    /// Overridable availability probe — inject for tests (avoids real Keychain).
    /// nil → use the pre-computed `_memoryOnlyReason` from the production init.
    private let availabilityProbe: (@Sendable () throws -> Void)?
    /// Non-nil when the data-protection Keychain is unavailable (no entitlement).
    /// Set once at production init time via a synchronous SecItemAdd probe.
    /// Nil for the test init — tests control availability via `availabilityProbe`.
    private let _memoryOnlyReason: String?

    // MARK: - Init

    /// Production init — probes data-protection Keychain availability at
    /// construction time (synchronous SecItemAdd + delete round-trip).
    ///
    /// If errSecMissingEntitlement is returned, `_memoryOnlyReason` is set and
    /// load()/store() degrade silently without touching the Keychain.
    public init(
        service: String = "io.shikki.vault-key",
        account: String = "vault-session-key",
        accessGroup: String? = nil
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.availabilityProbe = nil
        self._memoryOnlyReason = Self.probeDataProtectionKeychain(
            service: service, accessGroup: accessGroup
        )
    }

    /// Test-only init — inject a probe that drives availability behaviour.
    ///
    /// Probe semantics:
    ///   - throw VaultKeyCustodyError.dataProtectionUnavailable → memory-only
    ///   - return normally                                       → available
    ///
    /// `_memoryOnlyReason` is always nil for this init; custodyDescription
    /// reflects the "available" label regardless of the probe.
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
        self._memoryOnlyReason = nil
    }

    // MARK: - VaultKeyCustody

    /// Load the vault key from the data-protection Keychain.
    ///
    /// Returns nil if:
    ///   • The binary lacks keychain-access-groups (memory-only mode).
    ///   • No item exists yet (first run or after a clear).
    /// Throws on unexpected Keychain errors (malformed data, etc.).
    public func load() async throws -> SymmetricKeyPair? {
        // Memory-only mode (production: entitlement absent).
        if let _ = _memoryOnlyReason { return nil }
        // Test path: let the injected probe decide.
        if let probe = availabilityProbe {
            do { try probe() } catch VaultKeyCustodyError.dataProtectionUnavailable { return nil }
        }
        var query: [CFString: Any] = [
            kSecClass:                     kSecClassGenericPassword,
            kSecAttrService:               service,
            kSecAttrAccount:               account,
            kSecReturnData:                true,
            kSecMatchLimit:                kSecMatchLimitOne,
            kSecUseDataProtectionKeychain: true,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        // Belt-and-suspenders: degrade if the entitlement was revoked post-init.
        if status == errSecMissingEntitlement { return nil }
        guard status == errSecSuccess else {
            throw VaultKeyCustodyError.malformedData(expectedBytes: 64, gotBytes: 0)
        }
        guard let data = result as? Data else {
            throw VaultKeyCustodyError.malformedData(expectedBytes: 64, gotBytes: 0)
        }
        return try deserializeVaultKeyPair(data)
    }

    /// Persist the vault key in the data-protection Keychain.
    ///
    /// No-op when the binary lacks keychain-access-groups (memory-only mode).
    /// Uses kSecAttrAccessibleWhenUnlockedThisDeviceOnly + kSecUseDataProtectionKeychain
    /// so the item is inaccessible while the screen is locked (BR-03 hardware assist)
    /// and not synced to iCloud (BR-02).
    public func store(_ keys: SymmetricKeyPair) async throws {
        if let _ = _memoryOnlyReason { return }   // memory-only: no-op
        if let probe = availabilityProbe {
            do { try probe() } catch VaultKeyCustodyError.dataProtectionUnavailable { return }
        }
        let data = serializeVaultKeyPair(keys)
        var query: [CFString: Any] = [
            kSecClass:                     kSecClassGenericPassword,
            kSecAttrService:               service,
            kSecAttrAccount:               account,
            kSecUseDataProtectionKeychain: true,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        let updateAttrs: [CFString: Any] = [
            kSecValueData:                data,
            kSecAttrAccessible:           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess { return }
        var addQuery = query
        addQuery[kSecValueData]      = data as AnyObject
        addQuery[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        // errSecMissingEntitlement post-init: silently degrade.
        if addStatus == errSecSuccess || addStatus == errSecMissingEntitlement { return }
        throw VaultKeyCustodyError.dataProtectionUnavailable
    }

    /// Delete the vault key item. No-op if the item does not exist.
    ///
    /// Does NOT check availability — BR-06 vault.lock must not be blocked by
    /// a missing entitlement or an unreachable Keychain.
    public func clear() async throws {
        var query: [CFString: Any] = [
            kSecClass:                     kSecClassGenericPassword,
            kSecAttrService:               service,
            kSecAttrAccount:               account,
            kSecUseDataProtectionKeychain: true,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        let status = SecItemDelete(query as CFDictionary)
        // errSecItemNotFound and errSecMissingEntitlement are both acceptable.
        _ = status
    }

    public nonisolated var custodyDescription: String {
        if let reason = _memoryOnlyReason {
            return "memory only — \(reason)"
        }
        return "apple-keychain (\(service)/\(account))"
    }

    // MARK: - Private probe (production init)

    /// Synchronous probe: attempt to add a throwaway data-protection Keychain
    /// item.  Returns a non-nil reason string if the entitlement is absent.
    private static func probeDataProtectionKeychain(
        service: String,
        accessGroup: String?
    ) -> String? {
        let probeAccount = "avail-probe-\(UUID().uuidString)"
        var query: [CFString: Any] = [
            kSecClass:                     kSecClassGenericPassword,
            kSecAttrService:               service,
            kSecAttrAccount:               probeAccount,
            kSecValueData:                 Data([0x00]),
            kSecAttrAccessible:            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseDataProtectionKeychain: true,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecMissingEntitlement {
            return "keychain-access-groups not present — team-signed binary; add entitlement + .app wrapper to enable persistence"
        }
        if status == errSecSuccess {
            var deleteQuery: [CFString: Any] = [
                kSecClass:                     kSecClassGenericPassword,
                kSecAttrService:               service,
                kSecAttrAccount:               probeAccount,
                kSecUseDataProtectionKeychain: true,
            ]
            if let group = accessGroup { deleteQuery[kSecAttrAccessGroup] = group }
            _ = SecItemDelete(deleteQuery as CFDictionary)
        }
        return nil   // available
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
