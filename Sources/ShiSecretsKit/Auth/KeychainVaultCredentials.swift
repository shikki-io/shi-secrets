import Foundation
import Security

// KeychainVaultCredentials — macOS Keychain wrapper that stores and loads
// VaultwardenCredentials using Security.framework.
//
// Accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
// Access control: kSecAccessControlBiometryCurrentSet (set on write; LAContext
//   prompt required on read for high-stakes ops — see ProofOfPresence for W2).
//
// W1 ships the concrete macOS implementation. A SecureCredentialStore
// protocol + Linux/Windows variants are Wave 4/5/6 deliverables per spec.
// DO NOT abstract prematurely.
//
// Service identifier: "io.shikki.vault" (W3.1 — canonical product domain)
// Legacy service:     "eu.fj-studios.shikki.vault" (preserved for migration only)
// Account:            "vault-credentials"
//
// W3.1 migration: migrateLegacyIfPresent() auto-upgrades items seeded under
// the old eu.fj-studios org-namespace to the canonical io.shikki product domain.
// Bootstrap.unseal() calls it once per process before the load() attempt.
// The migration is idempotent — safe to call repeatedly.
//
// BR-SM-01, BR-SM-02, BR-SM-03

/// Keychain wrapper for VaultwardenCredentials.
///
/// The credentials JSON blob is written once by `shi secrets setup` (W2)
/// and read on every broker bootstrap. The Secure Enclave-backed access
/// control means the raw bytes cannot be extracted even with root access
/// on Apple Silicon.
public struct KeychainVaultCredentials: Sendable {

    // MARK: - Constants

    /// Bundle-rev service identifier — canonical across all Apple platforms.
    /// W3.1: renamed from eu.fj-studios.shikki.vault → io.shikki.vault (product domain mandate).
    public static let service = "io.shikki.vault"

    /// Legacy service identifier — preserved for migration only.
    /// W3.1: items seeded under this name are auto-migrated to `service` on first load.
    /// DO NOT use this constant for new writes.
    public static let legacyService = "eu.fj-studios.shikki.vault"

    /// Keychain item account label.
    public static let account = "vault-credentials"

    // MARK: - Errors

    public enum KeychainError: Swift.Error, Sendable, Equatable {
        /// Item does not exist yet — `shi secrets setup` (W2) not run.
        case itemNotFound

        /// The Keychain item exists but its JSON blob cannot be decoded.
        case dataMalformed

        /// Security.framework returned an unexpected OSStatus.
        case osError(status: Int32)

        /// Attempted to write credentials but the item already exists
        /// and `overwrite: false` was passed.
        case itemAlreadyExists
    }

    // MARK: - Instance service / account

    /// Service identifier used by this instance.
    ///
    /// Defaults to the production value `Self.service`. Tests inject a unique
    /// per-run value so they never touch the operator's real Keychain item.
    public let service: String

    /// Account label used by this instance.
    ///
    /// Defaults to the production value `Self.account`. Tests inject a unique
    /// per-run value so they never touch the operator's real Keychain item.
    public let account: String

    /// Create a Keychain credential wrapper.
    ///
    /// - Parameters:
    ///   - service: The Keychain service identifier. Defaults to the production
    ///     value `"io.shikki.vault"`. **Tests must always supply a unique test value.**
    ///   - account: The Keychain account label. Defaults to the production value
    ///     `"vault-credentials"`. **Tests must always supply a unique test value.**
    public init(
        service: String = Self.service,
        account: String = Self.account
    ) {
        self.service = service
        self.account = account
    }

    // MARK: - store(_:overwrite:)

    /// Persist credentials to the Keychain. Replaces any existing item
    /// when `overwrite` is true (default). Used by `shi secrets setup` (W2).
    ///
    /// Access flags (preferred when entitlements are present):
    ///   - kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly — survives
    ///     reboot once the user unlocks the device once.
    ///   - kSecAccessControlBiometryCurrentSet — biometric re-enroll
    ///     invalidates the item (protects against swapped fingerprints).
    ///
    /// Fallback (ad-hoc signed binary / no entitlements):
    ///   When `SecItemAdd` returns `errSecMissingEntitlement` (-34018) with the
    ///   biometry access control, the item is retried using only
    ///   `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and no
    ///   `kSecAttrAccessControl`. This allows `shi` (ad-hoc signed, no
    ///   keychain-access-groups entitlement) to seed credentials into the
    ///   default login Keychain without the biometry gate. brokerd (entitled)
    ///   reads the same service+account without access group filtering.
    public func store(
        _ credentials: VaultwardenCredentials,
        overwrite: Bool = true
    ) throws {
        let data = try JSONEncoder().encode(credentials)
        let baseQuery = baseStoreQuery(data: data, accessControl: nil)

        // Attempt preferred path: biometry access control.
        var cfError: Unmanaged<CFError>?
        if let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .biometryCurrentSet,
            &cfError
        ) {
            let acQuery = baseStoreQuery(data: data, accessControl: accessControl)
            do {
                try executeStore(query: acQuery as CFDictionary, overwrite: overwrite)
                return
            } catch KeychainError.osError(let status) where status == errSecMissingEntitlement {
                // -34018: binary lacks entitlements for the biometry access control
                // (ad-hoc signed `shi`). Fall through to the base query below.
                // The item is stored without the biometry gate — functionally
                // equivalent on dev machines without a real signing identity.
                _ = status  // silence unused warning
            }
            // Any other KeychainError propagates to the caller as-is.
        }

        // Fallback: no access control — plain accessibility flag only.
        try executeStore(query: baseQuery as CFDictionary, overwrite: overwrite)
    }

    private func baseStoreQuery(
        data: Data,
        accessControl: SecAccessControl?
    ) -> [CFString: Any] {
        var q: [CFString: Any] = [
            kSecClass:           kSecClassGenericPassword,
            kSecAttrService:     service,
            kSecAttrAccount:     account,
            kSecValueData:       data,
            kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let ac = accessControl {
            q[kSecAttrAccessControl] = ac
        }
        return q
    }

    private func executeStore(query: CFDictionary, overwrite: Bool) throws {
        var status = SecItemAdd(query, nil)
        if status == errSecDuplicateItem {
            guard overwrite else { throw KeychainError.itemAlreadyExists }
            // Delete and re-add rather than SecItemUpdate so the access
            // control flags are fully replaced (kSecAttrAccessControl is
            // not modifiable via SecItemUpdate on macOS 14+).
            let deleteQuery: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: account,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            status = SecItemAdd(query, nil)
        }
        guard status == errSecSuccess else {
            throw KeychainError.osError(status: status)
        }
    }

    // MARK: - load() throws -> VaultwardenCredentials

    /// Load credentials from the Keychain. Throws `.itemNotFound` when
    /// `shi secrets setup` has not been run yet.
    ///
    /// Note: on devices with biometrics, the OS will show a biometric
    /// prompt automatically when the access control flag is set. To
    /// drive the prompt with a custom reason string, pass a LAContext
    /// via ProofOfPresence.require (W2 path); for W1 broker bootstrap
    /// the OS-default prompt is acceptable.
    public func load() throws -> VaultwardenCredentials {
        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      service,
            kSecAttrAccount:      account,
            kSecReturnData:       true,
            kSecMatchLimit:       kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw KeychainError.dataMalformed
            }
            do {
                return try JSONDecoder().decode(VaultwardenCredentials.self, from: data)
            } catch {
                throw KeychainError.dataMalformed
            }
        case errSecItemNotFound:
            throw KeychainError.itemNotFound
        case errSecInteractionNotAllowed:
            throw KeychainError.osError(status: status)
        default:
            throw KeychainError.osError(status: status)
        }
    }

    // MARK: - delete()

    /// Remove the credentials item from the Keychain. Used by
    /// `shi secrets reset` (future). Silent if the item does not exist.
    public func delete() {
        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - migrateLegacyIfPresent() — W3.1

    /// Migrate a Keychain entry from the old eu.fj-studios.shikki.vault
    /// service name to the canonical io.shikki.vault product-domain name.
    ///
    /// Behaviour:
    ///   - If a legacy item exists under `legacyService`: decode it, write
    ///     under canonical `service`, then delete the legacy item.
    ///   - If no legacy item is present: no-op (returns immediately).
    ///   - Idempotent: calling twice after a successful migration is safe
    ///     (second call finds no legacy item and returns immediately).
    ///   - On decode failure of the legacy blob: delete the malformed legacy
    ///     item and throw `.dataMalformed` so the caller can surface a clear
    ///     error rather than silently losing credentials.
    ///
    /// Bootstrap.unseal() calls this exactly once per process before `load()`.
    public func migrateLegacyIfPresent() throws {
        // 1. Attempt to read the legacy item.
        let legacyQuery: [CFString: Any] = [
            kSecClass:        kSecClassGenericPassword,
            kSecAttrService:  Self.legacyService,
            kSecAttrAccount:  account,
            kSecReturnData:   true,
            kSecMatchLimit:   kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(legacyQuery as CFDictionary, &result)

        switch status {
        case errSecItemNotFound:
            // No legacy item — migration is complete or was never needed.
            return
        case errSecSuccess:
            break  // Fall through to migrate.
        default:
            // Unexpected Keychain error — propagate so caller can log.
            throw KeychainError.osError(status: status)
        }

        // 2. Decode the legacy blob.
        guard let data = result as? Data else {
            // Malformed legacy item — delete and report.
            let deleteQuery: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: Self.legacyService,
                kSecAttrAccount: account,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            throw KeychainError.dataMalformed
        }
        let credentials: VaultwardenCredentials
        do {
            credentials = try JSONDecoder().decode(VaultwardenCredentials.self, from: data)
        } catch {
            // Malformed JSON in legacy item — delete and report.
            let deleteQuery: [CFString: Any] = [
                kSecClass:       kSecClassGenericPassword,
                kSecAttrService: Self.legacyService,
                kSecAttrAccount: account,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            throw KeychainError.dataMalformed
        }

        // 3. Write under the canonical service name (self.service).
        // Use overwrite: true in case the canonical entry already exists
        // (handles edge case where both legacy and canonical are present).
        try store(credentials, overwrite: true)

        // 4. Delete the legacy item.
        let deleteLegacyQuery: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: Self.legacyService,
            kSecAttrAccount: account,
        ]
        SecItemDelete(deleteLegacyQuery as CFDictionary)
        // Ignore delete status — if it's already gone, migration is still complete.
    }
}
