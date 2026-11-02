import Foundation

// KeychainStore — the seam between AppleKeychainCustody and the OS Keychain.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W1 (review of shi-secrets#53).
//
// One protocol, two implementations, resolved through the DI container:
//   - `SystemKeychainStore` (production, Security framework) — registered by
//     `ShiSecretsModule` on Apple platforms.
//   - `InMemoryKeychainStore` (tests) — registered by the test, so a test can
//     never reach the real Keychain.

public protocol KeychainStore: Sendable {
    /// nil when the data-protection Keychain is usable; otherwise the reason
    /// custody must stay memory-only (typically a missing entitlement).
    func memoryOnlyReason(service: String, accessGroup: String?) -> String?

    /// The stored bytes, or nil when no item exists (or the entitlement is gone).
    /// Throws on unexpected Keychain errors.
    func read(service: String, account: String, accessGroup: String?) throws -> Data?

    /// Insert or replace the item.
    func write(_ data: Data, service: String, account: String, accessGroup: String?) throws

    /// Delete the item. Never throws: a missing item or entitlement is acceptable.
    func delete(service: String, account: String, accessGroup: String?)
}
