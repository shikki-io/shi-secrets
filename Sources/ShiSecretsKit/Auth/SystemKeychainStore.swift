import Foundation

#if canImport(Security) && (os(macOS) || os(iOS) || os(tvOS) || os(watchOS))
import Security

/// Production `KeychainStore` — the only type in the kit that calls the Security
/// framework for the vault key. BR-02: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
/// + kSecUseDataProtectionKeychain, so the key is only readable while unlocked
/// and never leaves the device.
public struct SystemKeychainStore: KeychainStore {

    public init() {}

    private func baseQuery(service: String, account: String, accessGroup: String?) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass:                     kSecClassGenericPassword,
            kSecAttrService:               service,
            kSecAttrAccount:               account,
            kSecUseDataProtectionKeychain: true,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup] = group }
        return query
    }

    /// Synchronous probe: add (then delete) a throwaway data-protection item.
    public func memoryOnlyReason(service: String, accessGroup: String?) -> String? {
        let probeAccount = "avail-probe-\(UUID().uuidString)"
        var query = baseQuery(service: service, account: probeAccount, accessGroup: accessGroup)
        query[kSecValueData] = Data([0x00])
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecMissingEntitlement {
            return "keychain-access-groups not present — team-signed binary; add entitlement + .app wrapper to enable persistence"
        }
        if status == errSecSuccess {
            delete(service: service, account: probeAccount, accessGroup: accessGroup)
        }
        return nil
    }

    public func read(service: String, account: String, accessGroup: String?) throws -> Data? {
        var query = baseQuery(service: service, account: account, accessGroup: accessGroup)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        // Not found, or the entitlement was revoked after the probe: degrade to nil.
        if status == errSecItemNotFound || status == errSecMissingEntitlement { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultKeyCustodyError.malformedData(expectedBytes: 64, gotBytes: 0)
        }
        return data
    }

    public func write(_ data: Data, service: String, account: String, accessGroup: String?) throws {
        let query = baseQuery(service: service, account: account, accessGroup: accessGroup)
        let updateAttrs: [CFString: Any] = [
            kSecValueData:      data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        if SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary) == errSecSuccess { return }
        var addQuery = query
        addQuery[kSecValueData]      = data
        addQuery[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        // errSecMissingEntitlement after the probe: silently degrade.
        if status == errSecSuccess || status == errSecMissingEntitlement { return }
        throw VaultKeyCustodyError.dataProtectionUnavailable
    }

    public func delete(service: String, account: String, accessGroup: String?) {
        _ = SecItemDelete(baseQuery(service: service, account: account, accessGroup: accessGroup) as CFDictionary)
    }
}

#endif
