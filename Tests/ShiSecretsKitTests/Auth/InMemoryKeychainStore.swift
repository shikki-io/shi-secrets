import Foundation
@testable import ShiSecretsKit

/// Test implementation of the `KeychainStore` seam — a dictionary, never the
/// Security framework. Registered on a test's own `DIContainer`.
final class InMemoryKeychainStore: KeychainStore, @unchecked Sendable {

    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private let reason: String?

    init(memoryOnlyReason: String? = nil) {
        self.reason = memoryOnlyReason
    }

    private func key(_ service: String, _ account: String, _ group: String?) -> String {
        [service, account, group ?? ""].joined(separator: "\u{1F}")
    }

    func memoryOnlyReason(service: String, accessGroup: String?) -> String? { reason }

    func read(service: String, account: String, accessGroup: String?) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return items[key(service, account, accessGroup)]
    }

    func write(_ data: Data, service: String, account: String, accessGroup: String?) throws {
        lock.lock(); defer { lock.unlock() }
        items[key(service, account, accessGroup)] = data
    }

    func delete(service: String, account: String, accessGroup: String?) {
        lock.lock(); defer { lock.unlock() }
        items[key(service, account, accessGroup)] = nil
    }
}
