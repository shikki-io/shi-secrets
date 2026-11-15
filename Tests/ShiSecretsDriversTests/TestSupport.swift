import Foundation
@testable import ShiSecretsDrivers
import ShiSecretsKit

// Shared test helpers used across the driver suites. A recording HTTP
// transport + a recording BWClient write-back are enough to drive every
// driver's happy + failure + anomaly paths without touching the network.

/// A thread-safe recording transport. Configure `responses` with the
/// (host, path) pairs you want to match; every `send` appends the
/// exercised request to `requests`.
public actor RecordingTransport: DriverHTTPTransport {

    public struct Match: Sendable, Equatable {
        public let method: String
        public let urlContains: String
        public init(method: String, urlContains: String) {
            self.method = method
            self.urlContains = urlContains
        }
    }

    private var _requests: [DriverHTTPRequest] = []
    private var _responses: [(Match, DriverHTTPResponse)] = []
    /// Default returned when nothing else matches; useful for "happy path"
    /// tests that don't want to script every request.
    private var _defaultResponse: DriverHTTPResponse = DriverHTTPResponse(status: 200)

    public init() {}

    public func setDefaultResponse(_ response: DriverHTTPResponse) {
        _defaultResponse = response
    }

    public func queue(match: Match, response: DriverHTTPResponse) {
        _responses.append((match, response))
    }

    public func requests() -> [DriverHTTPRequest] {
        _requests
    }

    nonisolated public func send(_ request: DriverHTTPRequest) async throws -> DriverHTTPResponse {
        await recordAndMatch(request)
    }

    private func recordAndMatch(_ request: DriverHTTPRequest) -> DriverHTTPResponse {
        _requests.append(request)
        for (i, (match, response)) in _responses.enumerated() {
            if match.method == request.method && request.url.contains(match.urlContains) {
                _responses.remove(at: i)
                return response
            }
        }
        return _defaultResponse
    }
}

/// Recording BWClient read + write-back. Supports seeded `get` entries via
/// `seedGet(name:fields:)` and appends every `update` call to `writes`.
/// Tests assert post-conditions on both.
public actor RecordingBWClient: BWClientWriteBack {

    private var _writes: [(name: String, fields: [String: String])] = []
    private var _vault: [String: [String: String]] = [:]

    public init() {}

    /// Pre-populate a vault entry so drivers can resolve admin credentials.
    public func seedGet(name: String, fields: [String: String]) {
        _vault[name] = fields
    }

    nonisolated public func get(name: String) async throws -> [String: String] {
        await fetchVaultEntry(name: name)
    }

    private func fetchVaultEntry(name: String) -> [String: String] {
        _vault[name] ?? [:]
    }

    nonisolated public func update(name: String, fields: [String: String]) async throws {
        await append(name: name, fields: fields)
    }

    private func append(name: String, fields: [String: String]) {
        _writes.append((name, fields))
    }

    public func writes() -> [(name: String, fields: [String: String])] {
        _writes
    }
}

/// A VaultEntryRef for the supplied vendor scope (e.g. `ovh/AK_*`).
public func makeEntry(vendor: String, name: String = "test-secret") -> VaultEntryRef {
    VaultEntryRef(
        name: name,
        scope: "\(vendor)/\(name)",
        tier: .warm,
        usageState: .warm,
        lastRotated: Date(timeIntervalSince1970: 1_000_000),
        rotationDue: Date(timeIntervalSince1970: 2_000_000)
    )
}
