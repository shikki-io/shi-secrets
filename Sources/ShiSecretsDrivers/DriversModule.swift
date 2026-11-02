import Foundation
import ShiSecretsKit

// ShiSecretsDrivers — per-vendor SecretRotationDriver conformances.
//
// Wave 4 ships three drivers (v1 set, locked 2026-04-20):
//   - DriverOVH         — OVH application-key rotation (sandbox + production)
//   - DriverBrevo       — Brevo transactional-email key rotation
//   - DriverGitHub      — GitHub fine-grained PAT rotation with rate-limit retry
//
// Wave 5 (2026-05-21) adds:
//   - DriverWoodpecker  — Woodpecker CI scoped token management
//     Replaces Gitea OAuth in the Woodpecker + Mattermost deploy spec
//     per operator decision 2026-05-21. Mints scoped CI tokens (TTL ≤ 3600s);
//     admin token resolved from BWClient vault (never plaintext config).
//
// The `SecretRotationDriver` protocol itself lives in ShiSecretsKit
// (declared early in Wave 3 so the RotationEngine could call into it).
// Wave 4 adds the vendor conformances in this target and exposes a
// `allV1Drivers(transport:)` helper so the DI registration in Wave 4
// T52 (BrokerDaemon) can register them in a single shot.

/// Minimal HTTP transport abstraction the drivers call through. Tests
/// inject a fake; production wires a real URLSession-backed implementation.
/// All v1 + Wave 5 drivers share the same surface so the anomaly-path
/// contract test (T46) can parameterize across them.
public protocol DriverHTTPTransport: Sendable {
    func send(_ request: DriverHTTPRequest) async throws -> DriverHTTPResponse
}

public struct DriverHTTPRequest: Sendable, Equatable {
    public let method: String
    public let url: String
    public let headers: [String: String]
    public let body: Data?

    public init(method: String, url: String, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

public struct DriverHTTPResponse: Sendable, Equatable {
    public let status: Int
    public let headers: [String: String]
    public let body: Data

    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

public enum DriverHTTPError: Swift.Error, Sendable, Equatable {
    case transportFailed(message: String)
}

/// Returns every v1-set driver wired against the supplied transport. A
/// BWClient hook is optional in Wave 4 (drivers write-back to vault via
/// BWClient in production; tests pass `nil` and assert the mutation
/// layer received the expected calls through a recording fake).
///
/// DriverWoodpecker is included from Wave 5 onward; its serverURL
/// defaults to the production endpoint and can be overridden at the
/// BrokerDaemon construction site via `config_resolved` (not magic string).
public func allV1Drivers(
    transport: any DriverHTTPTransport,
    bwClient: BWClientWriteBack? = nil
) -> [any SecretRotationDriver] {
    [
        DriverOVH(mode: .sandbox, transport: transport, bwClient: bwClient),
        DriverBrevo(transport: transport, bwClient: bwClient),
        DriverGitHub(transport: transport, bwClient: bwClient),
        DriverWoodpecker(transport: transport, bwClient: bwClient),
    ]
}

/// Minimal read + write-back surface drivers need on the BWClient. Declared
/// here so ShiSecretsBrokerd (which owns the real BWClient) can conform
/// and the drivers target does not have to link against the executable.
public protocol BWClientWriteBack: Sendable {
    /// Read a vault entry's fields. Returns `[:]` when the entry is absent.
    func get(name: String) async throws -> [String: String]
    func update(name: String, fields: [String: String]) async throws
}
