// DevMode — RC-3 closure of spec
// shi-secrets-setup-install-fix-and-dev-mode-2026-06-19.
//
// Boots the broker daemon against an in-memory `InMemoryBWClient` seeded
// with `dev-*` test credentials. Bypasses Bootstrap.unseal() (no
// vaultwarden contact). Bypasses admin-action signature verification
// (refuses to start under launchd; refuses production socket paths).
//
// Safety boundaries (validated at start):
//   - socket path MUST NOT live under ~/.shikki/run/    (production)
//   - process MUST NOT have XPC_SERVICE_NAME set       (launchd-launched)
//   - process MUST NOT have SHI_SECRETS_PRODUCTION=1   (operator opt-out)
//   - seeded values MUST be prefixed `dev-`            (leak grep)
//
// Reuses existing primitives (per [[ai-spawns-new-noun-when-primitive-already-exists]]):
//   - InMemoryBWClient        (Sources/ShiSecretsBrokerd/BWClient.swift)
//   - BrokerSigningKey         (Sources/ShiSecretsKit/DI/ShikkiSecretsModule.swift)
//   - PeerCredentials path     (Sources/ShiSecretsBrokerd/PeerCred.swift)

import Crypto
import Foundation
import ShiSecretsKit

// MARK: - Errors

public enum DevModeError: Swift.Error, Equatable, Sendable, CustomStringConvertible {
    case productionSocketPathRefused(path: String)
    case launchdLaunchRefused(xpcService: String)
    case productionFlagSet
    case seedValueNotDevPrefixed(name: String)

    public var description: String {
        switch self {
        case .productionSocketPathRefused(let p):
            return "DevMode refuses production socket path: \(p) (must NOT live under ~/.shikki/run/)"
        case .launchdLaunchRefused(let xpc):
            return "DevMode refuses launchd launch (XPC_SERVICE_NAME=\(xpc) detected)"
        case .productionFlagSet:
            return "DevMode refuses when SHI_SECRETS_PRODUCTION=1 is set in env"
        case .seedValueNotDevPrefixed(let n):
            return "DevMode refuses seed value for '\(n)' — must start with 'dev-' for leak grep"
        }
    }
}

// MARK: - Configuration

public struct DevModeConfig: Sendable, Equatable {
    public var socketPath: String
    public var seedCredentials: [(name: String, value: String)]

    public init(socketPath: String, seedCredentials: [(name: String, value: String)]) {
        self.socketPath = socketPath
        self.seedCredentials = seedCredentials
    }

    public static func == (lhs: DevModeConfig, rhs: DevModeConfig) -> Bool {
        guard lhs.socketPath == rhs.socketPath,
              lhs.seedCredentials.count == rhs.seedCredentials.count else { return false }
        for (a, b) in zip(lhs.seedCredentials, rhs.seedCredentials) {
            if a.name != b.name || a.value != b.value { return false }
        }
        return true
    }

    /// Default 6-cred seed per spec NF-3.
    public static let defaultSeed: [(name: String, value: String)] = [
        ("kuma/admin-username",            "dev-admin"),
        ("kuma/admin-password",            "dev-password-do-not-use-in-prod"),
        ("kuma/mail-relay-push-token",     "dev-token-mail-relay-aaaaaaaa"),
        ("kuma/postgres-backup-push-token","dev-token-postgres-backup-bbbbbbbb"),
        ("vaultwarden/master-password",    "dev-vaultwarden-master-cccccccc"),
        ("ntfy/admin-token",               "dev-ntfy-token-dddddddd"),
    ]
}

// MARK: - Safety

public enum DevModeSafety {
    /// Production socket prefix that dev-mode refuses to bind.
    public static let productionSocketPrefix = "/.shikki/run/"

    /// Validates the socket path is NOT a production location.
    ///
    /// HIGH-8: comparisons are lowercased + URL-standardized to prevent
    /// case-sensitive bypass (e.g. /.SHIKKI/Run/).
    public static func assertSocketSafe(_ path: String) throws {
        let absolute = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
            .standardized.path.lowercased()
        let prefix = productionSocketPrefix.lowercased()
        if absolute.contains(prefix) {
            throw DevModeError.productionSocketPathRefused(path: absolute)
        }
        // Also refuse anything literally named secrets-brokerd.sock — be paranoid.
        if absolute.hasSuffix("/secrets-brokerd.sock") && absolute.contains("/.shikki/") {
            throw DevModeError.productionSocketPathRefused(path: absolute)
        }
    }

    /// Refuses to start under launchd, refuses when SHI_SECRETS_PRODUCTION=1.
    ///
    /// XPC_SERVICE_NAME detection: XCTest sets this to "0" (sentinel), real
    /// launchd-issued services use a reverse-DNS bundle id (contains a dot,
    /// e.g. `io.shikki.secrets-brokerd`). Refuse only on the reverse-DNS pattern.
    /// Note: canonical label is io.shikki.secrets-brokerd (W3 mandate 2026-06-24).
    public static func assertEnvSafe(env: [String: String]) throws {
        if let xpc = env["XPC_SERVICE_NAME"], xpc.contains(".") {
            throw DevModeError.launchdLaunchRefused(xpcService: xpc)
        }
        if env["SHI_SECRETS_PRODUCTION"] == "1" {
            throw DevModeError.productionFlagSet
        }
    }

    /// Every seeded value MUST start with "dev-" for grep-distinguishability.
    public static func assertSeedSafe(_ seed: [(name: String, value: String)]) throws {
        for (name, value) in seed {
            if !value.hasPrefix("dev-") {
                throw DevModeError.seedValueNotDevPrefixed(name: name)
            }
        }
    }
}

// MARK: - DevModeBootstrap

/// Stand-in for production `Bootstrap` when `--dev-mode` is set. Produces
/// a ready-to-use `InMemoryBWClient` (seeded + activated) + an ephemeral
/// in-process Ed25519 signing key. No vaultwarden contact.
public struct DevModeBootstrap: Sendable {
    public let config: DevModeConfig

    public init(config: DevModeConfig) {
        self.config = config
    }

    public func unseal() async throws -> (bwClient: InMemoryBWClient, signingKey: BrokerSigningKey) {
        try DevModeSafety.assertSocketSafe(config.socketPath)
        try DevModeSafety.assertEnvSafe(env: ProcessInfo.processInfo.environment)
        try DevModeSafety.assertSeedSafe(config.seedCredentials)

        let bw = InMemoryBWClient()
        await bw.activate()
        for (name, value) in config.seedCredentials {
            await bw.seedFakeEntry(name: name, fields: ["value": value])
        }

        let privateKey = Curve25519.Signing.PrivateKey()
        let signingKey = BrokerSigningKey(privateKey: privateKey)

        return (bw, signingKey)
    }
}

// MARK: - CLI arg parsing

/// Minimal arg-parsing — no swift-argument-parser dep (matches Main.swift
/// style which reads env vars).
public struct DevModeArgs: Sendable, Equatable {
    public var enabled: Bool
    public var dryRun: Bool
    public var socketPath: String?

    public static func parse(_ args: [String]) -> DevModeArgs {
        var enabled = false
        var dryRun  = false
        var socketPath: String?
        var i = 0
        while i < args.count {
            let a = args[i]
            switch a {
            case "--dev-mode":
                enabled = true
            case "--dry-run":
                dryRun = true
            case "--socket":
                if i + 1 < args.count { socketPath = args[i + 1]; i += 1 }
            default:
                if a.hasPrefix("--socket=") {
                    socketPath = String(a.dropFirst("--socket=".count))
                }
            }
            i += 1
        }
        return DevModeArgs(enabled: enabled, dryRun: dryRun, socketPath: socketPath)
    }
}

// MARK: - DryRunBootstrap

/// Boots the broker against a loopback VaultwardenClient.
/// Used ONLY in process-level E2E tests — never in production or launchd.
///
/// Reads credentials from:
///   SHIKKI_E2E_CLIENT_ID      — OAuth client_id
///   SHIKKI_E2E_CLIENT_SECRET  — OAuth client_secret
///   SHIKKI_E2E_VAULT_URL      — must be http://127.0.0.1:<port>
///
/// Does NOT call VaultwardenClient.connect() — the first token exchange
/// happens inside vault.unlock, which is required to demonstrate the
/// v0.8.0 session-seeding regression.
public enum DryRunBootstrapError: Error, CustomStringConvertible {
    case missingEnvVar(String)
    case notLoopback(String)

    public var description: String {
        switch self {
        case .missingEnvVar(let k):  return "dry-run: env var \(k) is required"
        case .notLoopback(let url):  return "dry-run: SHIKKI_E2E_VAULT_URL must be http://127.0.0.1:<port>, got \(url)"
        }
    }
}

public struct DryRunBootstrap: Sendable {
    public init() {}

    public func unseal() async throws -> (bwClient: any BWClient, signingKey: BrokerSigningKey) {
        let env = ProcessInfo.processInfo.environment
        guard let clientID = env["SHIKKI_E2E_CLIENT_ID"] else {
            throw DryRunBootstrapError.missingEnvVar("SHIKKI_E2E_CLIENT_ID")
        }
        guard let clientSecret = env["SHIKKI_E2E_CLIENT_SECRET"] else {
            throw DryRunBootstrapError.missingEnvVar("SHIKKI_E2E_CLIENT_SECRET")
        }
        guard let vaultURLStr = env["SHIKKI_E2E_VAULT_URL"] else {
            throw DryRunBootstrapError.missingEnvVar("SHIKKI_E2E_VAULT_URL")
        }
        guard let url = URL(string: vaultURLStr),
              url.scheme == "http",
              (url.host == "127.0.0.1" || url.host == "localhost") else {
            throw DryRunBootstrapError.notLoopback(vaultURLStr)
        }
        let creds = VaultwardenCredentials(
            clientID: clientID,
            clientSecret: clientSecret,
            serverURL: url
        )
        let vaultClient = try VaultwardenClient(
            credentials: creds,
            configYmlVaultServer: vaultURLStr,
            allowHTTPLoopback: true
        )
        let bw = ProductionBWClient()
        await bw.wire(client: vaultClient)

        // spec 7c2e9a14 W0: file-backed custody for E2E tests.
        // SHIKKI_E2E_CUSTODY_FILE — path to the vault key file.
        // If present, wire the custody and try to restore a persisted key
        // so that a restarted broker in a multi-launch test scenario
        // can skip the master-password prompt (BR-04).
        if let custodyPath = env["SHIKKI_E2E_CUSTODY_FILE"], !custodyPath.isEmpty {
            let custody = FileBackedVaultKeyCustody(
                fileURL: URL(fileURLWithPath: custodyPath)
            )
            await bw.wireCustody(custody)
            // Non-fatal: if no key file exists yet, restorePersistedKey is a no-op.
            await bw.restorePersistedKey()
        }

        let signingKey = BrokerSigningKey(privateKey: Curve25519.Signing.PrivateKey())
        return (bw, signingKey)
    }
}
