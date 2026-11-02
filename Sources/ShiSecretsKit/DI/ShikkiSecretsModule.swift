import Crypto
import Foundation

// ShiSecretsModule — DI wiring for the secrets-broker feature (Task 41).
//
// Registers the core singletons in Architecture §3:
//   TokenRegistry, AuditWriter, SeamsWriter, ScopeValidator,
//   ManifestVerifier, ManifestStore, DriverRegistry, RotationEngine,
//   TokenMinter, TokenVerifier, plus the two guarded resolvers
//   (BrokerSigningKey, PinnedKeys) that refuse to resolve before
//   Bootstrap unseal completes (BR-I-04).
//
// Wave 3 targets shape + unseal gating — full BrokerDaemon wiring arrives
// with Bootstrap + UnixSocketServer in Wave 4. Registrations for
// daemon-specific types (BrokerDaemon, MCPBridge, UnixSocketServer) land
// there; this module confines itself to the in-process kit targets.

/// Opaque wrapper around the broker's Ed25519 signing private key.
/// Resolution is sealed at module install and unsealed only by Bootstrap
/// (Wave 4). This is the type-system half of BR-I-04.
public struct BrokerSigningKey: Sendable {
    public let privateKey: Curve25519.Signing.PrivateKey
    public init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }
}

/// Pinned public keys (manifest signer + peer pubkey for broker-side
/// verification + admin-action signer). Sealed until Bootstrap runs.
///
/// Item #9: `daimyoAdmin` pins the Ed25519 public key that verifies
/// passkey-signed admin actions (currently: `revokeAllBots`). The key
/// bytes MAY match `daimyoManifest` (same trust root, same ceremony),
/// but the signed `domain` field keeps the two classes separated so a
/// manifest signature cannot be replayed as an admin action.
public struct PinnedKeys: Sendable {
    public let daimyoManifest: Curve25519.Signing.PublicKey
    public let brokerPublic: Curve25519.Signing.PublicKey
    public let daimyoAdmin: Curve25519.Signing.PublicKey
    public init(
        daimyoManifest: Curve25519.Signing.PublicKey,
        brokerPublic: Curve25519.Signing.PublicKey,
        daimyoAdmin: Curve25519.Signing.PublicKey
    ) {
        self.daimyoManifest = daimyoManifest
        self.brokerPublic = brokerPublic
        self.daimyoAdmin = daimyoAdmin
    }
}

/// Allowlist supplied to ScopeValidator. Wrapped so the container can
/// register it as a distinct type without conflicting with plain String
/// arrays elsewhere in the app.
public struct EntitlementAllowlist: Sendable {
    public let globs: [String]
    public init(globs: [String]) {
        self.globs = globs
    }
}

public struct ShiSecretsModule: DIModule {

    public init() {}

    public func register(into c: DIContainer) {
        // --- Audit + seams (no deps) ---
        c.registerLazy(AuditWriter.self) { AuditWriter() }
        c.registerLazy(SeamsWriter.self) { SeamsWriter() }
        c.registerLazy(TokenRegistry.self) { TokenRegistry() }

        // --- NEW-M2: InMemoryCache wired to TokenRegistry for per-JTI revocation.
        // Uses the convenience init(tokenRegistry:) so isRevoked closure is auto-wired.
        // Without this registration, callers that construct InMemoryCache() directly
        // get isRevoked=nil (revocation silently disabled) — CRIT-3 gap closed here.
        c.registerLazy(InMemoryCache.self) {
            guard let registry = c.tryResolve(TokenRegistry.self) else {
                preconditionFailure("TokenRegistry not registered before InMemoryCache — NEW-M2 wiring requires TokenRegistry first")
            }
            return InMemoryCache(tokenRegistry: registry)
        }

        // --- ScopeValidator needs the allowlist ---
        c.registerLazy(ScopeValidator.self) {
            let allow = c.tryResolve(EntitlementAllowlist.self) ?? EntitlementAllowlist(globs: [])
            // `ScopeValidator.init` can throw on malformed globs. Review
            // finding #4 — replace the `try!` fallback landmine with a
            // manually-constructed empty-allowlist value. The empty globs
            // list is statically glob-safe (no characters to scan) so
            // this constructor is unreachable-in-practice for the throw
            // and no `try!` is needed.
            if let validator = try? ScopeValidator(allowlist: allow.globs) {
                return validator
            }
            // Fallback: empty allowlist is provably glob-safe (no chars
            // to scan) — construct via the same initializer under `try?`
            // so any future protocol change surfaces as nil here rather
            // than a runtime trap.
            guard let empty = try? ScopeValidator(allowlist: []) else {
                // Unreachable — empty allowlist never throws. Precondition
                // captures the contract if the initializer ever gains a
                // new check.
                preconditionFailure("ScopeValidator(allowlist: []) cannot throw — invariant broken")
            }
            return empty
        }

        // --- Driver registry (empty in Wave 3; Wave 4 registers vendors) ---
        c.registerLazy(DriverRegistry.self) { DriverRegistry(drivers: []) }

        // --- RotationEngine wires clock/drivers/audit/seams/registry ---
        // Review finding U6 — fall through to `preconditionFailure` on
        // missing registration. A silent `?? fresh()` would hand the
        // engine a brand-new in-memory writer distinct from the one the
        // rest of the broker uses; losing that invariant means audit
        // rows and tokens would land in orphaned actors. Fail loud
        // forces explicit registration at boot.
        c.registerLazy(RotationEngine.self) {
            guard let audit = c.tryResolve(AuditWriter.self) else {
                preconditionFailure("AuditWriter not registered in DIContainer before RotationEngine")
            }
            guard let seams = c.tryResolve(SeamsWriter.self) else {
                preconditionFailure("SeamsWriter not registered in DIContainer before RotationEngine")
            }
            guard let registry = c.tryResolve(TokenRegistry.self) else {
                preconditionFailure("TokenRegistry not registered in DIContainer before RotationEngine")
            }
            guard let drivers = c.tryResolve(DriverRegistry.self) else {
                preconditionFailure("DriverRegistry not registered in DIContainer before RotationEngine")
            }
            return RotationEngine(
                drivers: drivers,
                audit: audit,
                seams: seams,
                registry: registry
            )
        }

        // --- AdminActionVerifier (item #9) — resolved lazily from
        // `PinnedKeys.daimyoAdmin`. Fail-loud if `PinnedKeys` was not
        // registered before resolution: a broker wired without the
        // admin verifier cannot enforce BR-F-08 and must refuse to
        // run rather than silently accept every --signed-envelope.
        c.registerLazy(AdminActionVerifier.self) {
            guard let keys = c.tryResolve(PinnedKeys.self) else {
                preconditionFailure("PinnedKeys not registered in DIContainer before AdminActionVerifier — item #9 requires daimyoAdmin pubkey")
            }
            return AdminActionVerifier(pinnedPublicKey: keys.daimyoAdmin)
        }

        // --- Keychain seam (production = Security framework; tests register an
        // in-memory store on their own container, so they never reach the real one).
        #if canImport(Security) && (os(macOS) || os(iOS) || os(tvOS) || os(watchOS))
        c.registerLazy((any KeychainStore).self) { SystemKeychainStore() }
        #endif

        // --- Seal the key-bearing resolvers until Bootstrap unseals them.
        c.markSealed(BrokerSigningKey.self)
        c.markSealed(PinnedKeys.self)
    }
}
