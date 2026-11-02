import Foundation
import ShiSecretsDrivers
import ShiSecretsKit

// BWClient — the broker's vault client surface (BR-F-07).
//
// Wave 1 (shi-secrets W1 — 2026-05-21):
//   The original bw CLI subprocess pattern + BW_SESSION env var has been
//   gutted. The `ProcessLauncher` / `ProcessHandle` protocols and the
//   `InMemoryBWClient.start(session:)` method that passed BW_SESSION as an
//   environment variable are REMOVED. The broker no longer spawns any
//   child process to access vault data.
//
//   `ProductionBWClient` is updated to delegate `get(name:)` to
//   `VaultwardenClient` (actor, URLSession, Keychain-backed credentials).
//   `InMemoryBWClient` keeps the in-memory fake vault for unit tests but
//   drops the subprocess launch path entirely.
//
// Review finding #2 (PR #53) — protocol split still applies:
//   - `BWClient` protocol — unchanged public surface
//   - `InMemoryBWClient` — no subprocess, fake vault only (tests)
//   - `ProductionBWClient` — now delegates to VaultwardenClient (W1)
//
// Wave 3 (shi-secrets W3 — 2026-05-26):
//   Write path wired. Protocol extended with:
//   - `set(name:value:)`    — create-or-replace a secret in the vault
//   - `delete(name:)`       — remove a secret from the vault
//   - `list()`              — list all secret names in the vault
//
//   Vaultwarden accepts plaintext for API-key (client_credentials) clients.
//   No client-side encryption required. Decision: @db shikki.secrets.W3-encryption-decision.
//
// Public surface on the protocol:
//   - `get(name:)`          — reads a vault entry as `[field → value]`
//   - `set(name:value:)`    — create-or-replace a vault entry (W3)
//   - `delete(name:)`       — delete a vault entry (W3)
//   - `list()`              — list all vault entry names (W3)
//   - `update(name:fields:)` — driver write-back (BWClientWriteBack compat)
//   - `invalidateSession()` — invalidates the session; cuts new minting
//   - `isSessionValid`      — gate checked by BrokerDaemon before minting

// ProcessLauncher / ProcessHandle protocols REMOVED in W1.
// The bw CLI is no longer in the broker's trust boundary.
// See: features/shi-secrets-session-management-2026-05-21.md §Wave 1

/// Errors surfaced by a BWClient implementation.
public enum BWClientError: Swift.Error, Sendable, Equatable {
    case sessionInvalidated
    case notStarted
    /// `secret.delete` named an entry the vault doesn't hold.
    case notFound(name: String)
    /// Kept for any stale call-sites referencing the old W1/W2 stub path.
    /// No longer thrown by ProductionBWClient as of W3.
    case notImplementedV1_1(call: String)
}

// MARK: - Protocol surface (review finding #2)

/// Minimal client surface the BrokerDaemon holds. Conforms to
/// `BWClientWriteBack` (drivers dep) so vendor drivers can re-use the
/// same impl without re-importing anything Brokerd-specific.
///
/// Review finding U16 — the protocol declares `update` as plain
/// `async throws` so actor conformance is direct (no `nonisolated`
/// wrapper/dispatch hop). Implementations may mark their conformance
/// `nonisolated` only if the body is genuinely actor-agnostic.
public protocol BWClient: BWClientWriteBack, Sendable {
    func get(name: String) async throws -> [String: String]
    /// W3: Create or replace a vault entry. Plaintext via API-key path.
    func set(name: String, value: String) async throws
    /// W3: Delete a vault entry by name. No-op if not found.
    func delete(name: String) async throws
    /// W3: List all vault entry names.
    func list() async throws -> [String]
    func invalidateSession() async
    var isSessionValid: Bool { get async }
    /// Review finding U5 — monotonic counter bumped on every
    /// `invalidateSession` call. BrokerDaemon captures it before
    /// signing and re-checks after, closing the mint-vs-invalidate race.
    var sessionEpoch: UInt64 { get async }

    // MARK: - Vault unlock surface (feat/vault-unlock-2026-11-01)
    //
    // The access token authenticates the CALL; the master password unlocks
    // the DATA. Both must be present for secret.{get,set,list,delete} to
    // return plaintext. A caller that has a valid token but has not unlocked
    // will receive VaultUnlockError.locked from those methods.

    /// Derive the vault session key from the master password.
    /// Never stores the password; the derived SymmetricKeyPair lives only
    /// in memory for the life of the broker process.
    /// Throws VaultUnlockError on wrong password or missing account key.
    func unlock(masterPassword: String, email: String) async throws

    /// True once unlock(masterPassword:email:) has succeeded and the
    /// derived key is held in memory.
    var isVaultUnlocked: Bool { get async }

    // MARK: - Vault lock (spec 7c2e9a14 W0, BR-06)

    /// Drop the vault key from memory AND from the custody store (BR-06).
    /// After this call, isVaultUnlocked is false and the operator must
    /// re-type the master password to re-unlock.
    func lock() async throws
}

// MARK: - InMemoryBWClient (fake / default DEBUG + test binding)

/// InMemoryBWClient — actor so get/update calls serialize cleanly with
/// invalidateSession. Intended for tests and DEBUG builds.
///
/// W1 change: the bw CLI subprocess launch path (`start(session:)`) has
/// been REMOVED. The fake vault is driven directly by `seedFakeEntry` —
/// no subprocess, no BW_SESSION env var at any point.
///
/// A seam-test asserts the production binary resolves
/// `ProductionBWClient` instead (see `BWClientProtocolConformanceTests`).
public actor InMemoryBWClient: BWClient {

    /// In-memory vault driven directly by tests / debug code.
    private var fakeVault: [String: [String: String]] = [:]
    private var sessionValid: Bool = false
    /// Review finding U5 — monotonic counter, bumped on every
    /// `invalidateSession`. BrokerDaemon.handleRequest captures the
    /// value before mint and re-checks after so a concurrent
    /// invalidateSession cannot slip through while we're signing.
    private var _sessionEpoch: UInt64 = 0

    public init() {}

    /// Activate the fake session. Call before test assertions that
    /// exercise the mint path. No subprocess spawned.
    public func activate() {
        sessionValid = true
    }

    /// Reads a vault entry by name from the in-memory fake vault.
    public func get(name: String) async throws -> [String: String] {
        guard sessionValid else { throw BWClientError.sessionInvalidated }
        return fakeVault[name] ?? [:]
    }

    /// W3: Create or replace a vault entry in the in-memory fake vault.
    public func set(name: String, value: String) async throws {
        guard sessionValid else { throw BWClientError.sessionInvalidated }
        fakeVault[name] = ["value": value]
    }

    /// W3: Delete a vault entry from the in-memory fake vault.
    public func delete(name: String) async throws {
        guard sessionValid else { throw BWClientError.sessionInvalidated }
        fakeVault.removeValue(forKey: name)
    }

    /// W3: List all vault entry names in the in-memory fake vault.
    public func list() async throws -> [String] {
        guard sessionValid else { throw BWClientError.sessionInvalidated }
        return Array(fakeVault.keys)
    }

    /// Writes the supplied fields to the named entry in the fake vault.
    /// Review finding U16 — direct actor conformance.
    public func update(name: String, fields: [String: String]) async throws {
        guard sessionValid else { throw BWClientError.sessionInvalidated }
        var merged = fakeVault[name] ?? [:]
        for (k, v) in fields { merged[k] = v }
        fakeVault[name] = merged
    }

    /// Invalidates the fake session. BR-F-07: cuts new issuance.
    /// Review finding U5 — bumps the session epoch.
    public func invalidateSession() async {
        sessionValid = false
        _sessionEpoch &+= 1
    }

    /// Monotonic counter for BR-F-07 race closure (review finding U5).
    public var sessionEpoch: UInt64 { _sessionEpoch }

    /// Test helper — predeclares an entry in the in-memory fake vault.
    public func seedFakeEntry(name: String, fields: [String: String]) {
        fakeVault[name] = fields
    }

    public var isSessionValid: Bool { sessionValid }

    // MARK: - Vault unlock (feat/vault-unlock-2026-11-01)
    //
    // In-memory fake: any non-empty password succeeds. Tests that need a
    // wrong-password failure should pass an empty string, which is refused.
    // The real password is never present in any test; only fake KDF fixture
    // values are exercised.

    private var _vaultUnlocked: Bool = false

    /// Fake unlock — accepts any non-empty password. An empty password
    /// simulates a wrong-password failure (VaultUnlockError.locked).
    public func unlock(masterPassword: String, email: String) async throws {
        guard !masterPassword.isEmpty else {
            throw VaultUnlockError.locked
        }
        _vaultUnlocked = true
    }

    /// Whether the in-memory vault is unlocked.
    public var isVaultUnlocked: Bool { _vaultUnlocked }

    /// BR-06: drop the vault key. In-memory only (no custody in test double).
    public func lock() async throws {
        _vaultUnlocked = false
    }
}

// MARK: - ProductionBWClient (W3 — full read+write VaultwardenClient-backed)

/// ProductionBWClient — W3 implementation. All CRUD operations delegate to
/// `VaultwardenClient` (Swift-native HTTP actor; no bw CLI subprocess;
/// no BW_SESSION env var). Wired by Bootstrap.swift at broker start.
///
/// W3 write path:
///   `set(name:value:)` — upsert a SecureNote cipher (plaintext via API-key).
///   `delete(name:)`    — find by name, then DELETE /api/ciphers/{id}.
///   `list()`           — returns names from GET /api/ciphers.
///
/// Vaultwarden accepts plaintext for client_credentials grant clients. No
/// client-side master-key derivation required. Decision documented at
/// @db: shikki.secrets.W3-encryption-decision.
public actor ProductionBWClient: BWClient {

    private var _sessionEpoch: UInt64 = 0
    private var _sessionValid: Bool = false

    /// The VaultwardenClient actor. Set by Bootstrap.wire(client:) after
    /// connect() succeeds so the epoch/session-valid gate is correct.
    private var vaultClient: VaultwardenClient?

    public init() {}

    /// Wire the authenticated VaultwardenClient into this BWClient.
    /// Called by Bootstrap after VaultwardenClient.connect() succeeds.
    public func wire(client: VaultwardenClient) {
        vaultClient = client
        _sessionValid = true
    }

    /// Fetch a vault entry by name (item display name).
    /// Delegates to VaultwardenClient.listSecrets() + fetchSecret(id:).
    public func get(name: String) async throws -> [String: String] {
        guard _sessionValid, let vc = vaultClient else {
            throw BWClientError.sessionInvalidated
        }
        // Find the cipher id by name.
        let list = try await vc.listSecrets()
        guard let entry = list.first(where: { $0["name"] == name }),
              let id = entry["id"] else {
            return [:]
        }
        return try await vc.fetchSecret(id: id)
    }

    /// W3: Create or replace a vault entry. Uses upsert semantics:
    /// if a cipher with the same name already exists, delete it first.
    public func set(name: String, value: String) async throws {
        guard _sessionValid, let vc = vaultClient else {
            throw BWClientError.sessionInvalidated
        }
        // Upsert: delete existing cipher with the same name if present.
        let existingList = try await vc.listSecrets()
        if let existing = existingList.first(where: { $0["name"] == name }),
           let id = existing["id"] {
            try await vc.deleteCipher(id: id)
        }
        _ = try await vc.createCipher(name: name, value: value)
    }

    /// W3: Delete a vault entry by name. No-op if not found.
    public func delete(name: String) async throws {
        guard _sessionValid, let vc = vaultClient else {
            throw BWClientError.sessionInvalidated
        }
        let list = try await vc.listSecrets()
        guard let entry = list.first(where: { $0["name"] == name }),
              let id = entry["id"] else {
            throw BWClientError.notFound(name: name)
        }
        try await vc.deleteCipher(id: id)
    }

    /// W3: List all vault entry names.
    public func list() async throws -> [String] {
        guard _sessionValid, let vc = vaultClient else {
            throw BWClientError.sessionInvalidated
        }
        let items = try await vc.listSecrets()
        return items.compactMap { $0["name"] }
    }

    /// Driver write-back via BWClientWriteBack. Uses `set` semantics:
    /// writes the "value" field if present, otherwise falls back to the
    /// first field value.
    public func update(name: String, fields: [String: String]) async throws {
        let value = fields["value"] ?? fields.values.first ?? ""
        try await set(name: name, value: value)
    }

    /// Invalidates the session. Bumps epoch for BR-F-07 race closure.
    public func invalidateSession() async {
        _sessionValid = false
        vaultClient = nil
        _sessionEpoch &+= 1
    }

    public var isSessionValid: Bool { _sessionValid }

    /// Monotonically bumped by `invalidateSession` (review finding U5).
    public var sessionEpoch: UInt64 { _sessionEpoch }

    // MARK: - Vault unlock / lock (feat/vault-unlock + spec 7c2e9a14 W0)

    /// Derive the vault session key. Delegates to VaultwardenClient.unlock.
    /// Requires that wire(client:) has already been called (i.e. the broker
    /// has an authenticated session). A wrong master password fails as
    /// macMismatch — the server does not know the password.
    public func unlock(masterPassword: String, email: String) async throws {
        guard _sessionValid, let vc = vaultClient else {
            throw BWClientError.sessionInvalidated
        }
        try await vc.unlock(masterPassword: masterPassword, email: email)
    }

    /// True once unlock succeeded and the derived key is in memory.
    public var isVaultUnlocked: Bool {
        get async {
            guard let vc = vaultClient else { return false }
            return await vc.isVaultUnlocked
        }
    }

    /// BR-06: drop the vault key from memory AND from the custody store.
    public func lock() async throws {
        guard let vc = vaultClient else { return }
        await vc.lockVault()
    }

    // MARK: - Custody wiring (spec 7c2e9a14 W0)

    /// Inject a custody backend into the underlying VaultwardenClient.
    /// Must be called before the first unlock() for persistence to take effect.
    public func wireCustody(_ custody: any VaultKeyCustody) async {
        guard let vc = vaultClient else { return }
        await vc.wireCustody(custody)
    }

    /// Try to restore the vault key from the custody backend without the
    /// master password (BR-04). No-op if no key is stored. Non-fatal on error.
    public func restorePersistedKey() async {
        guard let vc = vaultClient else { return }
        try? await vc.restoreFromCustody()
    }
}
