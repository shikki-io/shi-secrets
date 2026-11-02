import Foundation
import ShiSecretsKit

// BrokerWireDispatch — routes JSON-RPC `WireRequest` frames to the
// corresponding `BrokerDaemon` handler.
//
// Phase 0.3c (BR-G-04 decoder half) of features/shikkisecrets-broker-completion.md.
//
// Wire shape:
//   WireRequest (NDJSON) → method-named arm → BrokerRequest →
//     BrokerDaemon.handleRequest → BrokerResponse → toWireResponse(id:)
//
// W3 (2026-05-26): secret.{set,list,delete} wired to BWClient.{set,list,delete}.
// The W3 write path uses Vaultwarden's API-key plaintext path (no client-side
// encryption — see decision @db shikki.secrets.W3-encryption-decision).
//
// Lives in ShiSecretsBrokerd because it needs `BrokerDaemon` +
// `MCPBridge` types that are private to the daemon target.

public actor BrokerWireDispatcher {

    private let daemon: BrokerDaemon
    private let bridge: MCPBridge
    /// CRIT-2: the UID that owns this broker instance. Mutations (set/list/delete)
    /// are only permitted when peerUid == ownerUid.
    private let ownerUid: UInt32

    public init(daemon: BrokerDaemon, bridge: MCPBridge, ownerUid: UInt32 = UInt32(getuid())) {
        self.daemon = daemon
        self.bridge = bridge
        self.ownerUid = ownerUid
    }

    /// Decode a `WireRequest` and route it to the matching handler. The
    /// `peerUid` is captured from `SO_PEERCRED` at accept(2) time
    /// and carried into the audit row and auth check.
    public func dispatch(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        switch request.method {

        case "secret.get":
            return await dispatchSecretGet(request, peerUid: peerUid)

        case "secret.set":
            return await dispatchSecretSet(request, peerUid: peerUid)

        case "secret.list":
            return await dispatchSecretList(request, peerUid: peerUid)

        case "secret.delete":
            return await dispatchSecretDelete(request, peerUid: peerUid)

        // feat/vault-unlock-2026-11-01 — vault key lifecycle surface.
        // vault.unlock: typed once by the operator; derives the SymmetricKeyPair
        //   and holds it in memory only. Never logged, never stored.
        // vault.status: reports { "locked": Bool } — safe to call unauthenticated
        //   (no secret material is present in the response).
        case "vault.unlock":
            return await dispatchVaultUnlock(request, peerUid: peerUid)

        case "vault.status":
            return await dispatchVaultStatus(request, peerUid: peerUid)

        // spec 7c2e9a14 W0 — vault.lock drops key from memory + custody (BR-06).
        case "vault.lock":
            return await dispatchVaultLock(request, peerUid: peerUid)

        // spec 7c2e9a14 W4 — vault.reencrypt lists plaintext entries, returns count (BR-10).
        case "vault.reencrypt":
            return await dispatchVaultReencrypt(request, peerUid: peerUid)

        // spec 7c2e9a14 W2 — test-only simulation verbs (dev/dry-run mode).
        // These are NEVER accessible in production (denied when simulationLockSource is nil).
        case "vault.simulate.device_lock":
            return await dispatchSimulateDeviceLock(request, peerUid: peerUid)

        case "vault.simulate.device_unlock":
            return await dispatchSimulateDeviceUnlock(request, peerUid: peerUid)

        // Phase 0.5+: token.{revoke, revokeAllBots, revokeAllBotsSigned}.
        // Phase 0.6+: audit.{blastRadius, recent, seams}.
        default:
            return WireResponse.methodNotFound(id: request.id, method: request.method)
        }
    }

    private func dispatchSecretGet(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        // Bug 1 fix: accept BOTH wire shapes for backward-compatibility.
        //
        // Shape A (canonical broker form):
        //   { sub: String, scope: String, op: "read"|"rotate", ttl: Int, toolName?: String }
        //
        // Shape B (client shorthand — ProductionBrokerClient.get(name:) sends this):
        //   { name: String }
        //
        // When Shape B is received, translate to Shape A using defaults:
        //   sub   = current process username ($USER env or NSUserName())
        //   scope = <name>   (the secret name IS the scope path)
        //   op    = "read"
        //   ttl   = 300
        let params: SecretGetParams
        do {
            // Try Shape A first (full canonical params).
            if let canonical = try? decodeParams(SecretGetParams.self, from: request.params) {
                // v0.4.2 @sensei HIGH fix: even Shape A's `sub` field is
                // attacker-controlled JSON. Override with kernel-peer-uid
                // resolution so audit rows always reflect the actual caller.
                let trustedSub = Self.usernameFromPeerUid(peerUid)
                params = SecretGetParams(
                    sub: trustedSub,
                    scope: canonical.scope,
                    op: canonical.op,
                    ttl: canonical.ttl,
                    toolName: canonical.toolName,
                    name: canonical.name
                )
            } else {
                // Try Shape B: { name: String } — translate to canonical form.
                struct NameOnlyParams: Decodable { let name: String }
                let nameParams = try decodeParams(NameOnlyParams.self, from: request.params)
                // HIGH-5 fix (@security panel): derive `sub` from the kernel-
                // reported peer credentials (uid + getpwuid), NOT from the
                // attacker-controlled USER environment variable. Mismatched
                // env spoofs the audit row's `sub` while uid remains correct;
                // this closes that audit-log spoofing vector.
                let subFromPeer = Self.usernameFromPeerUid(peerUid)
                params = SecretGetParams(
                    sub: subFromPeer,
                    scope: nameParams.name,
                    op: .read,
                    ttl: 300,
                    toolName: nil,
                    name: nameParams.name
                )
            }
        } catch {
            return WireResponse(
                id: request.id,
                error: WireError(
                    code: WireErrorCode.invalidParams,
                    message: "Invalid params for secret.get: \(error)"
                )
            )
        }

        let brokerRequest = BrokerRequest(
            sub: params.sub,
            scope: params.scope,
            op: params.op,
            ttl: params.ttl,
            toolName: params.toolName
        )

        // Build the WrappedRequest with the original JSON payload so audit
        // rows preserve the raw caller bytes.
        let payload = (try? JSONEncoder().encode(request)) ?? Data()
        let wrapped = await bridge.wrapUnixRequest(payload: payload, peerUid: peerUid)

        let response = await daemon.handleRequest(brokerRequest, wrapped: wrapped)

        // W4.2 — local-unix callers receive .boundPlaintext. The existing
        // ProductionBrokerClient.get() expects result: .string(value) (not
        // an object envelope). Emit the plaintext directly so the client
        // decode path succeeds without cross-repo changes.
        //
        // All other response cases use the standard toWireResponse() encoder.
        if case let .boundPlaintext(_, plaintext) = response {
            return WireResponse(id: request.id, result: .string(plaintext))
        }

        do {
            return try response.toWireResponse(id: request.id)
        } catch {
            return WireResponse(
                id: request.id,
                error: WireError(
                    code: WireErrorCode.internalError,
                    message: "Failed to encode broker response: \(error)"
                )
            )
        }
    }

    // MARK: - Auth gate (CRIT-2)

    /// Returns an authorization-denied WireResponse when peerUid ≠ ownerUid,
    /// also emitting an audit row for the rejected attempt.
    private func requireOwner(_ request: WireRequest, peerUid: UInt32) async -> WireResponse? {
        guard peerUid == ownerUid else {
            // Emit audit row for rejected mutation attempt (deny, no reason = write op rejection).
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-\(request.method)-denied",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: "(wire:\(request.method))",
                op: .read,
                allow: .deny,
                reason: .scopePatternDenied,
                llmTouched: false
            ))
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.denied,
                message: "Unauthorized: peerUid \(peerUid) != ownerUid \(ownerUid)"
            ))
        }
        return nil
    }

    // MARK: - secret.set (W3 — wired to BWClient.set)

    private func dispatchSecretSet(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        // CRIT-2: gate on owner identity before any mutation.
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }

        struct SetParams: Decodable {
            let name: String
            let value: String
        }
        let params: SetParams
        do {
            params = try decodeParams(SetParams.self, from: request.params)
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.invalidParams,
                message: "Invalid params for secret.set: \(error)"
            ))
        }
        // v0.4.2 @ronin FINDING-1 fix: enforce ScopePolicy on write paths
        // (secret.set bypassed BrokerDaemon.handleRequest where v0.4.1 wired
        // the policy). Without this check a local-uid peer could write keys
        // under another system's blast-radius scope.
        if let policy = daemon.systemScopePolicy, !policy.canRead(path: params.name) {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.invalidParams,
                message: "secret.set denied — path outside this system's blast-radius scope (W6.5c F-PSA-3)"
            ))
        }
        do {
            try await daemon.bwClient.set(name: params.name, value: params.value)
            // CRIT-2: audit every mutation.
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-set-\(UUID().uuidString.prefix(8))",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: String(params.name.prefix(AuditWriter.maxSecretNameLength)),
                op: .rotate,
                allow: .allow,
                reason: nil,
                llmTouched: false
            ))
            return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "secret.set failed: \(error)"
            ))
        }
    }

    // MARK: - secret.list (W3 — wired to BWClient.list)

    private func dispatchSecretList(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        // CRIT-2: gate on owner identity — listing is a read op but exposes all names.
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }

        struct ListParams: Decodable {
            let filter: String?
        }
        // params is optional for list — default to no filter.
        let filter: String?
        if let p = request.params {
            filter = (try? decodeParams(ListParams.self, from: p))?.filter
        } else {
            filter = nil
        }
        do {
            let names = try await daemon.bwClient.list()
            // Apply optional prefix glob filter (v1: prefix match).
            var filtered: [String]
            if let f = filter, !f.isEmpty {
                let prefix = f.hasSuffix("*") ? String(f.dropLast()) : f
                filtered = names.filter { $0.hasPrefix(prefix) }
            } else {
                filtered = names
            }
            // v0.4.2 @ronin FINDING-1 fix: enforce ScopePolicy on the list
            // response. Without this filter a local-uid peer could enumerate
            // every collection name in the vault, leaking which keys other
            // systems hold under their blast-radius scopes.
            if let policy = daemon.systemScopePolicy {
                filtered = filtered.filter { policy.canRead(path: $0) }
            }
            // Bug 2 fix: return [VaultEntryRef] shaped objects instead of raw
            // [String] names. ProductionBrokerClient.list() decodes [VaultEntryRef]
            // — returning bare strings causes DecodingError.typeMismatch.
            //
            // Synthetic defaults for metadata fields not yet tracked by BWClient.list():
            //   scope        = "default"
            //   tier         = .warm
            //   usageState   = .warm
            //   lastRotated  = epoch (unknown — broker does not store rotation history yet)
            //   rotationDue  = +7 days (warm tier baseline)
            let now = Date()
            let sevenDaysFromNow = now.addingTimeInterval(7 * 24 * 3600)
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let items: [JSONValue] = try filtered.map { name in
                let ref = VaultEntryRef(
                    name: name,
                    scope: "default",
                    tier: .warm,
                    usageState: .warm,
                    lastRotated: Date(timeIntervalSince1970: 0),
                    rotationDue: sevenDaysFromNow
                )
                let data = try encoder.encode(ref)
                return try JSONDecoder().decode(JSONValue.self, from: data)
            }
            // CRIT-2: audit list access.
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-list-\(UUID().uuidString.prefix(8))",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: "(list)",
                op: .read,
                allow: .allow,
                reason: nil,
                llmTouched: false
            ))
            return WireResponse(id: request.id, result: .array(items))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "secret.list failed: \(error)"
            ))
        }
    }

    // MARK: - secret.delete (W3 — wired to BWClient.delete)

    private func dispatchSecretDelete(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        // CRIT-2: gate on owner identity before any mutation.
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }

        struct DeleteParams: Decodable {
            let name: String
        }
        let params: DeleteParams
        do {
            params = try decodeParams(DeleteParams.self, from: request.params)
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.invalidParams,
                message: "Invalid params for secret.delete: \(error)"
            ))
        }
        // v0.4.2 @ronin FINDING-1 fix: enforce ScopePolicy on delete paths.
        if let policy = daemon.systemScopePolicy, !policy.canRead(path: params.name) {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.invalidParams,
                message: "secret.delete denied — path outside this system's blast-radius scope (W6.5c F-PSA-3)"
            ))
        }
        do {
            try await daemon.bwClient.delete(name: params.name)
            // CRIT-2: audit every mutation.
            _ = try? await daemon.audit.append(.init(
                ts: Date(),
                tokenJti: "wire-delete-\(UUID().uuidString.prefix(8))",
                callerUid: Int32(bitPattern: peerUid),
                callerTransport: .unix,
                secretName: String(params.name.prefix(AuditWriter.maxSecretNameLength)),
                op: .rotate,
                allow: .allow,
                reason: nil,
                llmTouched: false
            ))
            return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "secret.delete failed: \(error)"
            ))
        }
    }

    // MARK: - Params

    /// Decoded params for `secret.get`.
    ///
    /// Bug 1 fix: `name` is the shorthand field emitted by
    /// `ProductionBrokerClient.get(name:)` — `{name: "x"}`. When present
    /// and the canonical fields (`sub`, `scope`, `op`, `ttl`) are absent, the
    /// dispatcher fills in safe defaults (see `dispatchSecretGet`).
    private struct SecretGetParams: Decodable {
        let sub: String
        let scope: String
        let op: ShikkiSBT.Op
        let ttl: Int
        let toolName: String?
        /// Shorthand name field (Shape B — client shorthand form).
        let name: String?

        init(sub: String, scope: String, op: ShikkiSBT.Op, ttl: Int, toolName: String?, name: String? = nil) {
            self.sub = sub
            self.scope = scope
            self.op = op
            self.ttl = ttl
            self.toolName = toolName
            self.name = name
        }
    }

    /// HIGH-5 helper (@security panel): resolve a username from a kernel-
    /// reported peer UID via `getpwuid_r(3)` (reentrant variant).
    /// v0.4.2 fixes:
    /// - @tech-expert: replaced `getpwuid` (POSIX static buffer) with
    ///   `getpwuid_r` for thread-safety in actor concurrency.
    /// - @ronin FINDING-4: bound returned name to 64 bytes + strip
    ///   non-printable characters to prevent audit-log injection via
    ///   crafted passwd entries.
    static func usernameFromPeerUid(_ uid: UInt32) -> String {
        var pwd = passwd()
        var buf = [CChar](repeating: 0, count: 1024)
        var result: UnsafeMutablePointer<passwd>? = nil
        let rc = buf.withUnsafeMutableBufferPointer { ptr -> Int32 in
            getpwuid_r(uid_t(uid), &pwd, ptr.baseAddress, ptr.count, &result)
        }
        guard rc == 0, result != nil else { return "uid:\(uid)" }
        let raw = String(cString: pwd.pw_name)
        // Strip non-printable + cap at 64 bytes for safe audit rendering.
        let sanitized = raw.unicodeScalars
            .filter { $0.value >= 0x20 && $0.value < 0x7F }
            .prefix(64)
            .map { String($0) }
            .joined()
        return sanitized.isEmpty ? "uid:\(uid)" : sanitized
    }

    // MARK: - vault.unlock (feat/vault-unlock-2026-11-01)

    /// Derives the vault session key from the master password and holds it
    /// in memory only. The password itself is never logged or stored.
    ///
    /// Wire params: `{ "masterPassword": String, "email": String }`
    /// Wire result on success: `{ "ok": true }`
    /// Wire error on wrong password or missing account key:
    ///   code: -32000 (denied), message: human-readable failure reason.
    ///
    /// Security: vault.unlock is gated to the ownerUid — only the
    /// interactive operator can unlock the vault, never a remote peer.
    private func dispatchVaultUnlock(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        // Gate: only the broker owner may unlock the vault.
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }

        struct UnlockParams: Decodable {
            let masterPassword: String
            let email: String
        }
        let params: UnlockParams
        do {
            params = try decodeParams(UnlockParams.self, from: request.params)
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.invalidParams,
                message: "vault.unlock requires {masterPassword, email}: \(error)"
            ))
        }

        do {
            try await daemon.bwClient.unlock(masterPassword: params.masterPassword, email: params.email)
            // Verification probe: perform a list() call to confirm the session is
            // genuinely usable before reporting success. unlock() derives the vault
            // key in memory, but a stale / empty session cache means every
            // subsequent API call would throw notAuthenticated — this probe
            // surfaces that failure HERE rather than letting the CLI print
            // "Vault unlocked." while later calls silently fail.
            _ = try await daemon.bwClient.list()
            return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
        } catch {
            // Surface the failure clearly; do NOT echo the password back.
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.denied,
                message: "vault.unlock failed: \(error)"
            ))
        }
    }

    // MARK: - vault.lock (spec 7c2e9a14 W0, BR-06)

    /// Drop the vault key from memory and custody. Only the owner may lock.
    ///
    /// Wire params: none.
    /// Wire result on success: `{ "ok": true }`
    private func dispatchVaultLock(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }
        do {
            try await daemon.bwClient.lock()
            return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "vault.lock failed: \(error)"
            ))
        }
    }

    // MARK: - vault.simulate.device_lock / vault.simulate.device_unlock (spec 7c2e9a14 W2)

    /// Fire a simulated screen-lock event. Only available when a
    /// ManualDeviceLockSignalSource was wired (--dry-run mode). In production
    /// this verb is denied because simulationLockSource is nil.
    private func dispatchSimulateDeviceLock(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }
        guard let src = await daemon.simulationLockSource else {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.denied,
                message: "vault.simulate.device_lock: not available in production mode"
            ))
        }
        src.fireLock()
        // The lock propagates asynchronously (DeviceLockObserver fires an
        // unstructured Task). Callers poll vault.status for up to 2 s per BR-03.
        return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
    }

    /// Fire a simulated screen-unlock event. Only available in --dry-run mode.
    private func dispatchSimulateDeviceUnlock(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }
        guard let src = await daemon.simulationLockSource else {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.denied,
                message: "vault.simulate.device_unlock: not available in production mode"
            ))
        }
        src.fireUnlock()
        // The unlock propagates asynchronously (DeviceLockObserver fires an
        // unstructured Task). Callers poll vault.status for up to 3 s per BR-04.
        return WireResponse(id: request.id, result: .object(["ok": .bool(true)]))
    }

    // MARK: - vault.status (feat/vault-unlock-2026-11-01)

    /// Reports the current locked/unlocked state. Safe to call without
    /// owner auth — reveals no secret material.
    ///
    /// Wire params: none required.
    /// Wire result: `{ "locked": Bool }`
    private func dispatchVaultStatus(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        let unlocked = await daemon.bwClient.isVaultUnlocked
        let reason  = await daemon.bwClient.lockReason
        let backend = await daemon.bwClient.custodyBackend
        var result: [String: JSONValue] = ["locked": .bool(!unlocked)]
        if let reason  { result["reason"]  = .string(reason) }
        if let backend { result["backend"] = .string(backend) }
        return WireResponse(id: request.id, result: .object(result))
    }

    /// Scan the vault for plaintext entries and return a count (BR-10).
    /// The `--dry-run` and production paths both call bwClient.list().
    /// Actual re-encryption (writing new encrypted values) is out of scope
    /// per spec 7c2e9a14 §Out-of-scope.
    private func dispatchVaultReencrypt(_ request: WireRequest, peerUid: UInt32) async -> WireResponse {
        if let denied = await requireOwner(request, peerUid: peerUid) { return denied }
        do {
            let entries = try await daemon.bwClient.list(filter: nil)
            let count = entries.count
            return WireResponse(id: request.id, result: .object([
                "count": .int(Int64(count)),
            ]))
        } catch {
            return WireResponse(id: request.id, error: WireError(
                code: WireErrorCode.internalError,
                message: "vault.reencrypt list failed: \(error)"
            ))
        }
    }

    // MARK: - Helpers

    /// Decode a typed params struct from a JSONValue tree by re-encoding
    /// through JSON. Avoids ad-hoc per-method JSON walking.
    private func decodeParams<T: Decodable>(_ type: T.Type, from value: JSONValue?) throws -> T {
        guard let value else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "params required")
            )
        }
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(T.self, from: data)
    }
}
