import Foundation

// AuditRow — in-memory representation of a `secret_audit` row.
//
// The row is constructed by the broker *before* plaintext is returned to
// the caller (BR-G-01) and handed to AuditWriter (Wave 2) which persists
// it append-only. Column shape here matches migration 0031 one-to-one
// (BR-J-01): ts, token_jti, caller_uid, caller_transport, secret_name,
// op, allow, reason, llm_touched.
//
// `DenyReason` is the closed set of machine-readable reason codes a deny
// row can carry. New reason codes require a schema bump; the broker MUST
// NOT emit free-form strings into `secret_audit.reason`.

public struct AuditRow: Codable, Sendable, Equatable {

    public enum Transport: String, Codable, Sendable, Equatable {
        case unix
        case mcp
    }

    public enum Allow: String, Codable, Sendable, Equatable {
        case allow
        case deny
    }

    public enum DenyReason: String, Codable, Sendable, Equatable, CaseIterable {
        case tokenExpired         = "token_expired"
        case tokenNotYetValid     = "token_not_yet_valid"
        case tokenRevoked         = "token_revoked"
        case badSignature         = "bad_signature"
        case replay               = "replay"
        case scopeDenied          = "scope_denied"
        case scopePatternDenied   = "scope_pattern_denied"
        case scopeTooLong         = "scope_too_long"
        /// v0.5.0 / Wave A3 (@sensei v0.4.2 panel finding): distinct from
        /// `scopePatternDenied`. `scopePatternDenied` = toml-allowlist (a
        /// configuration gate, operator-tunable per ScopeValidator).
        /// `scopeBlastRadiusDenied` = per-system ScopePolicy refusal (a
        /// security enforcement of the W6.5c F-PSA-3 invariant; means the
        /// caller asked for a path outside this system's
        /// shi/system/<self>/** + shi/shared/** blast radius). Without
        /// this distinction ops cannot tell config-misroute from a real
        /// isolation-breach attempt in audit logs.
        case scopeBlastRadiusDenied = "scope_blast_radius_denied"
        case opMismatch           = "op_mismatch"
        case rotationFailed       = "rotation_failed"
        case manifestSigFailed    = "manifest_sig_failed"
        case incidentBypass       = "incident_bypass"
        case brokerSessionInvalid = "broker_session_invalid"
        /// The vault has no signed-in session (expected state, not a fault).
        case vaultNotLoggedIn     = "not_logged_in"
        /// The vault session is open but the key is not derived (expected state).
        case vaultLocked          = "vault_locked"
        case auditWriteFailed     = "audit_write_failed"
        /// Review finding U3 — catch-all for unexpected exceptions thrown
        /// from the mint path. Distinct from `.incidentBypass` (reserved
        /// for the documented `--force` revoke path).
        case internalError        = "internal_error"
        /// Review finding U8 — rejected because the caller-supplied
        /// `now` moved backwards vs the verifier's monotonic floor.
        case tokenClockRollback   = "token_clock_rollback"
        /// Item #9 (BR-F-08) — a privileged admin action was invoked
        /// without a signed envelope. The unsigned `--force` path is
        /// retired; every `revokeAllBots` now requires a passkey-
        /// signed `SignedAdminAction`.
        case adminSignatureRequired = "admin_signature_required"
        /// Item #9 (BR-F-08) — the admin envelope's Ed25519 signature
        /// did not verify against the pinned admin public key.
        case adminBadSignature      = "admin_bad_signature"
        /// Item #9 (BR-F-11) — `|now - issuedAt| > 60s`. The operator
        /// signing → submit window is measured in seconds; anything
        /// outside is treated as a stale replay attempt.
        case adminStale             = "admin_stale"
        /// Item #9 (BR-F-10) — a given nonce MUST be accepted at most
        /// once by the broker. Second presentations land here.
        case adminReplay            = "admin_replay"
    }

    public let ts: Date
    public let tokenJti: String
    public let callerUid: Int32?
    public let callerTransport: Transport
    public let secretName: String
    public let op: ShikkiSBT.Op
    public let allow: Allow
    public let reason: DenyReason?
    public let llmTouched: Bool

    enum CodingKeys: String, CodingKey {
        case ts
        case tokenJti        = "token_jti"
        case callerUid       = "caller_uid"
        case callerTransport = "caller_transport"
        case secretName      = "secret_name"
        case op
        case allow
        case reason
        case llmTouched      = "llm_touched"
    }

    public init(
        ts: Date,
        tokenJti: String,
        callerUid: Int32?,
        callerTransport: Transport,
        secretName: String,
        op: ShikkiSBT.Op,
        allow: Allow,
        reason: DenyReason?,
        llmTouched: Bool
    ) {
        self.ts = ts
        self.tokenJti = tokenJti
        self.callerUid = callerUid
        self.callerTransport = callerTransport
        self.secretName = secretName
        self.op = op
        self.allow = allow
        self.reason = reason
        self.llmTouched = llmTouched
    }
}
