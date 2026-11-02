import Foundation

// RotationEngine — the broker's core cadence + anomaly + conversation
// rotation orchestrator.
//
// Wave 3 delivers six surfaces:
//   T27  fetchRate(tier:f24h:f7d:f30d:)        → tier-weighted Σ (BR-C-01)
//   T28  cadenceHours(tier:fetchRate:isDormant:) → clamped cadence (BR-C-02, -09, -10)
//   T29  evaluateDormancy + tick filter         → suspend dormant (BR-B-05/-06, BR-C-04/-05)
//   T30  applyRotation + handleFailure          → state mutation (BR-B-02/-03/-04/-08/-09)
//   T31  onAnomaly(_:)                          → <60s SLA (BR-B-07, BR-C-08)
//   T32  onLLMTouched + onConversationEnd       → LLM queue drain (BR-C-06, BR-E-02/-04)
//
// All state lives in this actor (in-memory vault-entries + retry queue +
// LLM rotation queue); Wave 4 swaps the backing store for the real
// ShikkiDB driver without changing the call surface. The driver protocol
// itself is declared here as a light forward ref; DriverOVH/Brevo/GitHub
// conformances arrive in Wave 4 (T42-T46).
//
// ---- Driver seam ---------------------------------------------------------
// Wave 3 does not ship real vendor drivers; it declares the protocol the
// engine calls into and a simple in-process registry. Tests inject a
// stub driver to drive the happy + failure + anomaly paths.

/// What triggered a rotation call. Anomaly paths carry their signal so
/// drivers can log / tag / escalate as needed.
public enum RotationTrigger: Sendable, Equatable {
    case scheduled(QoSTrackTier)
    case llmTouchedSessionEnd
    case anomaly(AnomalySignal)
    case manual(op: String)
}

/// Tier-alias used by `.scheduled` so the engine can communicate which
/// kernel QoS slot fired without re-importing ShikkiCore's QoSTrack in
/// every signature. Values match the four `Tier` cases one-to-one.
public enum QoSTrackTier: String, Sendable, Equatable {
    case hot, warm, cool, external
}

/// Outcome of a driver call back to the engine.
public enum RotationOutcome: Sendable, Equatable {
    case rotated
    case failed(reason: String)
}

/// The driver protocol every vendor adapter implements. Wave 3 ships the
/// call-path (`vendor` + `rotate`) the RotationEngine relies on; Wave 4
/// adds `invalidate(previous:)` for vendors that need an explicit revoke.
///
/// Review finding U17 — the previously-declared `humanFallback` slot
/// was never read anywhere, so it was dropped. Future vendors that need
/// a manual runbook carry it on a vendor-specific config object
/// (`HumanRunbook` still exists for that use), not on the protocol.
/// YAGNI wins over speculative extension points.
public protocol SecretRotationDriver: Sendable {
    var vendor: String { get }
    func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome
    /// Invalidate the previous credential after a successful rotation.
    /// Default implementation is a no-op; vendors that need an explicit
    /// revoke (e.g. GitHub PAT, Brevo API key) override it.
    func invalidate(previous: VaultEntryRef) async throws
}

extension SecretRotationDriver {
    public func invalidate(previous: VaultEntryRef) async throws {
        _ = previous
    }
}

/// Registry keyed by `vendor` string. Wave 3 scaffold — DI-wired full
/// registry lands with the daemon in Wave 4.
public actor DriverRegistry {
    private var drivers: [String: any SecretRotationDriver] = [:]

    public init(drivers: [any SecretRotationDriver] = []) {
        for d in drivers {
            self.drivers[d.vendor] = d
        }
    }

    public func register(_ driver: any SecretRotationDriver) {
        drivers[driver.vendor] = driver
    }

    public func resolve(vendor: String) -> (any SecretRotationDriver)? {
        drivers[vendor]
    }
}

// ---- The engine ----------------------------------------------------------

/// A clock source the engine can swap out under test. Defaults to the
/// system `Date()` in production.
public struct RotationClock: Sendable {
    public let now: @Sendable () -> Date
    public init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }
}

public actor RotationEngine {

    // MARK: - Tunables
    /// Retry backoff for `handleFailure` (BR-B-04).
    public static let retryBackoffSeconds: TimeInterval = 300   // 5 min
    /// SLA ceiling for anomaly-driven rotations (BR-C-08).
    public static let anomalySLASeconds: TimeInterval = 60
    /// `llm_touched` conversation-end rotation cap (BR-E-03).
    public static let conversationRotationCapSeconds: TimeInterval = 3600

    /// Review finding U10 — per-session cap on queued secrets. A
    /// malicious MCP caller cannot grow the set past this ceiling.
    public static let llmQueueMaxPerSession: Int = 100
    /// Review finding U10 — global cap on number of active session ids.
    /// When exceeded, the oldest entry is evicted and a seam row with
    /// `.llmQueueSaturated` is appended.
    public static let llmQueueMaxSessions: Int = 1_000

    // MARK: - Collaborators
    private let clock: RotationClock
    private let drivers: DriverRegistry
    private let audit: AuditWriter
    private let seams: SeamsWriter
    private let registry: TokenRegistry

    // MARK: - State (in-memory; Wave 4 swap → ShikkiDB)
    /// Keyed by secret name. Mirrors the 0030 vault-entries row shape.
    private var entries: [String: VaultEntryRef] = [:]
    /// Per-entry fetch counters feeding `fetchRate`. Reset on dormancy exit.
    private var fetchCounters: [String: (f24h: Int, f7d: Int, f30d: Int)] = [:]
    /// `handleFailure` retry queue keyed by secret name → due date.
    private var retryQueue: [String: Date] = [:]
    /// LLM-touched rotation queue — sessionId → set of parent secret names.
    private var llmRotationQueue: [String: Set<String>] = [:]
    /// Insertion order for the LLM queue — used by the U10 eviction
    /// policy. An array keeps "oldest first" O(1) amortized.
    private var llmQueueInsertionOrder: [String] = []

    /// Output-path audit surface (BR-H-01 — for the broker's output gate).
    public enum OutputTransport: Sendable, Equatable {
        case mcp
        case llmBridgeUid
        case unix
    }

    public init(
        clock: RotationClock = RotationClock(),
        drivers: DriverRegistry = DriverRegistry(),
        audit: AuditWriter,
        seams: SeamsWriter,
        registry: TokenRegistry
    ) {
        self.clock = clock
        self.drivers = drivers
        self.audit = audit
        self.seams = seams
        self.registry = registry
    }

    // MARK: - Test / bootstrap helpers

    /// Registers (or upserts) an entry. On create (first insert), seeds
    /// `last_rotated = now` and `rotation_due = now + baseHours`
    /// (BR-B-02: every entry is rotation-scheduled at creation).
    public func seed(entry: VaultEntryRef) {
        entries[entry.name] = entry
    }

    public func entry(name: String) -> VaultEntryRef? { entries[name] }

    public func entryCount() -> Int { entries.count }

    public func setFetchCounters(secret: String, f24h: Int, f7d: Int, f30d: Int) {
        fetchCounters[secret] = (f24h, f7d, f30d)
    }

    public func fetchCounters(secret: String) -> (f24h: Int, f7d: Int, f30d: Int) {
        fetchCounters[secret] ?? (0, 0, 0)
    }

    public func retryDueDate(secret: String) -> Date? { retryQueue[secret] }

    public func llmQueuedParents(sessionId: String) -> [String] {
        Array(llmRotationQueue[sessionId] ?? [])
    }

    // ====================================================================
    // MARK: - T27 — fetchRate (BR-C-01)
    // ====================================================================

    /// Tier-adaptive fetch-rate. Pure function — no side effects.
    /// Formula (locked 2026-04-20):
    ///   fr = f24h·w24h + f7d·w7d + f30d·w30d
    public nonisolated func fetchRate(tier: Tier, f24h: Int, f7d: Int, f30d: Int) -> Double {
        let w = tier.weights
        return Double(f24h) * w.w24h + Double(f7d) * w.w7d + Double(f30d) * w.w30d
    }

    // ====================================================================
    // MARK: - T28 — cadenceHours (BR-C-02, BR-C-09, BR-C-10)
    // ====================================================================

    /// Cadence clamp: if dormant → `.max` (rotation suspended). Otherwise
    /// `round(base / (1 + fr))` clamped to the range [1, base].
    /// Note: fetchRate > 0 may still produce a value above base by math
    /// alone only when fr < 0; negative rates aren't reachable because
    /// weights are non-negative. The upper clamp to base guards the
    /// "fr == 0, non-dormant" case and any future weight re-tuning.
    public nonisolated func cadenceHours(tier: Tier, fetchRate: Double, isDormant: Bool) -> Int {
        if isDormant { return .max }
        let base = Double(tier.baseHours)
        let raw = base / (1.0 + fetchRate)
        let clampedUpper = min(raw, base)
        let clampedLower = max(clampedUpper, 1.0)
        return Int(clampedLower.rounded())
    }

    // ====================================================================
    // MARK: - T29 — evaluateDormancy + tick filter
    // ====================================================================

    /// Returns `.dormant` iff all three windows are zero (BR-C-04).
    /// Otherwise returns `nil` — the caller keeps the prior usage_state.
    public nonisolated func evaluateDormancy(f24h: Int, f7d: Int, f30d: Int) -> UsageState? {
        (f24h == 0 && f7d == 0 && f30d == 0) ? .dormant : nil
    }

    /// Kernel-job entrypoint: enumerate rotation candidates for a given
    /// QoS track. Dormant + archived are filtered OUT (BR-C-05, BR-B-09).
    /// Returns names that are actually rotation-due.
    public func tick(track: QoSTrackTier) async -> [String] {
        let now = clock.now()
        let wantedTier: Tier = {
            switch track {
            case .hot:      return .hot
            case .warm:     return .warm
            case .cool:     return .cool
            case .external: return .external
            }
        }()
        return entries.values
            .filter { e in
                e.tier == wantedTier
                && e.usageState != .dormant
                && e.usageState != .archived
                && e.rotationDue <= now
            }
            .map(\.name)
            .sorted()
    }

    /// `onFetch` hook. Records a fetch and — if the entry was dormant —
    /// exits dormancy, resets counters, and re-schedules next tick
    /// (BR-B-06, BR-C-05).
    @discardableResult
    public func onFetch(secret: String) -> Bool {
        guard var entry = entries[secret] else { return false }
        // Increment the 24h counter as a proxy for "there was activity".
        // Real window rollover is the Wave 4 DB-driven job.
        var counters = fetchCounters[secret] ?? (0, 0, 0)
        counters.f24h += 1
        fetchCounters[secret] = counters

        if entry.usageState == .dormant {
            // Exit dormancy: reset counters, restore tier state, re-schedule.
            // Review finding #14 — Tier.defaultUsageState dedup.
            fetchCounters[secret] = (1, 0, 0)
            let restoredState: UsageState = entry.tier.defaultUsageState
            let baseHrs = Double(entry.tier.baseHours)
            let nextDue = clock.now().addingTimeInterval(baseHrs * 3600)
            entry = VaultEntryRef(
                name: entry.name,
                scope: entry.scope,
                tier: entry.tier,
                usageState: restoredState,
                lastRotated: entry.lastRotated,
                rotationDue: nextDue
            )
            entries[secret] = entry
            return true
        }
        return false
    }

    // ====================================================================
    // MARK: - T30 — applyRotation + handleFailure
    // ====================================================================

    /// Seeds a freshly-created vault entry per BR-B-02:
    ///   last_rotated = now, rotation_due = now + tier.baseHours,
    ///   usage_state = matching tier enum.
    public func createEntry(name: String, scope: String, tier: Tier) -> VaultEntryRef {
        let now = clock.now()
        let due = now.addingTimeInterval(Double(tier.baseHours) * 3600)
        // Review finding #14 — Tier.defaultUsageState dedup.
        let state: UsageState = tier.defaultUsageState
        let entry = VaultEntryRef(
            name: name,
            scope: scope,
            tier: tier,
            usageState: state,
            lastRotated: now,
            rotationDue: due
        )
        entries[name] = entry
        return entry
    }

    /// Successful rotation path (BR-B-03): updates `last_rotated`,
    /// recomputes `rotation_due` from cadenceHours, appends `op=rotate`
    /// allow audit row. Throws if entry is archived (BR-B-09).
    public func applyRotation(entry: VaultEntryRef) async throws -> VaultEntryRef {
        if entry.usageState == .archived {
            throw RotationError.archivedEntryIssuanceRefused(name: entry.name)
        }
        let now = clock.now()
        let counters = fetchCounters[entry.name] ?? (0, 0, 0)
        let fr = fetchRate(tier: entry.tier, f24h: counters.f24h, f7d: counters.f7d, f30d: counters.f30d)
        let dormancy = evaluateDormancy(f24h: counters.f24h, f7d: counters.f7d, f30d: counters.f30d)
        let cad = cadenceHours(tier: entry.tier, fetchRate: fr, isDormant: dormancy == .dormant)
        let newDue: Date = {
            if cad == .max {
                // Dormant — suspend: next tick far-future.
                return .distantFuture
            }
            return now.addingTimeInterval(Double(cad) * 3600)
        }()
        let rotated = VaultEntryRef(
            name: entry.name,
            scope: entry.scope,
            tier: entry.tier,
            usageState: entry.usageState,
            lastRotated: now,
            rotationDue: newDue
        )
        entries[entry.name] = rotated

        // BR-G-01 — audit row BEFORE returning. Rotation path uses
        // op=rotate + allow, even though this path is broker-internal.
        try await audit.append(
            AuditRow(
                ts: now,
                tokenJti: "internal:rotation-engine",
                callerUid: nil,
                callerTransport: .unix,
                secretName: entry.name,
                op: .rotate,
                allow: .allow,
                reason: nil,
                llmTouched: false
            )
        )
        // Clear retry queue on success.
        retryQueue.removeValue(forKey: entry.name)
        return rotated
    }

    /// Failure path (BR-B-04): leaves `last_rotated` untouched, writes a
    /// `deny / rotation_failed` audit row, enqueues retry at now+5min.
    public func handleFailure(entry: VaultEntryRef, reason: String) async throws {
        let now = clock.now()
        try await audit.append(
            AuditRow(
                ts: now,
                tokenJti: "internal:rotation-engine",
                callerUid: nil,
                callerTransport: .unix,
                secretName: entry.name,
                op: .rotate,
                allow: .deny,
                reason: .rotationFailed,
                llmTouched: false
            )
        )
        retryQueue[entry.name] = now.addingTimeInterval(Self.retryBackoffSeconds)
        // NOTE: deliberately leave `entries[entry.name]` untouched so the
        // existing `last_rotated` persists — BR-B-04.
        _ = reason
    }

    /// Archive path (BR-B-08): retired entries carry a timestamp, never
    /// hard-deleted. Subsequent `applyRotation` / token issuance refuse
    /// (BR-B-09).
    @discardableResult
    public func archive(name: String) -> VaultEntryRef? {
        guard let current = entries[name] else { return nil }
        let archived = VaultEntryRef(
            name: current.name,
            scope: current.scope,
            tier: current.tier,
            usageState: .archived,
            lastRotated: current.lastRotated,
            rotationDue: clock.now()
        )
        entries[name] = archived
        return archived
    }

    // ====================================================================
    // MARK: - T31 — onAnomaly (BR-B-07, BR-C-08)
    // ====================================================================

    /// Anomaly-driven rotation. Bypasses dormancy + cadence + retry queue.
    /// Appends a seams row (BR-G-03) and must complete under the SLA ceiling
    /// (BR-C-08 — 60s) as measured by the injected clock. Throws on SLA
    /// breach so tests can #expect the failure mode.
    public func onAnomaly(_ signal: AnomalySignal, secretName: String) async throws {
        let start = clock.now()
        guard let entry = entries[secretName] else {
            // No entry: still append a seams row and surface error.
            try await seams.append(
                signal: signal,
                secret: secretName,
                outcome: .failed,
                ts: start,
                notes: "no vault_entry for anomaly"
            )
            throw RotationError.noEntryForAnomaly(name: secretName)
        }

        // Bypass dormancy / cadence / queue: force rotate now.
        // Review finding #7 — when the vendor has no registered driver,
        // emit a seams row with `.noDriverRegistered` and surface a
        // deterministic `.failed` outcome via the HUP fallback. The
        // fallback is now a visible signal, not a silent failure.
        let vendorName = Self.vendor(from: entry.scope)
        let outcome: RotationOutcome
        if let driver = await drivers.resolve(vendor: vendorName) {
            outcome = await driver.rotate(entry: entry, trigger: .anomaly(signal))
        } else {
            try await seams.append(
                signal: .noDriverRegistered(vendor: vendorName, secretName: secretName),
                secret: secretName,
                outcome: .failed,
                ts: clock.now(),
                notes: "no driver registered for vendor=\(vendorName)"
            )
            outcome = .failed(reason: "no driver registered for \(vendorName)")
        }
        let end = clock.now()
        let elapsed = end.timeIntervalSince(start)

        switch outcome {
        case .rotated:
            _ = try await applyRotation(entry: entry)
            try await seams.append(
                signal: signal,
                secret: secretName,
                outcome: .rotated,
                ts: end,
                notes: "anomaly rotation elapsed=\(Int(elapsed))s"
            )
        case .failed(let reason):
            try await handleFailure(entry: entry, reason: reason)
            try await seams.append(
                signal: signal,
                secret: secretName,
                outcome: .failed,
                ts: end,
                notes: "anomaly rotation failed: \(reason)"
            )
        }

        if elapsed > Self.anomalySLASeconds {
            throw RotationError.anomalySLABreached(elapsed: elapsed)
        }
    }

    // ====================================================================
    // MARK: - T32 — onLLMTouched + onConversationEnd
    // ====================================================================

    /// Enqueues `secret`'s parent for post-conversation rotation, regardless
    /// of cadence (BR-C-06, BR-E-02). Idempotent per (sessionId, secret).
    ///
    /// Review finding U10 — applies bounded growth:
    ///   * Per-session cap of `llmQueueMaxPerSession`; further inserts
    ///     for that session drop silently AFTER a saturation seam is
    ///     written (one per overflow event).
    ///   * Global cap of `llmQueueMaxSessions`; on overflow, the oldest
    ///     session is evicted and a `.llmQueueSaturated` seam is written.
    public func onLLMTouched(secret: String, sessionId: String) async {
        var set = llmRotationQueue[sessionId] ?? []

        // Per-session cap.
        if set.count >= Self.llmQueueMaxPerSession && !set.contains(secret) {
            try? await seams.append(
                signal: .llmQueueSaturated(sessionId: sessionId, droppedCount: 1),
                secret: secret,
                outcome: .bypassed,
                ts: clock.now(),
                notes: "per-session cap \(Self.llmQueueMaxPerSession) reached"
            )
            return
        }

        let isNewSession = llmRotationQueue[sessionId] == nil

        // Global cap: evict oldest non-target session before inserting a
        // brand-new session id.
        if isNewSession && llmRotationQueue.count >= Self.llmQueueMaxSessions {
            if let victim = llmQueueInsertionOrder.first(where: { $0 != sessionId }) {
                let droppedSet = llmRotationQueue.removeValue(forKey: victim) ?? []
                llmQueueInsertionOrder.removeAll { $0 == victim }
                try? await seams.append(
                    signal: .llmQueueSaturated(sessionId: victim, droppedCount: droppedSet.count),
                    secret: "llm_rotation_queue",
                    outcome: .bypassed,
                    ts: clock.now(),
                    notes: "global cap \(Self.llmQueueMaxSessions) reached; evicted oldest"
                )
            }
        }

        set.insert(secret)
        llmRotationQueue[sessionId] = set
        if isNewSession {
            llmQueueInsertionOrder.append(sessionId)
        }
    }

    /// Drains the per-session queue and rotates each parent. The call
    /// gates rotation within `conversationRotationCapSeconds` of session
    /// end per BR-E-03 (60 min ceiling).
    public func onConversationEnd(sessionId: String) async throws {
        guard let pending = llmRotationQueue.removeValue(forKey: sessionId) else { return }
        // Keep the insertion-order ledger in sync with the queue.
        llmQueueInsertionOrder.removeAll { $0 == sessionId }
        for name in pending.sorted() {
            guard let entry = entries[name] else { continue }
            let vendorName = Self.vendor(from: entry.scope)
            // Review finding #7 — missing driver surfaces visibly via a
            // seams row instead of silently failing.
            let outcome: RotationOutcome
            if let driver = await drivers.resolve(vendor: vendorName) {
                outcome = await driver.rotate(entry: entry, trigger: .llmTouchedSessionEnd)
            } else {
                try await seams.append(
                    signal: .noDriverRegistered(vendor: vendorName, secretName: entry.name),
                    secret: entry.name,
                    outcome: .failed,
                    ts: clock.now(),
                    notes: "no driver registered for vendor=\(vendorName)"
                )
                outcome = .failed(reason: "no driver registered for \(vendorName)")
            }
            switch outcome {
            case .rotated:
                _ = try await applyRotation(entry: entry)
            case .failed(let reason):
                try await handleFailure(entry: entry, reason: reason)
            }
        }
    }

    /// Review finding U20 — escape hatch for RotationTickJob to record
    /// a failure-of-failure (audit write threw inside the tick's
    /// handleFailure branch). Best-effort; drops silently if even this
    /// seam append throws.
    ///
    /// 3rd-pass validator T4 — routed through the dedicated
    /// `.rotationHandlerDoubleFailure` case so the seams ledger no
    /// longer misleadingly tags these as `.failedFetchBurst(windowSec:
    /// 0, count: 0)`.
    public func seamRotationHandlerDoubleFailure(
        secretName: String,
        primary: String,
        secondary: String
    ) async {
        try? await seams.append(
            signal: .rotationHandlerDoubleFailure(
                secretName: secretName,
                primary: primary,
                secondary: secondary
            ),
            secret: secretName,
            outcome: .failed,
            ts: clock.now(),
            notes: "double-failure: apply=\(primary); handle=\(secondary)"
        )
    }

    /// Extracts a vendor string from a scope like `ovh/*` → `ovh`.
    /// Falls back to `unknown` if the scope has no slash.
    /// Public so that `BrokerWireDispatch` can resolve the driver for
    /// manual-rotation requests without duplicating this extraction logic.
    public static func vendor(from scope: String) -> String {
        if let slash = scope.firstIndex(of: "/") {
            return String(scope[..<slash])
        }
        return "unknown"
    }

    // MARK: - Errors
    public enum RotationError: Swift.Error, Sendable, Equatable {
        case archivedEntryIssuanceRefused(name: String)
        case noEntryForAnomaly(name: String)
        case anomalySLABreached(elapsed: TimeInterval)
    }
}

/// Retained for backwards compatibility with any existing test call
/// sites. Review finding #16 — scoped `private` + deprecated so new
/// callers route through the seams-emitting fallback in
/// `onAnomaly` / `onConversationEnd` instead of constructing a silent
/// `.failed` driver directly.
@available(*, deprecated, message: "Fallback path now emits a seams row; construct directly only from legacy tests.")
private struct UnavailableDriver: SecretRotationDriver {
    let vendor: String = "unknown"
    func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        _ = entry
        _ = trigger
        return .failed(reason: "no driver registered for \(vendor)")
    }
}
