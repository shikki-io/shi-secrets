// StatusCommand — W8 one-line vault-system health.
//
// One line, exit 0 (green) / 1 (yellow) / 2 (red). Designed for shi-inbox /
// dashboards / shell prompts. Composes W7 helpers (PlistPathPolicy) + W4
// boundPlaintext path knowledge + W2 token cache probe.
//
// BR-COMPOSE — only Process() is for /bin/launchctl + /usr/bin/lsof (non-Swift
// externals, both gated through injectable `BrokerdProbing` protocol so tests
// can swap in fakes).

import Foundation
import ShiSecretsKit

// MARK: - Health model

public struct StatusSnapshot: Sendable, Equatable {
    public let brokerd: BrokerdHealth
    public let cache: CacheHealth
    public let vault: VaultHealth
    public let sync: SyncHealth

    public init(brokerd: BrokerdHealth, cache: CacheHealth, vault: VaultHealth, sync: SyncHealth) {
        self.brokerd = brokerd; self.cache = cache; self.vault = vault; self.sync = sync
    }

    public var overall: OverallHealth {
        // Any RED component → red
        if brokerd.isRed || cache.isRed || vault.isRed || sync.isRed { return .red }
        // Any YELLOW component → yellow
        if brokerd.isYellow || cache.isYellow || vault.isYellow || sync.isYellow { return .yellow }
        return .green
    }
}

public enum OverallHealth: String, Sendable {
    case green
    case yellow
    case red

    public var exitCode: Int32 {
        switch self {
        case .green: return 0
        case .yellow: return 1
        case .red: return 2
        }
    }

    public var glyph: String {
        switch self {
        case .green: return "✓"
        case .yellow: return "⚠"
        case .red: return "✗"
        }
    }
}

public enum BrokerdHealth: Sendable, Equatable {
    case up(pid: Int)
    case downNotLoaded
    case multiplePidsRunning(pids: [Int])
    case pidRunningButSocketUnbound(pid: Int)   // T-W8-06 regression
}

public enum CacheHealth: Sendable, Equatable {
    case valid(ageMinutes: Int)
    case expired
    case absent
}

public enum VaultHealth: Sendable, Equatable {
    case reachable(host: String)
    case cooldown429(nextMinutes: Int)
    case unreachable
    /// MED-4 fix (@security panel): yellow state when no real probe ran.
    /// Prevents the false-green case during an actual vault outage.
    case unknownUnprobed(host: String)
}

public enum SyncHealth: Sendable, Equatable {
    case recent(ageSeconds: Int)
    case stale(ageSeconds: Int)
    case never
}

// MARK: - Severity helpers

extension BrokerdHealth {
    var isRed: Bool {
        switch self {
        case .downNotLoaded, .multiplePidsRunning, .pidRunningButSocketUnbound: return true
        case .up: return false
        }
    }
    var isYellow: Bool { false }
}

extension CacheHealth {
    var isRed: Bool { false }
    var isYellow: Bool {
        if case .expired = self { return true }
        if case .absent = self { return true }
        return false
    }
}

extension VaultHealth {
    var isRed: Bool { if case .unreachable = self { return true }; return false }
    var isYellow: Bool {
        if case .cooldown429 = self { return true }
        if case .unknownUnprobed = self { return true } // MED-4: stub = yellow, not green
        return false
    }
}

extension SyncHealth {
    var isRed: Bool { if case .never = self { return true }; return false }
    var isYellow: Bool { if case .stale = self { return true }; return false }
}

// MARK: - Probe protocol

public protocol BrokerdProbing: Sendable {
    /// Returns the list of brokerd PIDs found via `launchctl list` + `pgrep`.
    func pids() -> [Int]
    /// Returns true if the unix socket file exists AND is a socket (not a stale file).
    func socketBound() -> Bool
    /// Cache JSON last-modified or nil if absent.
    func cacheModifiedAt() -> Date?
    /// Cache TTL minutes; nil if no cache.
    func cacheTTLMinutes() -> Int?
    /// Vault host as configured (e.g. "vw.obyw.one"); nil if unconfigured.
    func vaultHost() -> String?
    /// Synchronous reachability probe (HEAD /api/version, 2s timeout); returns
    /// `.reachable` / `.cooldown429(nextMinutes:)` / `.unreachable`.
    func vaultProbe() -> VaultHealth
    /// Most recent sync timestamp (`shi secrets list` or NATS sync event); nil if never.
    func lastSyncAt() -> Date?
}

// MARK: - LiveBrokerdProbe (default implementation for CLI wire-up)

public struct LiveBrokerdProbe: BrokerdProbing {

    public init() {}

    public func pids() -> [Int] {
        let task = Process() // shi-doctor: process-bypass exempt — pgrep probe for running brokerd PIDs; no pure-Swift pid-by-name API
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = ["-f", "shikki-secrets-brokerd"]
        let out = Pipe()
        task.standardOutput = out
        task.standardError = Pipe()
        do { try task.run() } catch { return [] }
        task.waitUntilExit()
        let raw = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return raw.split(separator: "\n").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
    }

    public func socketBound() -> Bool {
        let path = BrokerSocketPath.resolve()
        // Use higher-level FileManager + attribute introspection — avoids the
        // Darwin.stat type-vs-function name clash entirely.
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        guard let type = attrs?[.type] as? FileAttributeType else {
            return FileManager.default.fileExists(atPath: path) // fall back to file existence
        }
        // FileAttributeType.typeSocket exists on Apple platforms via FileManager.
        return type == .typeSocket
    }

    public func cacheModifiedAt() -> Date? {
        let path = NSString(string: "~/.shikki/cache/secrets-brokerd/cache.json").expandingTildeInPath
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        return attrs?[.modificationDate] as? Date
    }

    public func cacheTTLMinutes() -> Int? { 60 }

    public func vaultHost() -> String? { "vw.obyw.one" }

    public func vaultProbe() -> VaultHealth {
        // MED-4 fix (@security panel): stub returns `.unknownUnprobed` (yellow)
        // not `.reachable` (green) — avoids the false-green case during a real
        // vault outage. Real HEAD probe is W8-stage2 follow-up work.
        if let h = vaultHost() { return .unknownUnprobed(host: h) }
        return .unreachable
    }

    public func lastSyncAt() -> Date? {
        let path = NSString(string: "~/.shikki/state/secrets-brokerd-last-sync").expandingTildeInPath
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        return attrs?[.modificationDate] as? Date
    }
}

// MARK: - StatusCommand

public struct StatusCommand {

    private let probe: BrokerdProbing
    private let nowProvider: () -> Date

    public init(
        probe: BrokerdProbing,
        nowProvider: @escaping () -> Date = { Date() }
    ) {
        self.probe = probe
        self.nowProvider = nowProvider
    }

    public func snapshot() -> StatusSnapshot {
        let now = nowProvider()
        // brokerd
        let pids = probe.pids()
        let socketUp = probe.socketBound()
        let brokerd: BrokerdHealth
        if pids.isEmpty { brokerd = .downNotLoaded }
        else if pids.count > 1 { brokerd = .multiplePidsRunning(pids: pids) }
        else if !socketUp { brokerd = .pidRunningButSocketUnbound(pid: pids[0]) }
        else { brokerd = .up(pid: pids[0]) }

        // cache
        let cache: CacheHealth
        if let modAt = probe.cacheModifiedAt(), let ttl = probe.cacheTTLMinutes() {
            let ageMin = Int(now.timeIntervalSince(modAt) / 60)
            cache = ageMin <= ttl ? .valid(ageMinutes: ageMin) : .expired
        } else {
            cache = .absent
        }

        // vault
        let vault: VaultHealth = probe.vaultProbe()

        // sync
        let sync: SyncHealth
        if let last = probe.lastSyncAt() {
            let age = Int(now.timeIntervalSince(last))
            sync = age <= 60 ? .recent(ageSeconds: age) : .stale(ageSeconds: age)
        } else {
            sync = .never
        }

        return StatusSnapshot(brokerd: brokerd, cache: cache, vault: vault, sync: sync)
    }

    /// One-line render (operator-facing).
    public static func render(_ s: StatusSnapshot) -> String {
        let glyph = s.overall.glyph
        let brokerd: String = {
            switch s.brokerd {
            case .up(let pid): return "brokerd:up(pid\(pid))"
            case .downNotLoaded: return "brokerd:DOWN"
            case .multiplePidsRunning(let pids): return "brokerd:DUPED(\(pids.count) pids)"
            case .pidRunningButSocketUnbound(let pid): return "brokerd:PID\(pid)-NO-SOCKET"
            }
        }()
        let cache: String = {
            switch s.cache {
            case .valid(let age): return "cache:valid(\(age)m)"
            case .expired: return "cache:EXPIRED"
            case .absent: return "cache:absent"
            }
        }()
        let vault: String = {
            switch s.vault {
            case .reachable(let h): return "vault:\(h)"
            case .cooldown429(let next): return "vault:429-cooldown(next:\(next)min)"
            case .unreachable: return "vault:UNREACHABLE"
            case .unknownUnprobed(let h): return "vault:\(h)(unprobed)"
            }
        }()
        let sync: String = {
            switch s.sync {
            case .recent(let s): return "sync:\(s)s"
            case .stale(let s): return "sync:STALE(\(s)s)"
            case .never: return "sync:never"
            }
        }()
        var line = "\(glyph) \(brokerd) \(cache) \(vault) \(sync)"
        // Append actionable hint if any RED.
        if case .pidRunningButSocketUnbound = s.brokerd {
            line += " — pid running but socket unbound; run shi secrets doctor --fix"
        } else if case .multiplePidsRunning = s.brokerd {
            line += " — dual brokerd; run shi secrets doctor --fix"
        } else if case .downNotLoaded = s.brokerd {
            line += " — run shi secrets login"
        }
        return line
    }

    /// JSON shape for --json flag (machine readable).
    public static func renderJSON(_ s: StatusSnapshot) -> String {
        struct Out: Encodable {
            let brokerd: String
            let cache: String
            let vault: String
            let sync: String
            let overall: String
        }
        let out = Out(
            brokerd: describe(s.brokerd),
            cache: describe(s.cache),
            vault: describe(s.vault),
            sync: describe(s.sync),
            overall: s.overall.rawValue
        )
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return (try? String(data: enc.encode(out), encoding: .utf8)) ?? "{}"
    }

    private static func describe(_ b: BrokerdHealth) -> String {
        switch b {
        case .up(let p): return "up:\(p)"
        case .downNotLoaded: return "down"
        case .multiplePidsRunning(let pids): return "duped:\(pids.count)"
        case .pidRunningButSocketUnbound(let p): return "no-socket:\(p)"
        }
    }
    private static func describe(_ c: CacheHealth) -> String {
        switch c {
        case .valid(let m): return "valid:\(m)m"
        case .expired: return "expired"
        case .absent: return "absent"
        }
    }
    private static func describe(_ v: VaultHealth) -> String {
        switch v {
        case .reachable(let h): return "reachable:\(h)"
        case .cooldown429(let m): return "429:\(m)m"
        case .unreachable: return "unreachable"
        case .unknownUnprobed(let h): return "unprobed:\(h)"
        }
    }
    private static func describe(_ s: SyncHealth) -> String {
        switch s {
        case .recent(let s): return "recent:\(s)s"
        case .stale(let s): return "stale:\(s)s"
        case .never: return "never"
        }
    }
}
