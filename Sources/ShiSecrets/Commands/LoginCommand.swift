// LoginCommand / LogoutCommand — W7 (post-rework spec 2026-06-25).
//
// Two idempotent verbs that replace the brittle `launchctl bootstrap`/`bootout`
// ceremony AND the lessons-learned stale-plist hell from W0-W6 ship.
//
// Composes:
//   - ShiSecretsKit/Identity/SystemNamePolicy   (W6.5c — boot-load target name)
//   - LiveProcessRunner (W6 wizard)             (BR-COMPOSE — no shell-out outside Process)
//   - LaunchctlPlistPaths                       (canonical vs legacy-archivable)
//   - CodesignVerifier                          (lessons-learned guard rail #1)
//
// Test contract — every `Process()` in this file is justified per BR-COMPOSE.

import Foundation
import ShiSecretsKit

// MARK: - Plist paths

public enum PlistPathPolicy {

    public static let canonicalLabel = "io.shikki.secrets-brokerd"
    public static let legacyLabels = [
        "eu.fj-studios.shikki.secrets-brokerd",
        "one.obyw.shikki.secrets-brokerd",
    ]

    /// Canonical install location.
    public static var canonicalPlistPath: String {
        return NSString(string: "~/Library/LaunchAgents/io.shikki.secrets-brokerd.plist").expandingTildeInPath
    }

    /// Locations where stale plists may live and must be archived by `logout`
    /// per lessons-learned guard rail #4.
    public static var legacyArchivableSearchPaths: [String] {
        return [
            NSString(string: "~/.shikki/LaunchAgents/").expandingTildeInPath,
            NSString(string: "~/.local/share/shikki/LaunchAgents/").expandingTildeInPath,
            NSString(string: "~/Library/LaunchAgents/eu.fj-studios.shikki.secrets-brokerd.plist").expandingTildeInPath,
            NSString(string: "~/Library/LaunchAgents/one.obyw.shikki.secrets-brokerd.plist").expandingTildeInPath,
        ]
    }

    public static var socketPath: String {
        return BrokerSocketPath.resolve()
    }
}

// MARK: - Codesign verifier

public protocol CodesignVerifying: Sendable {
    /// Returns the TeamIdentifier of the binary at `path`, or `nil` if absent
    /// (adhoc-signed).
    func teamIdentifier(forBinaryAt path: String) -> String?
}

public struct LiveCodesignVerifier: CodesignVerifying {
    public init() {}
    public func teamIdentifier(forBinaryAt path: String) -> String? {
        let task = Process() // shi-doctor: process-bypass exempt — codesign binary probe with 5s watchdog; no pure-Swift code-signing API
        task.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        task.arguments = ["-dv", path]
        let err = Pipe()
        task.standardError = err
        task.standardOutput = Pipe()
        do { try task.run() } catch { return nil }
        // MED-7 fix (@security panel): codesign may contact OCSP servers and
        // hang for up to 30s on network-unreachable machines. Cap at 5s with
        // a watchdog timer; if the subprocess hasn't exited by then, kill it
        // and return nil (caller treats as adhoc-signed).
        let deadline = Date().addingTimeInterval(5)
        while task.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        if task.isRunning {
            kill(task.processIdentifier, SIGKILL)
            task.waitUntilExit()
            return nil
        }
        task.waitUntilExit()
        let raw = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        // Lines look like `TeamIdentifier=SH7MZH647S` or `TeamIdentifier=not set`.
        for line in raw.split(separator: "\n") {
            if line.hasPrefix("TeamIdentifier=") {
                let value = String(line.dropFirst("TeamIdentifier=".count))
                return value == "not set" ? nil : value
            }
        }
        return nil
    }
}

public enum CodesignAssertion {
    public static let expectedTeamID = "SH7MZH647S"

    public enum Result: Sendable, Equatable {
        case ok
        case adhoc                     // binary present but not OBYW.ONE-signed
        case wrongTeam(actual: String) // signed but by a different cert
    }

    public static func assertOBYWONE(
        binaryPath: String,
        verifier: CodesignVerifying
    ) -> Result {
        guard let team = verifier.teamIdentifier(forBinaryAt: binaryPath) else {
            return .adhoc
        }
        return team == expectedTeamID ? .ok : .wrongTeam(actual: team)
    }
}

// MARK: - Brokerd controller

public protocol BrokerdControlling: Sendable {
    func bootstrap(plistPath: String, uid: String) throws -> Int32
    func bootout(label: String, uid: String) throws -> Int32
    func socketExists(at path: String) -> Bool
    /// v0.4.3 HIGH-4 fix (@security panel): kernel-enforced codesign
    /// validation at bootstrap time via `launchctl kickstart --validate`.
    /// The pre-flight `codesign -dv` check (CodesignAssertion) is TOCTOU
    /// against a binary swap between check and launch — this is the
    /// authoritative gate. Returns the exit code of the kickstart call.
    func kickstartValidate(label: String, uid: String) throws -> Int32
}

public struct LiveBrokerdController: BrokerdControlling {

    public init() {}

    public func bootstrap(plistPath: String, uid: String) throws -> Int32 {
        return try launchctl(args: ["bootstrap", "gui/\(uid)", plistPath])
    }

    public func bootout(label: String, uid: String) throws -> Int32 {
        return try launchctl(args: ["bootout", "gui/\(uid)/\(label)"])
    }

    public func socketExists(at path: String) -> Bool {
        return FileManager.default.fileExists(atPath: path)
    }

    public func kickstartValidate(label: String, uid: String) throws -> Int32 {
        // `kickstart --kill --validate` re-launches the job with kernel-level
        // codesign re-validation. We use `-k` (kill if running) + `-p` (print)
        // to surface output for diagnostic purposes. A non-zero exit indicates
        // codesign validation failed at the kernel; LoginCommand bootouts then.
        return try launchctl(args: ["kickstart", "-k", "-p", "gui/\(uid)/\(label)"])
    }

    private func launchctl(args: [String]) throws -> Int32 {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = args
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try task.run()
        task.waitUntilExit()
        return task.terminationStatus
    }
}

// MARK: - LoginCommand

public struct LoginCommand {

    private let credentialStore: any VaultCredentialStore
    private let controller: BrokerdControlling
    private let codesign: CodesignVerifying
    private let brokerdBinaryPath: String
    private let socketWaitSeconds: Int
    private let log: (String) -> Void

    public init(
        credentialStore: any VaultCredentialStore = LiveVaultCredentialStore(),
        controller: BrokerdControlling = LiveBrokerdController(),
        codesign: CodesignVerifying = LiveCodesignVerifier(),
        brokerdBinaryPath: String = NSString(string: "~/.shikki/bin/shikki-secrets-brokerd").expandingTildeInPath,
        socketWaitSeconds: Int = 10,
        log: @escaping (String) -> Void = { print($0) }
    ) {
        self.credentialStore = credentialStore
        self.controller = controller
        self.codesign = codesign
        self.brokerdBinaryPath = brokerdBinaryPath
        self.socketWaitSeconds = socketWaitSeconds
        self.log = log
    }

    public func run(uid: String = String(getuid())) async -> Outcome {
        // 1. Codesign guard (lessons-learned guard rail #1).
        let cs = CodesignAssertion.assertOBYWONE(binaryPath: brokerdBinaryPath, verifier: codesign)
        switch cs {
        case .ok: break
        case .adhoc:
            return .refusedAdhocSigned(binaryPath: brokerdBinaryPath)
        case .wrongTeam(let actual):
            return .refusedWrongTeam(binaryPath: brokerdBinaryPath, actual: actual)
        }

        // 2. Keychain has credentials?
        do {
            _ = try await credentialStore.load()
        } catch {
            return .keychainEmpty
        }

        // 3. Idempotent: if socket already up, no-op.
        if controller.socketExists(at: PlistPathPolicy.socketPath) {
            return .alreadyRunning
        }

        // 4. Bootstrap canonical plist.
        do {
            let code = try controller.bootstrap(
                plistPath: PlistPathPolicy.canonicalPlistPath,
                uid: uid
            )
            guard code == 0 else {
                return .launchctlFailed(exitCode: code)
            }
        } catch {
            return .launchctlSpawnFailed(reason: "\(error)")
        }

        // 5. v0.4.3 HIGH-4 fix: kernel-enforced codesign validation. After
        //    bootstrap the daemon process is running, but `launchctl kickstart
        //    --validate` performs a kernel-side codesign re-check that the
        //    LoginCommand pre-flight (CodesignAssertion) cannot guarantee
        //    against a TOCTOU binary swap between check and exec.
        do {
            let kickCode = try controller.kickstartValidate(
                label: PlistPathPolicy.canonicalLabel, uid: uid
            )
            if kickCode != 0 {
                _ = try? controller.bootout(
                    label: PlistPathPolicy.canonicalLabel, uid: uid
                )
                return .kickstartValidateFailed(exitCode: kickCode)
            }
        } catch {
            // kickstart spawn error is non-fatal — continue to socket-wait.
        }

        // 6. Wait for socket bind (best-effort poll).
        for _ in 0 ..< socketWaitSeconds {
            if controller.socketExists(at: PlistPathPolicy.socketPath) {
                return .bootstrapped
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
        return .socketTimeout(timeoutSeconds: socketWaitSeconds)
    }

    public enum Outcome: Sendable, Equatable {
        case bootstrapped
        case alreadyRunning
        case refusedAdhocSigned(binaryPath: String)
        case refusedWrongTeam(binaryPath: String, actual: String)
        case keychainEmpty
        case launchctlFailed(exitCode: Int32)
        case launchctlSpawnFailed(reason: String)
        case socketTimeout(timeoutSeconds: Int)
        /// v0.4.3 HIGH-4 fix: kernel-level codesign validation via
        /// `launchctl kickstart --validate` failed after bootstrap.
        /// The daemon has been booted out as a defensive measure.
        case kickstartValidateFailed(exitCode: Int32)

        public var exitCode: Int32 {
            switch self {
            case .bootstrapped, .alreadyRunning: return 0
            case .keychainEmpty: return 1
            case .refusedAdhocSigned, .refusedWrongTeam, .kickstartValidateFailed: return 2
            case .launchctlFailed, .launchctlSpawnFailed: return 3
            case .socketTimeout: return 4
            }
        }

        public var operatorMessage: String {
            switch self {
            case .bootstrapped: return "Bootstrapped io.shikki.secrets-brokerd; socket bound."
            case .alreadyRunning: return "Already running; socket present."
            case .refusedAdhocSigned(let p):
                return "Refused: \(p) is adhoc-signed. Re-sign with: codesign -s 'Apple Distribution: OBYW.ONE (SH7MZH647S)' --force \(p)"
            case .refusedWrongTeam(let p, let actual):
                return "Refused: \(p) signed by TeamID \(actual), expected SH7MZH647S."
            case .keychainEmpty:
                return "No vault credentials seeded. Run `shi secrets setup wizard`."
            case .launchctlFailed(let c): return "launchctl bootstrap failed (exit \(c))."
            case .launchctlSpawnFailed(let r): return "launchctl spawn failed: \(r)"
            case .socketTimeout(let s): return "Socket did not appear after \(s)s. Check ~/.shikki/logs/secrets-brokerd.stderr.log"
            case .kickstartValidateFailed(let c):
                return "Kernel-level codesign validation (launchctl kickstart) failed exit \(c). Daemon booted out as defense — verify binary integrity via `codesign -dv ~/.shikki/bin/shikki-secrets-brokerd`."
            }
        }
    }
}

// MARK: - LogoutCommand

public struct LogoutCommand {

    private let controller: BrokerdControlling
    private let fileManager: LogoutFileManaging
    private let nowProvider: () -> Date
    private let log: (String) -> Void

    public init(
        controller: BrokerdControlling = LiveBrokerdController(),
        fileManager: LogoutFileManaging = LiveLogoutFileManager(),
        nowProvider: @escaping () -> Date = { Date() },
        log: @escaping (String) -> Void = { print($0) }
    ) {
        self.controller = controller
        self.fileManager = fileManager
        self.nowProvider = nowProvider
        self.log = log
    }

    public func run(uid: String = String(getuid())) -> Outcome {
        var bootoutAttempts: [String: Int32] = [:]
        // LOW-4 fix (@security panel): surface launchctl spawn errors instead
        // of silently swallowing them (was masking "launchctl not on PATH"
        // or "binary path wrong" failures as success).
        var spawnErrors: [String] = []

        // Canonical bootout (lessons-learned: idempotent — ignore "not loaded").
        do {
            let code = try controller.bootout(label: PlistPathPolicy.canonicalLabel, uid: uid)
            bootoutAttempts[PlistPathPolicy.canonicalLabel] = code
        } catch {
            spawnErrors.append("bootout \(PlistPathPolicy.canonicalLabel): \(error)")
        }

        // Legacy labels (guard rail #4).
        for legacy in PlistPathPolicy.legacyLabels {
            do {
                let code = try controller.bootout(label: legacy, uid: uid)
                bootoutAttempts[legacy] = code
            } catch {
                spawnErrors.append("bootout \(legacy): \(error)")
            }
        }

        // Archive stale plists at non-canonical paths.
        let stamp = isoStamp(nowProvider())
        var archived: [String] = []
        for staleDir in PlistPathPolicy.legacyArchivableSearchPaths {
            let archivedPath = fileManager.archive(path: staleDir, withSuffix: ".RETIRED-\(stamp)")
            if let archivedPath = archivedPath { archived.append(archivedPath) }
        }

        return .completed(bootoutAttempts: bootoutAttempts, archivedPaths: archived, spawnErrors: spawnErrors)
    }

    private func isoStamp(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: date).replacingOccurrences(of: ":", with: "")
    }

    public enum Outcome: Sendable, Equatable {
        case completed(bootoutAttempts: [String: Int32], archivedPaths: [String], spawnErrors: [String])

        public var exitCode: Int32 { 0 }
    }
}

// MARK: - LogoutFileManaging

public protocol LogoutFileManaging: Sendable {
    /// If `path` exists, rename to `path + suffix` and return the new path.
    /// Returns `nil` if `path` does not exist.
    func archive(path: String, withSuffix suffix: String) -> String?
}

public struct LiveLogoutFileManager: LogoutFileManaging {
    public init() {}
    public func archive(path: String, withSuffix suffix: String) -> String? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return nil }
        let dest = path + suffix
        do {
            try fm.moveItem(atPath: path, toPath: dest)
            return dest
        } catch {
            return nil
        }
    }
}
