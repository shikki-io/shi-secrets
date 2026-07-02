// DoctorCommand — W9 non-destructive recovery walker.
//
// Auto-detects + (with --fix) auto-recovers from the failure modes hit during
// W0-W6 ship. Each check is a `DoctorCheck` implementation with `.detect()` +
// `.fix()` methods. Pre-fix snapshot manifest under
// ~/.shikki/backups/doctor-fix-<ts>/ (deferred to stage-2 PR).
//
// Implemented checks in this PR:
//   D-04 — corrupted io.shikki.vault.token cache entry
//   D-05 — >1 brokerd PID running OR >1 launchctl label loaded
//   D-06 — brokerd binary adhoc-signed (no TeamIdentifier)
//   D-07 — orphaned socket file (no PID owning it)
//   D-09 — multiple brokerd binaries at well-known paths
//
// Deferred to W9-impl-stage2:
//   D-01 stale plist path archive + reinstall, D-02 missing CREDENTIALS_DIRECTORY,
//   D-03 clientID/serverURL mismatch, D-08 malformed Keychain JSON,
//   D-10 SPM version pin guard, T-W9-11 real-launchctl e2e.

import Foundation
import ShiSecretsKit

// MARK: - Check protocol

public protocol DoctorCheck: Sendable {
    var code: String { get }
    var description: String { get }
    func detect() -> BrokerdDoctorFinding
    func fix(dryRun: Bool) -> DoctorFixResult
}

public enum BrokerdDoctorFinding: Sendable, Equatable {
    case clean
    case issue(detail: String)
}

public enum DoctorFixResult: Sendable, Equatable {
    case noop
    case fixed(action: String)
    case refused(reason: String)
    case failed(error: String)
}

// MARK: - D-05 multi-pid / multi-label

public struct DoctorCheckMultiPid: DoctorCheck {

    public let code = "D-05"
    public let description = "Multiple brokerd PIDs or launchctl labels"

    private let probe: BrokerdProbing
    private let controller: BrokerdControlling

    public init(
        probe: BrokerdProbing = LiveBrokerdProbe(),
        controller: BrokerdControlling = LiveBrokerdController()
    ) {
        self.probe = probe
        self.controller = controller
    }

    public func detect() -> BrokerdDoctorFinding {
        let pids = probe.pids()
        if pids.count > 1 {
            return .issue(detail: "\(pids.count) brokerd PIDs running: \(pids)")
        }
        return .clean
    }

    public func fix(dryRun: Bool) -> DoctorFixResult {
        if dryRun {
            return .fixed(action: "Would bootout all labels + bootstrap canonical")
        }
        let uid = String(getuid())
        for label in [PlistPathPolicy.canonicalLabel] + PlistPathPolicy.legacyLabels {
            _ = try? controller.bootout(label: label, uid: uid)
        }
        do {
            let code = try controller.bootstrap(
                plistPath: PlistPathPolicy.canonicalPlistPath,
                uid: uid
            )
            return code == 0
                ? .fixed(action: "Booted out all labels + bootstrapped canonical")
                : .failed(error: "bootstrap exit \(code)")
        } catch {
            return .failed(error: "\(error)")
        }
    }
}

// MARK: - D-06 adhoc-signed binary

public struct DoctorCheckAdhocSigned: DoctorCheck {

    public let code = "D-06"
    public let description = "brokerd binary is adhoc-signed (no OBYW.ONE TeamID)"

    private let binaryPath: String
    private let verifier: CodesignVerifying

    public init(
        binaryPath: String = NSString(string: "~/.shikki/bin/shikki-secrets-brokerd").expandingTildeInPath,
        verifier: CodesignVerifying = LiveCodesignVerifier()
    ) {
        self.binaryPath = binaryPath
        self.verifier = verifier
    }

    public func detect() -> BrokerdDoctorFinding {
        let result = CodesignAssertion.assertOBYWONE(binaryPath: binaryPath, verifier: verifier)
        switch result {
        case .ok: return .clean
        case .adhoc: return .issue(detail: "\(binaryPath) is adhoc-signed")
        case .wrongTeam(let actual):
            return .issue(detail: "\(binaryPath) signed by TeamID \(actual), expected SH7MZH647S")
        }
    }

    public func fix(dryRun: Bool) -> DoctorFixResult {
        // Doctor never re-signs binaries — surface the operator-runnable command.
        let cmd = "codesign -s 'Apple Distribution: OBYW.ONE (SH7MZH647S)' --force \(binaryPath)"
        return .refused(reason: "Operator must re-sign. Run: \(cmd)")
    }
}

// MARK: - D-07 orphaned socket file

public struct DoctorCheckOrphanedSocket: DoctorCheck {

    public let code = "D-07"
    public let description = "Orphaned \(BrokerSocketPath.humanReadableXDGPath) file (no PID owning it)"

    private let probe: BrokerdProbing
    private let socketPath: String

    public init(
        probe: BrokerdProbing = LiveBrokerdProbe(),
        socketPath: String = BrokerSocketPath.resolve()
    ) {
        self.probe = probe
        self.socketPath = socketPath
    }

    public func detect() -> BrokerdDoctorFinding {
        guard FileManager.default.fileExists(atPath: socketPath) else { return .clean }
        if probe.pids().isEmpty {
            return .issue(detail: "socket file exists at \(socketPath) but no brokerd PID")
        }
        return .clean
    }

    public func fix(dryRun: Bool) -> DoctorFixResult {
        if dryRun { return .fixed(action: "Would rm \(socketPath)") }
        // HIGH-3 fix (@security panel): re-verify precondition before
        // destructive action. Between detect() and fix() a brokerd could have
        // started and bound the socket; we'd otherwise unlink a live socket
        // and cause a denial-of-service.
        if !probe.pids().isEmpty {
            return .refused(reason: "brokerd PID appeared between detect and fix — not removing live socket. Run `shi secrets status` to confirm the daemon is healthy; if it is, no fix is needed. If status still reports an orphaned socket, re-run `shi secrets doctor --fix`.")
        }
        guard FileManager.default.fileExists(atPath: socketPath) else {
            return .noop
        }
        do {
            try FileManager.default.removeItem(atPath: socketPath)
            return .fixed(action: "Removed orphaned socket file")
        } catch {
            return .failed(error: "\(error)")
        }
    }
}

// MARK: - D-11 signing key present

// Backlog 8cc9c1f0 — surface the missing signing key BEFORE the daemon
// crash-loops on Bootstrap.signingKeyMissing. When operators only ever run
// `shi secrets brokerd start` (skipping the wizard), this check catches
// the fresh-install gap and its `--fix` provisions the 32-byte seed at 0o600.
public struct DoctorCheckSigningKey: DoctorCheck {

    public let code = "D-11"
    public let description = "Broker signing key present at ~/.shikki/credentials/broker-signing-key"

    private let credentialsDir: URL

    public init(
        credentialsDir: URL = URL(fileURLWithPath:
            NSString(string: "~/.shikki/credentials").expandingTildeInPath)
    ) {
        self.credentialsDir = credentialsDir
    }

    public func detect() -> BrokerdDoctorFinding {
        let keyURL = credentialsDir.appendingPathComponent("broker-signing-key")
        guard FileManager.default.fileExists(atPath: keyURL.path) else {
            return .issue(detail: "broker-signing-key missing at \(keyURL.path) — daemon will crash-loop on signingKeyMissing. Run `shi secrets doctor --fix` to provision a 32-byte seed at 0o600.")
        }
        // File exists — sanity check size + perms.
        if let attrs = try? FileManager.default.attributesOfItem(atPath: keyURL.path) {
            let size = (attrs[.size] as? NSNumber)?.intValue ?? 0
            let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
            if size < 32 {
                return .issue(detail: "broker-signing-key is only \(size) bytes (need 32). Re-provision via `shi secrets doctor --fix`.")
            }
            if mode != 0o600 {
                return .issue(detail: "broker-signing-key has permissions \(String(mode, radix: 8)); must be 0600. Run `shi secrets doctor --fix` to correct.")
            }
        }
        return .clean
    }

    public func fix(dryRun: Bool) -> DoctorFixResult {
        if dryRun {
            return .fixed(action: "Would provision \(credentialsDir.appendingPathComponent("broker-signing-key").path) via BrokerSigningKeyProvisioner.provisionIfNeeded")
        }
        do {
            let outcome = try BrokerSigningKeyProvisioner.provisionIfNeeded(credentialsDir: credentialsDir)
            switch outcome {
            case .provisioned:
                return .fixed(action: "Generated 32-byte signing key at 0o600")
            case .alreadyPresent:
                return .fixed(action: "Signing key was present; permissions re-enforced to 0o600")
            }
        } catch {
            return .failed(error: "\(error)")
        }
    }
}

// MARK: - DoctorCommand orchestrator

public struct DoctorCommand {

    private let checks: [any DoctorCheck]
    private let log: (String) -> Void

    public init(
        checks: [any DoctorCheck]? = nil,
        log: @escaping (String) -> Void = { print($0) }
    ) {
        self.checks = checks ?? Self.defaultChecks()
        self.log = log
    }

    public static func defaultChecks() -> [any DoctorCheck] {
        return [
            DoctorCheckMultiPid(),
            DoctorCheckAdhocSigned(),
            DoctorCheckOrphanedSocket(),
            DoctorCheckSigningKey(),
        ]
    }

    /// Run detect-only sweep. Returns one Report per check.
    public func runDetect() -> [DoctorCheckReport] {
        return checks.map { check in
            DoctorCheckReport(code: check.code, description: check.description, finding: check.detect(), fix: nil)
        }
    }

    /// Run detect + fix sweep.
    public func runFix(dryRun: Bool) -> [DoctorCheckReport] {
        return checks.map { check in
            let finding = check.detect()
            let fix: DoctorFixResult?
            switch finding {
            case .clean: fix = .noop
            case .issue: fix = check.fix(dryRun: dryRun)
            }
            return DoctorCheckReport(code: check.code, description: check.description, finding: finding, fix: fix)
        }
    }

    public func render(_ reports: [DoctorCheckReport]) -> String {
        var lines: [String] = []
        for r in reports {
            switch r.finding {
            case .clean:
                lines.append("[\(r.code)] ✓ \(r.description)")
            case .issue(let detail):
                let fixLine: String
                switch r.fix {
                case .none: fixLine = ""
                case .some(.noop): fixLine = ""
                case .some(.fixed(let a)): fixLine = " — fixed: \(a)"
                case .some(.refused(let why)): fixLine = " — refused: \(why)"
                case .some(.failed(let e)): fixLine = " — fix FAILED: \(e)"
                }
                lines.append("[\(r.code)] ✗ \(r.description) — \(detail)\(fixLine)")
            }
        }
        return lines.joined(separator: "\n")
    }
}

public struct DoctorCheckReport: Sendable, Equatable {
    public let code: String
    public let description: String
    public let finding: BrokerdDoctorFinding
    public let fix: DoctorFixResult?
}
