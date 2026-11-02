// SecretsBrokerdCommand — `shi secrets brokerd <start|stop|status>`
//
// Bug 3 fix: v0.1.0 had `brokerd start` attempting `swift build --product
// shikki-secrets-brokerd` which always failed ("no product named") because the
// product doesn't exist inside the plugin's standalone SPM package.
//
// CORRECT behavior (production):
//   start  — check ~/.shikki/bin/shikki-secrets-brokerd; if present, load the
//             launchd plist via `launchctl load -w <plist>`. NEVER call swift build.
//             If the binary is missing, surface "binary missing — reinstall via
//             `shi pickup shi-secrets`" and exit 1.
//   stop   — `launchctl unload -w <plist>`
//   status — `launchctl list io.shikki.secrets-brokerd`
//
// Canonical label: io.shikki.secrets-brokerd (product domain, operator mandate 2026-06-24).
// Supersedes: eu.fj-studios.shikki.secrets-brokerd (deprecated org-namespace label).
//
// The plist path is:
//   ~/.shikki/LaunchAgents/io.shikki.secrets-brokerd.plist   (macOS, W3 canonical)
//   ~/.config/systemd/user/shikki-secrets-brokerd.service    (Linux)
//
// NEVER call `swift build` — that is a dev-pipeline concern. The pre-built
// binary is installed by `shi pickup shi-secrets` into ~/.shikki/bin/.

import Foundation

public struct SecretsBrokerdCommand {

    public let action: String

    public init(action: String) {
        self.action = action
    }

    // MARK: - Constants

    private var binaryPath: String {
        "\(NSHomeDirectory())/.shikki/bin/shikki-secrets-brokerd"
    }

    private var plistPath: String {
        // W3 mandate 2026-06-24: canonical plist is now at ~/.shikki/LaunchAgents/ (not ~/Library/LaunchAgents/).
        // Label: io.shikki.secrets-brokerd (product domain). Supersedes eu.fj-studios.shikki.secrets-brokerd.
        "\(NSHomeDirectory())/.shikki/LaunchAgents/io.shikki.secrets-brokerd.plist"
    }

    private static let plistLabel = "io.shikki.secrets-brokerd"

    // MARK: - run()

    public func run() async throws -> Int32 {
        switch action {
        case "start":
            return runStart()
        case "stop":
            return runStop()
        case "status":
            return runStatus()
        default:
            fputs("Unknown brokerd action: \(action). Try: start, stop, status\n", stderr)
            return 1
        }
    }

    // MARK: - start

    private func runStart() -> Int32 {
        // NEVER call swift build — that's the dev-pipeline, not production.
        // Binary must have been installed by `shi pickup shi-secrets`.
        guard FileManager.default.fileExists(atPath: binaryPath) else {
            fputs(
                """
                ERROR: shikki-secrets-brokerd binary not found at \(binaryPath)
                Reinstall via: shi pickup shi-secrets
                (Do NOT attempt `swift build` — the pre-built binary ships via shi pickup.)
                """,
                stderr
            )
            return 1
        }

        guard FileManager.default.fileExists(atPath: plistPath) else {
            fputs(
                """
                ERROR: launchd plist not found at \(plistPath)
                Run `shi secrets setup install` first to register the daemon.
                """,
                stderr
            )
            return 1
        }

        let result = shell("launchctl", "load", "-w", plistPath)
        if result == 0 {
            print("shikki-secrets-brokerd started (launchd plist loaded).")
        } else {
            fputs("ERROR: launchctl load failed (exit \(result)). Check Console.app for details.\n", stderr)
        }
        return result
    }

    // MARK: - stop

    private func runStop() -> Int32 {
        guard FileManager.default.fileExists(atPath: plistPath) else {
            fputs("ERROR: launchd plist not found at \(plistPath). Nothing to stop.\n", stderr)
            return 1
        }
        let result = shell("launchctl", "unload", "-w", plistPath)
        if result == 0 {
            print("shikki-secrets-brokerd stopped.")
        } else {
            fputs("ERROR: launchctl unload failed (exit \(result)).\n", stderr)
        }
        return result
    }

    // MARK: - status

    private func runStatus() -> Int32 {
        let result = shell("launchctl", "list", Self.plistLabel)
        // launchctl list exits 0 if job is loaded (running or stopped),
        // non-zero if not known to launchd.
        if result != 0 {
            fputs("shikki-secrets-brokerd is NOT loaded in launchd.\n", stderr)
            fputs("Run `shi secrets brokerd start` to start it.\n", stderr)
        }
        return result
    }

    // MARK: - Helpers

    /// Runs a shell command with a timeout (default 30s) and returns its exit code.
    /// QG-fix: wraps Process() in a Task with timeout watchdog instead of bare
    /// waitUntilExit() (which can block indefinitely).
    @discardableResult
    private func shell(_ args: String..., timeoutSeconds: TimeInterval = 30) -> Int32 {
        let proc = Process() // shi-doctor: process-bypass exempt — manual deadline-poll watchdog for launchctl/env; no TimedShell equivalent for system daemon management
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = Array(args)
        do {
            try proc.run()
        } catch {
            fputs("ERROR: Failed to start \(args.joined(separator: " ")): \(error)\n", stderr)
            return 127
        }
        // Timeout watchdog via a background thread — avoids indefinite block.
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while proc.isRunning {
            if Date() > deadline {
                proc.terminate()
                fputs("ERROR: \(args.joined(separator: " ")) timed out after \(Int(timeoutSeconds))s\n", stderr)
                return 1
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        return proc.terminationStatus
    }
}
