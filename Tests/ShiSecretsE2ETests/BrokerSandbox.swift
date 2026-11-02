import CoreKitTestSupport
import Foundation
import ShellKit

// BrokerSandbox — the one shared setup for every broker-process E2E test
// (review of shi-secrets#53: "refactorize it in one method", "be DRY").
//
// Paths: the sandbox directory comes from CoreKitTestSupport.TestScratch, the
// fleet's test-path SSoT (`<package>/.tests/.test-runs/<run>/<scope>/<uuid>`).
// It is the broker's HOME and holds the custody file, so no test touches the
// operator's real home.
//
// Sockets are the one exception: a Unix-domain socket path is limited to 104
// bytes on macOS (`sun_path`), and the scratch directory alone is longer than
// that inside a worktree. Sockets therefore stay at a short `/tmp/sh-e-*.s`
// path (E2ESupport.socketPath()) and are removed in `cleanUp()`.
//
// Subprocesses: ShellKit's DetachedProcess (process group, SIGTERM/SIGKILL
// escalation) — never a raw Process.

final class BrokerSandbox: @unchecked Sendable {

    private static let scratch = TestScratch.forPackage()

    /// Scratch directory: the broker's HOME and the custody-file location.
    let directory: URL
    private var socketPaths: [String] = []

    init(scope: String = "broker-e2e") throws {
        self.directory = try Self.scratch.makeScratchDir(scope: scope)
    }

    var home: String { directory.path }

    var custodyFile: String { directory.appendingPathComponent("vault.key").path }

    /// A fresh short socket path (see the 104-byte limit above).
    func makeSocketPath() -> String {
        let path = E2ESupport.socketPath()
        socketPaths.append(path)
        return path
    }

    /// The broker environment every E2E suite used to spell out by hand.
    func brokerEnvironment(
        clientID: String,
        clientSecret: String,
        vaultPort: Int,
        socketPath: String? = nil
    ) -> [String: String] {
        var env: [String: String] = [
            "SHIKKI_E2E_CLIENT_ID":     clientID,
            "SHIKKI_E2E_CLIENT_SECRET": clientSecret,
            "SHIKKI_E2E_VAULT_URL":     "http://127.0.0.1:\(vaultPort)",
            "SHIKKI_E2E_CUSTODY_FILE":  custodyFile,
            "HOME":                     home,
            "PATH":                     "/usr/bin:/bin:/usr/local/bin",
        ]
        if let socketPath { env["SHIKKI_BROKER_SOCKET"] = socketPath }
        return env
    }

    /// Launch the broker in `--dry-run` mode on `socketPath`.
    func launchBroker(
        binaryPath: String,
        socketPath: String,
        environment: [String: String]
    ) throws -> DetachedProcess {
        try DetachedProcess(
            [binaryPath, "--dry-run", "--socket", socketPath],
            environment: environment,
            output: .discard
        )
    }

    func cleanUp() {
        for path in socketPaths { try? FileManager.default.removeItem(atPath: path) }
        try? Self.scratch.removeScratchDir(directory)
    }
}
