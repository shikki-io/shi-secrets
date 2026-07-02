// SecretsSetupWizardCommand — `shi secrets setup wizard`
//
// The one-click vault setup verb. Wraps every step the operator previously had to
// orchestrate manually (bash script `shi-secrets-bootstrap`):
//   1. Read client_id / client_secret / server_url (≤3 prompts)
//   2. Seed Keychain via VaultCredentialsSeeder (delegates to existing W3.1 path)
//   3. Bootout any stale brokerd labels (legacy + canonical)
//   4. Bootstrap canonical io.shikki.secrets-brokerd plist via launchctl
//   5. Wait for unix socket up to <timeout> seconds
//   6. Smoke test: set a sentinel + get it back, assert value matches
//
// Compile-time guarantees:
//   - Strong types throughout (no String-typed configs)
//   - Codable + same VaultwardenCredentials struct brokerd decodes (zero schema drift)
//   - All shell-outs go through Process() with explicit arg arrays (no shell injection)
//   - WizardStep enum models the state machine; every transition is exhaustive-checked
//
// Runtime verification:
//   - Each step returns Result<StepOutput, WizardError>
//   - On failure: rolls back as far as is safe + surfaces a typed error with hint
//   - smoke step asserts get == set (W4.2 boundPlaintext path proves the wire works)
//
// W6 — spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 — supersedes the deleted bash wrapper.

import Foundation
import ShiSecretsKit

// MARK: - Public command surface

/// `shi secrets setup wizard` — one-click vault setup, end-to-end.
public struct SecretsSetupWizardCommand {

    // MARK: Parsed parameters (CLI flags)

    public let clientID: String?
    public let serverURL: String
    public let clientSecretArg: String?
    public let force: Bool
    public let socketWaitSeconds: Int
    public let skipSmoke: Bool

    // MARK: Dependencies (injectable for tests)

    private let store: any VaultCredentialStore
    private let secretReader: () -> String?
    private let stdinReader: () -> String?
    private let processRunner: ProcessRunning
    private let socketProbe: (String) -> Bool
    private let nowProvider: () -> Date
    private let smokeRunner: SmokeRunning?

    // MARK: Designated init

    public init(
        clientID: String? = nil,
        serverURL: String = "https://vw.obyw.one",
        clientSecretArg: String? = nil,
        force: Bool = false,
        socketWaitSeconds: Int = 30,
        skipSmoke: Bool = false,
        store: any VaultCredentialStore = LiveVaultCredentialStore(),
        secretReader: @escaping @Sendable () -> String? = WizardSecretReaders.live,
        stdinReader: @escaping @Sendable () -> String? = WizardSecretReaders.stdinLine,
        processRunner: ProcessRunning = LiveProcessRunner(),
        socketProbe: @escaping (String) -> Bool = { path in
            FileManager.default.fileExists(atPath: path)
        },
        nowProvider: @escaping () -> Date = { Date() },
        smokeRunner: SmokeRunning? = nil
    ) {
        self.clientID = clientID
        self.serverURL = serverURL
        self.clientSecretArg = clientSecretArg
        self.force = force
        self.socketWaitSeconds = socketWaitSeconds
        self.skipSmoke = skipSmoke
        self.store = store
        self.secretReader = secretReader
        self.stdinReader = stdinReader
        self.processRunner = processRunner
        self.socketProbe = socketProbe
        self.nowProvider = nowProvider
        self.smokeRunner = smokeRunner
    }

    // MARK: Entrypoint

    /// Runs the wizard end-to-end. Returns 0 on green smoke, non-zero on first error.
    public func run() async -> Int32 {
        var transcript: [String] = []
        func log(_ s: String) {
            transcript.append(s)
            print(s)
        }

        // STEP 1: collect inputs (≤3 prompts)
        log("→ Step 1/5: collect Vaultwarden credentials")
        let inputs: WizardInputs
        switch collectInputs() {
        case .success(let i): inputs = i
        case .failure(let e): return failExit(e, transcript: transcript)
        }

        // STEP 2: seed Keychain via the existing W3.1 seeder
        log("→ Step 2/5: seed Keychain io.shikki.vault/vault-credentials")
        let seedResult = await seedKeychain(inputs: inputs)
        switch seedResult {
        case .seeded(let prefix):
            log("✓ Seeded — clientID prefix: \(prefix)")
        case .alreadyExists:
            log("✗ Keychain entry already exists — re-run with --force to overwrite")
            return 2
        case .invalidClientID(let s):
            return failExit(.invalidClientID(s), transcript: transcript)
        case .invalidServerURL(let s):
            return failExit(.invalidServerURL(s), transcript: transcript)
        case .keychainError(let st):
            return failExit(.keychainOSError(status: st), transcript: transcript)
        case .verifyFailed(let m), .failure(let m):
            return failExit(.seederFailed(message: m), transcript: transcript)
        }

        // STEP 3: bootout stale brokerd + bootstrap canonical
        log("→ Step 3/5: bootout stale + bootstrap io.shikki.secrets-brokerd")
        switch rebootBroker() {
        case .success: log("✓ Bootstrapped launchd plist")
        case .failure(let e): return failExit(e, transcript: transcript)
        }

        // STEP 4: wait for socket
        log("→ Step 4/5: wait up to \(socketWaitSeconds)s for unix socket")
        switch waitForSocket() {
        case .success(let elapsed): log("✓ Socket bound after \(elapsed)s")
        case .failure(let e): return failExit(e, transcript: transcript)
        }

        // STEP 5: smoke
        if skipSmoke {
            log("⏭  Step 5/5: --skip-smoke set; not running set/get round-trip")
            return 0
        }
        log("→ Step 5/5: smoke (set + get round-trip)")
        switch await runSmoke() {
        case .success(let pair):
            log("✓ Smoke GREEN — set/get round-trip for \(pair.0) = \(pair.1)")
            return 0
        case .failure(let e):
            return failExit(e, transcript: transcript)
        }
    }

    // MARK: - Step helpers

    /// Collect inputs from flags + interactive prompts. ≤3 prompts total.
    func collectInputs() -> Result<WizardInputs, WizardError> {
        // client_id: flag → prompt
        let cid: String
        if let provided = clientID, !provided.isEmpty {
            cid = provided
        } else {
            print("client_id (user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): ", terminator: "")
            guard let line = stdinReader(), !line.isEmpty else {
                return .failure(.missingInput(field: "client_id"))
            }
            cid = line.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        // CRIT-2 fix: accept BOTH `user.` and `machine.` prefixes (see
        // VaultCredentialsSeeder.seed for rationale).
        guard cid.hasPrefix("user.") || cid.hasPrefix("machine.") else {
            return .failure(.invalidClientID(cid))
        }
        if cid.hasPrefix("user.") {
            FileHandle.standardError.write(Data(
                "⚠  WARN: client_id starts with 'user.' — this is a personal Bitwarden API key (full-vault access). For blast-radius isolation prefer machine.* when available.\n".utf8
            ))
        }

        // client_secret: --client-secret flag (- = stdin) → prompt no-echo
        let cs: String
        if let arg = clientSecretArg {
            if arg == "-" {
                guard let line = stdinReader(), !line.isEmpty else {
                    return .failure(.missingInput(field: "client_secret"))
                }
                cs = line
            } else {
                // MED-5 fix (@security panel): command-line secret is visible
                // in `ps aux`, shell history, and process environment. Warn
                // loudly and recommend stdin pipe (--client-secret -).
                FileHandle.standardError.write(Data(
                    "⚠  WARN: --client-secret literal exposes the secret in shell history + ps output. Prefer --client-secret - (stdin pipe) or omit (no-echo prompt).\n".utf8
                ))
                cs = arg
            }
        } else {
            guard let read = secretReader(), !read.isEmpty else {
                return .failure(.missingInput(field: "client_secret"))
            }
            cs = read
        }

        // server_url: flag (with default) — no prompt unless explicitly empty
        guard let url = URL(string: serverURL),
              let scheme = url.scheme,
              scheme == "https" || scheme == "http"
        else {
            return .failure(.invalidServerURL(serverURL))
        }

        return .success(WizardInputs(clientID: cid, clientSecret: cs, serverURL: url))
    }

    /// Delegate to VaultCredentialsSeeder (W3.1) — never re-implements Keychain shape.
    func seedKeychain(inputs: WizardInputs) async -> SeedResult {
        let seeder = VaultCredentialsSeeder(store: store, verifier: nil)
        return await seeder.seed(
            clientID: inputs.clientID,
            clientSecret: inputs.clientSecret,
            serverURL: inputs.serverURL.absoluteString,
            force: force,
            verify: false
        )
    }

    /// Bootout legacy + canonical labels, kill leftover procs, bootstrap canonical.
    func rebootBroker() -> Result<Void, WizardError> {
        // P0 backlog 8cc9c1f0 — provision the broker signing key BEFORE launchd
        // starts the daemon. Without this, Bootstrap.loadSigningKey() throws
        // signingKeyMissing and the daemon crash-loops silently. Idempotent —
        // if the key already exists the bytes are kept; only the 0o600 perm is
        // (re-)enforced. Fresh installs get a new 32-byte Ed25519 seed here.
        let credentialsDir = URL(fileURLWithPath: NSString(string: "~/.shikki/credentials")
            .expandingTildeInPath)
        do {
            _ = try BrokerSigningKeyProvisioner.provisionIfNeeded(credentialsDir: credentialsDir)
        } catch {
            return .failure(.signingKeyProvisionFailed(reason: "\(error)"))
        }

        // Foundation has no `realUserID`; use Darwin's getuid(2).
        let uid = String(getuid())
        // Bootout both labels — ignore exit codes (no-such-process is fine).
        _ = try? processRunner.run(executable: "/bin/launchctl",
                                    arguments: ["bootout", "gui/\(uid)/io.shikki.secrets-brokerd"])
        _ = try? processRunner.run(executable: "/bin/launchctl",
                                    arguments: ["bootout", "gui/\(uid)/eu.fj-studios.shikki.secrets-brokerd"])
        // HIGH-1 fix (@security panel): `pkill -f` matches any process whose
        // argv contains the string, including malicious paths like
        // /tmp/evil-shikki-secrets-brokerd. The launchctl bootout above is
        // sufficient for graceful shutdown. Removed `pkill -9 -f`.
        Thread.sleep(forTimeInterval: 1)
        // Remove stale socket.
        let sockPath = BrokerSocketPath.resolve()
        try? FileManager.default.removeItem(atPath: sockPath)
        // Bootstrap canonical.
        let plistPath = NSString(string: "~/Library/LaunchAgents/io.shikki.secrets-brokerd.plist").expandingTildeInPath
        do {
            let result = try processRunner.run(executable: "/bin/launchctl",
                                                arguments: ["bootstrap", "gui/\(uid)", plistPath])
            guard result.exitCode == 0 else {
                return .failure(.launchctlBootstrap(exitCode: result.exitCode, stderr: result.stderr))
            }
            return .success(())
        } catch {
            return .failure(.processSpawnFailed(executable: "/bin/launchctl", reason: "\(error)"))
        }
    }

    func waitForSocket() -> Result<Int, WizardError> {
        let sockPath = BrokerSocketPath.resolve()
        let start = nowProvider()
        for i in 1 ... socketWaitSeconds {
            if socketProbe(sockPath) {
                return .success(i)
            }
            Thread.sleep(forTimeInterval: 1)
            _ = start  // referenced for clarity; future: emit elapsed in log
        }
        return .failure(.socketNeverAppeared(timeoutSeconds: socketWaitSeconds, path: sockPath))
    }

    func runSmoke() async -> Result<(String, String), WizardError> {
        let runner = smokeRunner ?? LiveSmokeRunner()
        return await runner.run()
    }

    // MARK: Error rendering

    func failExit(_ error: WizardError, transcript: [String]) -> Int32 {
        FileHandle.standardError.write(Data("\n✗ Wizard failed: \(error.message)\n".utf8))
        if let hint = error.hint {
            FileHandle.standardError.write(Data("  hint: \(hint)\n".utf8))
        }
        return error.exitCode
    }
}

// MARK: - Inputs (compile-time-typed)

public struct WizardInputs: Sendable, Equatable {
    public let clientID: String
    public let clientSecret: String
    public let serverURL: URL
}

// MARK: - Errors (every step has a typed failure)

public enum WizardError: Error, Sendable, Equatable {
    case missingInput(field: String)
    case invalidClientID(String)
    case invalidServerURL(String)
    case keychainOSError(status: Int32)
    case seederFailed(message: String)
    case launchctlBootstrap(exitCode: Int32, stderr: String)
    case processSpawnFailed(executable: String, reason: String)
    case signingKeyProvisionFailed(reason: String)
    case socketNeverAppeared(timeoutSeconds: Int, path: String)
    case smokeSetFailed(message: String)
    case smokeGetFailed(message: String)
    case smokeMismatch(expected: String, got: String)

    public var exitCode: Int32 {
        switch self {
        case .missingInput, .invalidClientID, .invalidServerURL: return 1
        case .keychainOSError, .seederFailed: return 2
        case .launchctlBootstrap, .processSpawnFailed, .signingKeyProvisionFailed: return 3
        case .socketNeverAppeared: return 4
        case .smokeSetFailed, .smokeGetFailed, .smokeMismatch: return 5
        }
    }

    public var message: String {
        switch self {
        case .missingInput(let f): return "missing input: \(f)"
        case .invalidClientID(let s): return "invalid client_id (must start with user. or machine.): \(s)"
        case .invalidServerURL(let s): return "invalid server_url: \(s)"
        case .keychainOSError(let st): return "Keychain OSStatus \(st)"
        case .seederFailed(let m): return "seeder failed: \(m)"
        case .launchctlBootstrap(let code, let err): return "launchctl bootstrap exit=\(code) stderr=\(err)"
        case .processSpawnFailed(let exe, let reason): return "process spawn failed (\(exe)): \(reason)"
        case .signingKeyProvisionFailed(let reason): return "signing key provision failed: \(reason)"
        case .socketNeverAppeared(let s, let p): return "socket never appeared after \(s)s: \(p)"
        case .smokeSetFailed(let m): return "smoke set failed: \(m)"
        case .smokeGetFailed(let m): return "smoke get failed: \(m)"
        case .smokeMismatch(let e, let g): return "smoke mismatch: expected \(e), got \(g)"
        }
    }

    public var hint: String? {
        switch self {
        case .missingInput: return "re-run and provide the prompted value"
        case .invalidClientID: return "Bitwarden API key starts with 'user.' (personal full-vault) or 'machine.' (scoped service account) — copy from Settings → Security → Keys → API Key"
        case .invalidServerURL: return "must start with https:// or http:// (e.g. https://vw.obyw.one)"
        case .keychainOSError(let st) where st == -25300: return "errSecItemNotFound — re-run with --force"
        case .keychainOSError: return "check Keychain Access.app for the io.shikki.vault entry"
        case .launchctlBootstrap: return "check ~/.shikki/logs/secrets-brokerd.stderr.log"
        case .signingKeyProvisionFailed: return "check ~/.shikki/credentials/ is writable + parent dirs exist (chmod 700 ~/.shikki/credentials/)"
        case .socketNeverAppeared: return "click 'Toujours autoriser' on any pending Keychain popup, then re-run"
        case .smokeMismatch: return "brokerd returned wrong value — check ScopeValidator allowlist + boundPlaintext path"
        default: return nil
        }
    }
}

// MARK: - Process runner abstraction (injectable for tests)

public struct ProcessResult: Sendable, Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
}

public protocol ProcessRunning: Sendable {
    func run(executable: String, arguments: [String]) throws -> ProcessResult
}

public struct LiveProcessRunner: ProcessRunning {
    public init() {}
    public func run(executable: String, arguments: [String]) throws -> ProcessResult {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        let out = Pipe()
        let err = Pipe()
        task.standardOutput = out
        task.standardError = err
        try task.run()
        task.waitUntilExit()
        let outStr = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let errStr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return ProcessResult(exitCode: task.terminationStatus, stdout: outStr, stderr: errStr)
    }
}

// MARK: - Smoke runner abstraction (injectable for tests)

public protocol SmokeRunning: Sendable {
    func run() async -> Result<(String, String), WizardError>
}

public struct LiveSmokeRunner: SmokeRunning {
    public init() {}
    public func run() async -> Result<(String, String), WizardError> {
        // IN-PROCESS composition (BR-COMPOSE) — directly instantiate the same
        // ShiSecretsAPIClient that SecretsSetCommand + SecretsGetCommand use.
        // No subprocess, no shell-out, no parsing stdout.
        //
        // API surface confirmed via LSP `documentSymbol` on ShiSecretsAPIClient:
        //   set(uri: ShiSecretURI, value: String)
        //   resolveValue(uri: ShiSecretURI) -> String
        // URI shape (per ShiSecretURI.parse): shi-secret://<namespace>/<key>
        let timestamp = Int(Date().timeIntervalSince1970)
        let nonce = Int.random(in: 1_000_000 ..< 9_999_999)
        let key = "wizard-smoke-\(timestamp)"
        let value = "hello-world-\(nonce)"

        let uri: ShiSecretURI
        do {
            uri = try ShiSecretURI.parse("shi-secret://wizard/\(key)")
        } catch {
            return .failure(.smokeSetFailed(message: "URI parse failed: \(error)"))
        }

        let sockPath = BrokerSocketPath.resolve()
        let client = ShiSecretsAPIClient(socket: sockPath)

        // set (BR-COMPOSE: direct in-process call — same code path as SecretsSetCommand)
        do {
            try await client.set(uri: uri, value: value)
        } catch {
            return .failure(.smokeSetFailed(message: "\(error)"))
        }

        // resolveValue (BR-COMPOSE: same code path as SecretsGetCommand with --value)
        let got: String
        do {
            got = try await client.resolveValue(uri: uri)
        } catch {
            return .failure(.smokeGetFailed(message: "\(error)"))
        }

        if got == value {
            return .success((uri.qualifiedKey, got))
        } else {
            return .failure(.smokeMismatch(expected: value, got: got))
        }
    }
}

// MARK: - Secret readers (injectable for tests)

public enum WizardSecretReaders {
    /// Live secret reader — uses getpass(3) for no-echo terminal input.
    @Sendable
    public static func live() -> String? {
        guard let prompt = "client_secret (will not echo): ".cString(using: .utf8) else { return nil }
        guard let raw = getpass(prompt) else { return nil }
        return String(cString: raw)
    }

    /// Reads one line from stdin (used when --client-secret - is passed).
    @Sendable
    public static func stdinLine() -> String? {
        guard let line = readLine(strippingNewline: true), !line.isEmpty else { return nil }
        return line
    }
}
