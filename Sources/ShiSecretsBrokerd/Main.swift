// kagami-scope: exempt — resolver-exempt marker only (no behavioral change); package has no .kagami/scopes.yaml coverage.
import Crypto
import Foundation
import ShiSecretsKit

// shikki-secrets-brokerd — Wave 5 standalone daemon entrypoint.
//
// Bootstrap → BrokerDaemon.start() → runAcceptLoop until SIGTERM.
//
// macOS LaunchAgent (or direct invocation) enters here. No ShikkiKernel
// supervisor required — the daemon manages its own lifecycle.
//
// BR-I-04: bootstrap.unseal is the first runtime action. On failure the
// process exits non-zero; no socket is bound.
//
// Signal handling: SIGTERM / SIGINT cancel the watchdog task, which calls
// socket.shutdown() so accept() returns EBADF and runAcceptLoop exits.

// MARK: - Shutdown coordinator (actor-isolated)

private actor ShutdownCoordinator {
    private var shutdownContinuation: CheckedContinuation<Void, Never>?
    private var triggered = false

    func waitForShutdown() async {
        if triggered { return }
        await withCheckedContinuation { cont in
            shutdownContinuation = cont
        }
    }

    func triggerShutdown() {
        guard !triggered else { return }
        triggered = true
        shutdownContinuation?.resume()
        shutdownContinuation = nil
    }
}

private let shutdownCoordinator = ShutdownCoordinator()

// MARK: - Entry point

@main
struct BrokerMain {
    static func main() async throws {
        let stderr = FileHandle.standardError
        func log(_ msg: String) {
            try? stderr.write(contentsOf: Data((msg + "\n").utf8))
        }

        // ── 0. --dev-mode arg parse (spec RC-3) ───────────────────────────
        let cliArgs = Array(CommandLine.arguments.dropFirst())
        let devArgs = DevModeArgs.parse(cliArgs)

        // ── 1. Bootstrap — production OR dev-mode ─────────────────────────
        let bwClient: any BWClient
        let signingKey: BrokerSigningKey
        let prodVaultClient: VaultwardenClient?
        let resolvedSocketPath: String

        // Used by BrokerDaemon init below; dev-mode constructs a no-op
        // Bootstrap (won't be exercised after the in-memory bw is wired).
        let bootstrap = Bootstrap()

        if devArgs.enabled {
            // Dev-mode path — no vaultwarden contact, in-memory seeded vault.
            // Socket path comes from --socket arg or SHIKKI_BROKER_SOCKET env;
            // production paths are refused.
            let devSocket = devArgs.socketPath
                ?? ProcessInfo.processInfo.environment["SHIKKI_BROKER_SOCKET"]
                ?? "/tmp/shi-secrets-dev-\(getuid()).sock"
            let devConfig = DevModeConfig(
                socketPath: devSocket,
                seedCredentials: DevModeConfig.defaultSeed
            )
            let devBootstrap = DevModeBootstrap(config: devConfig)
            do {
                let (bw, sk) = try await devBootstrap.unseal()
                bwClient = bw
                signingKey = sk
                prodVaultClient = nil
                resolvedSocketPath = devSocket
                log("shikki-secrets-brokerd: --dev-mode ACTIVE — seeded \(devConfig.seedCredentials.count) dev-* creds, socket=\(devSocket)")
            } catch {
                log("shikki-secrets-brokerd: dev-mode refused — \(error)")
                throw error
            }
        } else {
            // Production path — vaultwarden contact, hardened keychain.
            let bootstrap = Bootstrap()
            let prodVault: VaultwardenClient
            do {
                (prodVault, signingKey) = try await bootstrap.unseal()
            } catch {
                log("shikki-secrets-brokerd: bootstrap.unseal failed — refusing to start: \(error)")
                throw BootstrapError.unsealFailed
            }
            let prod = ProductionBWClient()
            await prod.wire(client: prodVault)
            bwClient = prod
            prodVaultClient = prodVault
            // Resolution order (production):
            //   1. --socket <path> CLI arg (passed by LaunchAgent plist — honors XDG install path)
            //   2. BrokerSocketPath.resolve() — env override + XDG default, shared with
            //      the client library (single source of truth per policy_dry_single_source_of_truth).
            resolvedSocketPath = devArgs.socketPath ?? BrokerSocketPath.resolve()
        }
        _ = prodVaultClient  // suppress unused warning when dev-mode

        // ── 2. Wire collaborators ──────────────────────────────────────────
        let kernel    = ShikkiKernel()
        let audit     = AuditWriter()
        let seams     = SeamsWriter()
        let registry  = TokenRegistry()
        let drivers   = DriverRegistry()
        let engine    = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )

        // ManifestStore: no signed manifest injected in standalone dev mode
        // (BR-H-02/e applies to MCP-manifest preload, not standalone socket
        //  access). manifestSource = nil disables the preload; the store
        //  starts empty and accepts a HUP reload from ops later.
        let verifier      = ManifestVerifier(pinnedPublicKey: signingKey.privateKey.publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)

        // ScopeValidator: load allowlist from ~/.shikki/settings/secrets-brokerd.toml
        // [scope].allowlist. On first boot, if the config is absent, a dev-friendly
        // default ["**"] is seeded and a WARN is emitted.
        //
        // secret.list / secret.set bypass handleRequest and work regardless of the
        // allowlist. Only secret.get is gated.
        let brokerdSettings = BrokerdSettings.loadOrDefault()
        try? BrokerdSettings.writeDefaultIfMissing(
            at: URL(fileURLWithPath: (NSHomeDirectory() as NSString)
                .appendingPathComponent(".shikki/settings/secrets-brokerd.toml"))
        )
        if brokerdSettings.isWildcardAllowlist {
            log("shikki-secrets-brokerd: WARN scope allowlist is \"**\" — DEV ONLY. Configure ~/.shikki/settings/secrets-brokerd.toml [scope].allowlist for production (e.g. allowlist = [\"shi/**\", \"ci/**\"])")
        }
        // HIGH-6 fix: refuse start with empty allowlist (silent DoS fingerprint).
        // v0.4.2 @kintsugi UX-F fix: the error message now provides the
        // exact TOML stanza an operator should paste, not just a hint.
        if brokerdSettings.scopeAllowlist.isEmpty {
            FileHandle.standardError.write(Data(
                """
                shikki-secrets-brokerd: ERROR scope allowlist is empty — refusing to start.
                Edit ~/.shikki/settings/secrets-brokerd.toml and add:

                    [scope]
                    allowlist = ["shi/**"]

                Then re-run `shi secrets login`.

                """.utf8
            ))
            exit(78)
        }
        let scopeValidator = try ScopeValidator(allowlist: brokerdSettings.scopeAllowlist)

        // v0.5.0 Wave A1 (@sensei v0.4.2 panel finding): delegate to the
        // BootstrapProvider — Main.swift becomes pure wiring. Tests
        // injecting a mock BootstrapProvider can return nil (or a fixed
        // ScopePolicy) without touching the real filesystem.
        //
        // Composes the prior v0.4.3 HIGH-2 (cross-validate via
        // SystemNameBindingVerifier) + tech-expert MED (explicit error
        // path for IO failures + sidecar/Keychain mismatch).
        let systemScopePolicy: ScopePolicy?
        do {
            systemScopePolicy = try bootstrap.loadSystemScopePolicy()
            if let policy = systemScopePolicy {
                log("shikki-secrets-brokerd: per-system ScopePolicy active for systemName=\(policy.systemName)")
            }
        } catch SystemScopePolicyLoadError.bindingMismatch(let reason) {
            FileHandle.standardError.write(Data(
                "shikki-secrets-brokerd: ERROR system-name binding verification FAILED: \(reason)\n".utf8
            ))
            exit(78)
        } catch SystemScopePolicyLoadError.sidecarReadFailed(let reason) {
            FileHandle.standardError.write(Data(
                "shikki-secrets-brokerd: ERROR system-name sidecar read failed: \(reason). Blast-radius isolation DISABLED.\n".utf8
            ))
            systemScopePolicy = nil
        } catch {
            FileHandle.standardError.write(Data(
                "shikki-secrets-brokerd: ERROR loadSystemScopePolicy unexpected: \(error). Blast-radius isolation DISABLED.\n".utf8
            ))
            systemScopePolicy = nil
        }

        let bridge = MCPBridge()

        // Socket: dev-mode resolved its own socketPath; production resolves
        // from --socket arg / SHIKKI_BROKER_SOCKET env / legacy default.
        // (bwClient was assigned in dev or prod branch above.)
        let socketPath = resolvedSocketPath
        // HIGH-6: suppress SIGPIPE — writes to closed sockets return EPIPE instead of killing the process.
        signal(SIGPIPE, SIG_IGN)
        let socketConfig = UnixSocketConfig(
            socketPath: socketPath,
            expectedMode: 0o600,
            expectedUid: UInt32(getuid())
        )
        let socket = UnixSocketServer(config: socketConfig)

        // Ensure the run directory exists.
        let runDir = URL(fileURLWithPath: socketPath).deletingLastPathComponent().path
        try? FileManager.default.createDirectory(
            atPath: runDir, withIntermediateDirectories: true
        )

        let minter = TokenMinter(
            registry: registry,
            signingKey: signingKey.privateKey,
            toolManifest: []
        )

        // Wave A4: wire RequestGateway before BrokerDaemon so pre-mint
        // scope/session checks are owned by the gateway, not the daemon.
        let gateway = RequestGateway(
            scopeValidator: scopeValidator,
            systemScopePolicy: systemScopePolicy,
            bwClient: bwClient,
            audit: audit
        )

        let daemon = BrokerDaemon(
            kernel: kernel,
            audit: audit,
            seams: seams,
            registry: registry,
            drivers: drivers,
            engine: engine,
            manifestStore: manifestStore,
            gateway: gateway,
            systemScopePolicy: systemScopePolicy,
            bridge: bridge,
            socket: socket,
            bwClient: bwClient,
            minter: minter,
            bootstrap: bootstrap,
            manifestSource: nil,   // standalone: no pre-signed manifest
            devMode: devArgs.enabled
        )

        // ── 3. start() — preflight: socket bind + kernel job registration ─
        do {
            try await daemon.start()
        } catch {
            log("shikki-secrets-brokerd: daemon.start() failed — \(error)")
            throw error
        }

        log("shikki-secrets-brokerd ready — socket: \(socketPath)")

        // ── 4. Signal handling for graceful shutdown ───────────────────────
        // Signal handlers are nonisolated C functions; they hand off to the
        // actor-isolated coordinator via an unstructured Task so Swift
        // concurrency invariants are respected.
        let signalHandler: @convention(c) (Int32) -> Void = { _ in
            Task { await shutdownCoordinator.triggerShutdown() }
        }
        signal(SIGTERM, signalHandler)
        signal(SIGINT,  signalHandler)

        // Spawn the shutdown watcher. When triggered, interrupt accept() and
        // remove the socket file. Uses the nonisolated requestShutdownAndInterrupt()
        // instead of actor-isolated shutdown() because the daemon may be blocked
        // inside accept(2) when the signal arrives — shutdown() would deadlock
        // waiting for the actor to become free. After the interrupt, accept()
        // returns EBADF and runAcceptLoop exits, releasing the actor, at which
        // point the process terminates.
        let watchTask = Task.detached {
            await shutdownCoordinator.waitForShutdown()
            socket.requestShutdownAndInterrupt()
        }

        // ── 5. Accept loop — runs forever until shutdown ───────────────────
        // CRIT-1: peerUid is now threaded per-connection from peerCredentials(fd:)
        // inside runAcceptLoop. The static uid local var is no longer used here.
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge)
        await socket.runAcceptLoop { wireRequest, peerUid in
            await dispatcher.dispatch(wireRequest, peerUid: peerUid)
        }

        watchTask.cancel()
        log("shikki-secrets-brokerd: accept loop exited — daemon stopped.")
    }
}
