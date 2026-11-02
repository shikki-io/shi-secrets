import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// E2ESupport — in-process full-stack assembler for Wave 5 E2E tests.
//
// W1 update (shi-secrets W1 — 2026-05-21):
//   E2EFakeHandle / E2EFakeLauncher REMOVED — bw CLI subprocess gone.
//   E2EStubBootstrap updated to async unseal() returning VaultwardenClient.
//   InMemoryBWClient wired via activate() instead of start(session:).

/// Review finding U13 — stub bootstrap for full-stack E2E tests.
struct E2EStubBootstrap: BootstrapProvider {
    func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
        let creds = VaultwardenCredentials(
            clientID: "user.e2e",
            clientSecret: "e2e-secret",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        let client = try VaultwardenClient(credentials: creds, configYmlVaultServer: "https://vw.obyw.one")
        return (client, BrokerSigningKey(privateKey: Curve25519.Signing.PrivateKey()))
    }
}

struct E2EStack: Sendable {
    let daemon: BrokerDaemon
    let bwClient: InMemoryBWClient
    let socket: UnixSocketServer
    let audit: AuditWriter
    let seams: SeamsWriter
    let registry: TokenRegistry
    let engine: RotationEngine
    let manifestStore: ManifestStore
    let manifestPrivateKey: Curve25519.Signing.PrivateKey
}

enum E2ESupport {

    static func socketPath() -> String {
        "/tmp/sh-e-\(UUID().uuidString.prefix(8)).s"
    }

    /// Default manifest entry for MCP-transport tests.
    static let defaultMCPToolEntry = ManifestVerifier.ToolEntry(
        toolName: "secrets.request_token",
        schemaHash: "sha256:e2e",
        scopeGlob: "ovh/*",
        maxTtl: 3600,
        op: .read
    )

    static func make(
        scopeAllowlist: [String] = ["ovh/OVH_APP_KEY", "brevo/BREVO_API_KEY", "github/GH_PAT", "ovh/dns/read"],
        toolManifest: [ManifestVerifier.ToolEntry] = [E2ESupport.defaultMCPToolEntry]
    ) async throws -> E2EStack {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )
        let manifestKey = Curve25519.Signing.PrivateKey()
        let verifier = ManifestVerifier(pinnedPublicKey: manifestKey.publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: scopeAllowlist)
        let bridge = MCPBridge(bearerAllowlist: ["mcp-bearer-e2e"])
        let socket = UnixSocketServer(
            config: UnixSocketConfig(
                socketPath: socketPath(),
                expectedMode: 0o600,
                expectedUid: UInt32(geteuid())
            )
        )
        // W1: InMemoryBWClient uses activate() — no subprocess, no BW_SESSION.
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry, signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: toolManifest
        )
        let gateway = RequestGateway(
            scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: E2EStubBootstrap()
        )
        return E2EStack(
            daemon: daemon, bwClient: bwClient, socket: socket,
            audit: audit, seams: seams, registry: registry, engine: engine,
            manifestStore: manifestStore, manifestPrivateKey: manifestKey
        )
    }

    static func tearDown(_ stack: E2EStack) async {
        await stack.socket.shutdown()
    }

    /// Simulate a Claude-MCP `secrets.request_token` tool call.
    static func claudeMCPRequestToken(
        stack: E2EStack,
        scope: String,
        op: ShikkiSBT.Op,
        ttl: Int,
        toolName: String? = "secrets.request_token",
        sub: String = "claude@tusken"
    ) async throws -> BrokerResponse {
        let bridge = await stack.daemon.bridge
        let wrapped = try await bridge.wrapMcpRequest(
            payload: Data(),
            bearer: "mcp-bearer-e2e"
        )
        let request = BrokerRequest(
            sub: sub, scope: scope, op: op, ttl: ttl, toolName: toolName
        )
        return await stack.daemon.handleRequest(request, wrapped: wrapped)
    }
}

// MARK: - BrokerProcessGate

/// Serialises broker-process launches across E2E suites.
///
/// Swift Testing runs @Suite types in parallel by default.  When four suites
/// each spawn a brokerd process at the same time the Mac runs out of CPU
/// budget during socket creation, causing 15 s socket-wait timeouts to expire.
/// Acquiring the gate before `Process.run()` and releasing it once the socket
/// file appears limits concurrent startups to one at a time while letting the
/// test bodies (which are I/O-bound) overlap freely.
actor BrokerProcessGate {
    static let shared = BrokerProcessGate()
    private var inUse = false
    private var queue: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        guard inUse else { inUse = true; return }
        await withCheckedContinuation { queue.append($0) }
    }

    func release() {
        if queue.isEmpty { inUse = false; return }
        queue.removeFirst().resume()
    }
}

// MARK: - Shared socket-wait helper

enum E2EBrokerError: Error, CustomStringConvertible {
    case socketTimeout(String)
    var description: String {
        switch self {
        case .socketTimeout(let p): return "broker socket did not appear at \(p)"
        }
    }
}

extension E2ESupport {
    /// Wait for a broker process socket file to appear, serialising the
    /// startup phase via `BrokerProcessGate.shared`.
    ///
    /// Call this after `Process.run()` with `timeout: 15` (default).  The gate
    /// is held only until the socket file exists, so the test body runs without
    /// holding the gate and other suites can start their broker concurrently.
    static func waitForBrokerSocket(
        _ path: String,
        timeout: TimeInterval = 15
    ) async throws {
        await BrokerProcessGate.shared.acquire()
        defer { Task { await BrokerProcessGate.shared.release() } }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: path) { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw E2EBrokerError.socketTimeout(path)
    }
}
