import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsClient
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// BrokerProcessDeleteE2ETests — process-level E2E tests for the secret.delete
// wire path exercised through ProductionBrokerClient over a real Unix socket.
//
// Stack: ProductionBrokerClient → SocketConnection → UnixSocketServer →
//        BrokerWireDispatcher → InMemoryBWClient.
// No real Vaultwarden, no Keychain, no kernel jobs (devMode: true).
//
// Scenarios:
//   PE2E-01  set + delete → list no longer shows the entry
//   PE2E-02  delete a name that was never set → clear domain response, NOT -32601

@Suite("BrokerProcessDeleteE2E")
struct BrokerProcessDeleteE2ETests {

    // MARK: - Stack assembly

    private static func socketPath() -> String {
        "/tmp/shi-pe2e-\(UUID().uuidString.prefix(8)).s"
    }

    private struct Stack: Sendable {
        let socket: UnixSocketServer
        let socketPath: String
        let acceptTask: Task<Void, Never>
    }

    private func makeStack() async throws -> Stack {
        let path = Self.socketPath()
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        let engine = RotationEngine(drivers: drivers, audit: audit, seams: seams, registry: registry)
        let privateKey = Curve25519.Signing.PrivateKey()
        let verifier = ManifestVerifier(pinnedPublicKey: privateKey.publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        // "**" glob matches any scope at any depth — wide-open allowlist for E2E tests.
        let scopeValidator = try ScopeValidator(allowlist: ["**"])
        let bridge = MCPBridge(bearerAllowlist: [])
        let config = UnixSocketConfig(
            socketPath: path,
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        let minter = TokenMinter(
            registry: registry,
            signingKey: Curve25519.Signing.PrivateKey(),
            toolManifest: []
        )
        let gateway = RequestGateway(
            scopeValidator: scopeValidator, bwClient: bwClient, audit: audit
        )
        let daemon = BrokerDaemon(
            kernel: kernel, audit: audit, seams: seams, registry: registry,
            drivers: drivers, engine: engine,
            manifestStore: manifestStore, gateway: gateway,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: PE2EStubBootstrap(),
            devMode: true
        )
        // daemon.start() in devMode: binds socket, skips bootstrap + kernel jobs.
        try await daemon.start()
        let dispatcher = BrokerWireDispatcher(
            daemon: daemon, bridge: bridge, ownerUid: UInt32(geteuid())
        )
        let acceptTask: Task<Void, Never> = Task.detached {
            await socket.runAcceptLoop { req, peerUid in
                await dispatcher.dispatch(req, peerUid: peerUid)
            }
        }
        return Stack(socket: socket, socketPath: path, acceptTask: acceptTask)
    }

    private func tearDown(_ stack: Stack) async {
        await stack.socket.shutdown()
        stack.acceptTask.cancel()
    }

    // MARK: - PE2E-01: set + delete → list no longer contains the entry

    @Test("PE2E-01: set then delete — list no longer contains the deleted entry")
    func test_setThenDelete_listNoLongerContains() async throws {
        let stack = try await makeStack()
        defer { Task { await tearDown(stack) } }

        let client = ProductionBrokerClient(
            socket: SocketConnection(socketPath: stack.socketPath)
        )

        // Set the secret.
        try await client.set(name: "pe2e-test-key", value: "secret-value-01")

        // Confirm it appears in list before delete.
        let beforeList = try await client.list(filter: nil)
        let beforeNames = beforeList.map(\.name)
        #expect(
            beforeNames.contains("pe2e-test-key"),
            "key must appear in list after set; got \(beforeNames)"
        )

        // Delete via BrokerClient.delete — this is the new method under test.
        try await client.delete(name: "pe2e-test-key")

        // Confirm it is gone from list.
        let afterList = try await client.list(filter: nil)
        let afterNames = afterList.map(\.name)
        #expect(
            !afterNames.contains("pe2e-test-key"),
            "deleted key must NOT appear in list; got \(afterNames)"
        )
    }

    // MARK: - PE2E-02: delete a name that was never set → NOT -32601

    @Test("PE2E-02: delete a never-set name — clear domain response, not -32601 methodNotFound")
    func test_deleteNeverSetName_notMethodNotFound() async throws {
        let stack = try await makeStack()
        defer { Task { await tearDown(stack) } }

        let client = ProductionBrokerClient(
            socket: SocketConnection(socketPath: stack.socketPath)
        )

        do {
            // Idempotent delete is acceptable (no error). The key requirement is
            // that the error is NOT -32601 ("Method not found") which is what the
            // broken `rotate` call used to return.
            try await client.delete(name: "never-set-key-pe2e")
        } catch let e as BrokerClientError {
            switch e {
            case .brokerError(let code, let message):
                #expect(
                    code != WireErrorCode.methodNotFound,
                    "delete must NOT return -32601 methodNotFound; got code=\(code) message=\(message)"
                )
            case .socketUnavailable, .wireDecodeFailed, .methodNotImplemented,
                 .denied, .connectionClosed:
                throw e
            }
        }
    }
}

// MARK: - PE2EStubBootstrap

private struct PE2EStubBootstrap: BootstrapProvider {
    func unseal() async throws -> (vaultClient: VaultwardenClient, signingKey: BrokerSigningKey) {
        let creds = VaultwardenCredentials(
            clientID: "user.pe2e",
            clientSecret: "pe2e-secret",
            serverURL: URL(string: "https://vw.obyw.one")!
        )
        let client = try VaultwardenClient(credentials: creds, configYmlVaultServer: "https://vw.obyw.one")
        return (client, BrokerSigningKey(privateKey: Curve25519.Signing.PrivateKey()))
    }
}
