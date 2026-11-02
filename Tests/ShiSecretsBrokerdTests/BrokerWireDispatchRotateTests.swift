import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// BrokerWireDispatchRotateTests — coverage for the `secret.rotate` wire path.
//
// TR-01  success — seeded entry + registered driver → RotationResult wire shape
// TR-02  unknown secret — engine has no entry → wire error invalidParams
// TR-03  no driver registered — entry exists, vendor unregistered → wire error denied
// TR-04  wrong peer uid — peerUid ≠ ownerUid → requireOwner returns denied
// TR-05  ScopePolicy denied — systemScopePolicy rejects path → wire error invalidParams
// TR-06  driver failure — driver returns .failed(reason:) → wire error + audit deny
// TR-07  missing params → wire error invalidParams
//
// All tests inject mock drivers; no network or real Vaultwarden required.
// All tests use Swift Testing style (#expect, @Test, @Suite).

/// Deterministic mock driver for rotate tests.
private struct MockRotationDriver: SecretRotationDriver {
    let vendor: String
    let outcome: RotationOutcome

    func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        _ = entry; _ = trigger
        return outcome
    }
}

@Suite("BrokerWireDispatch — secret.rotate")
struct BrokerWireDispatchRotateTests {

    // MARK: - Helpers

    private func socketPath() -> String {
        "/tmp/sh-rot-\(UUID().uuidString.prefix(8)).s"
    }

    /// Builds a full in-process dispatcher with one registered mock driver.
    /// - Parameters:
    ///   - vendor: the vendor string to register the driver under.
    ///   - outcome: what the driver returns from `rotate(entry:trigger:)`.
    ///   - seedEntry: when non-nil, seeds an entry in the engine under that name.
    ///   - seedScope: scope used when seeding the entry (default: "\(vendor)/KEY").
    ///   - systemScopePolicy: optional ScopePolicy; nil means no path restriction.
    ///   - ownerUid: the UID that owns the daemon (default: current euid).
    private func makeDispatcher(
        vendor: String = "ovh",
        outcome: RotationOutcome = .rotated,
        seedEntry: String? = nil,
        seedScope: String? = nil,
        systemScopePolicy: ScopePolicy? = nil,
        ownerUid: UInt32 = UInt32(geteuid())
    ) async throws -> (
        dispatcher: BrokerWireDispatcher,
        engine: RotationEngine,
        audit: AuditWriter,
        socket: UnixSocketServer
    ) {
        let kernel = ShikkiKernel()
        let audit = AuditWriter()
        let seams = SeamsWriter()
        let registry = TokenRegistry()
        let drivers = DriverRegistry()
        await drivers.register(MockRotationDriver(vendor: vendor, outcome: outcome))
        let engine = RotationEngine(
            drivers: drivers, audit: audit, seams: seams, registry: registry
        )
        if let name = seedEntry {
            let scope = seedScope ?? "\(vendor)/KEY"
            await engine.seed(entry: VaultEntryRef(
                name: name,
                scope: scope,
                tier: .warm,
                usageState: .warm,
                lastRotated: Date(timeIntervalSinceNow: -3600),
                rotationDue: Date(timeIntervalSinceNow: -60)
            ))
        }
        let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
        let manifestStore = ManifestStore(verifier: verifier, seams: seams)
        let scopeValidator = try ScopeValidator(allowlist: ["**"])
        let bridge = MCPBridge(bearerAllowlist: ["bearer-rot"])
        let config = UnixSocketConfig(
            socketPath: socketPath(),
            expectedMode: 0o600,
            expectedUid: UInt32(geteuid())
        )
        let socket = UnixSocketServer(config: config)
        let bwClient = InMemoryBWClient()
        await bwClient.activate()
        // Unlock the vault so dispatchSecretRotate passes the isVaultUnlocked gate.
        try await bwClient.unlock(masterPassword: "test-unlock", email: "test@rotate")
        // Mirror the engine seed into the vault so the dispatcher can resolve the
        // entry via bwClient.get() (the production lookup path post-fix).
        if let name = seedEntry {
            let scope = seedScope ?? "\(vendor)/KEY"
            await bwClient.seedFakeEntry(
                name: name,
                fields: ["scope": scope, "value": "test-credential"]
            )
        }
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
            systemScopePolicy: systemScopePolicy,
            bridge: bridge, socket: socket, bwClient: bwClient, minter: minter,
            bootstrap: StubBootstrapProvider()
        )
        try await daemon.start()
        let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge, ownerUid: ownerUid)
        return (dispatcher, engine, audit, socket)
    }

    // MARK: - TR-01: success

    @Test("TR-01: success — seeded entry + driver returning .rotated → RotationResult wire response")
    func test_rotate_success_returnsRotationResult() async throws {
        let (dispatcher, _, _, socket) = try await makeDispatcher(
            vendor: "ovh",
            outcome: .rotated,
            seedEntry: "OVH_APP_KEY",
            seedScope: "ovh/OVH_APP_KEY"
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("OVH_APP_KEY")]),
            id: "tr-01"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(resp.error == nil, "TR-01: expected no error on success")
        guard let result = resp.result, case .object(let obj) = result else {
            Issue.record("TR-01: result must be a JSON object")
            return
        }
        guard case .string(let secretName) = obj["secretName"] else {
            Issue.record("TR-01: result must contain 'secretName'")
            return
        }
        #expect(secretName == "OVH_APP_KEY", "TR-01: secretName must match requested name")
        #expect(obj["oldJtiSuffix"] != nil, "TR-01: oldJtiSuffix must be present")
        #expect(obj["invalidAt"] != nil, "TR-01: invalidAt must be present")
    }

    // MARK: - TR-02: unknown secret

    @Test("TR-02: unknown secret — engine has no entry → wire error invalidParams")
    func test_rotate_unknownSecret_returnsInvalidParams() async throws {
        // No seedEntry — engine registry is empty.
        let (dispatcher, _, _, socket) = try await makeDispatcher(vendor: "ovh", outcome: .rotated)
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("UNKNOWN_KEY")]),
            id: "tr-02"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(resp.error != nil, "TR-02: expected error for unknown secret")
        #expect(resp.error?.code == WireErrorCode.invalidParams,
                "TR-02: expected invalidParams for unknown secret")
    }

    // MARK: - TR-03: no driver registered

    @Test("TR-03: no driver registered for vendor → wire error denied (not a fake success)")
    func test_rotate_noDriverRegistered_returnsDenied() async throws {
        // Entry is seeded with vendor "brevo" but only "ovh" driver is registered.
        let (dispatcher, _, _, socket) = try await makeDispatcher(
            vendor: "ovh",     // driver registered under "ovh"
            outcome: .rotated,
            seedEntry: "BREVO_API_KEY",
            seedScope: "brevo/BREVO_API_KEY"   // vendor derived = "brevo"
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("BREVO_API_KEY")]),
            id: "tr-03"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(resp.error != nil, "TR-03: expected error when no driver registered")
        #expect(resp.error?.code == WireErrorCode.denied,
                "TR-03: a missing driver must be a denied error, not a fake success")
    }

    // MARK: - TR-04: wrong peer uid

    @Test("TR-04: peerUid ≠ ownerUid → requireOwner returns denied")
    func test_rotate_wrongPeerUid_returnsDenied() async throws {
        let ownerUid = UInt32(geteuid())
        let wrongUid: UInt32 = ownerUid == 0 ? 1 : 0

        let (dispatcher, _, _, socket) = try await makeDispatcher(
            vendor: "ovh",
            outcome: .rotated,
            seedEntry: "OVH_APP_KEY",
            seedScope: "ovh/OVH_APP_KEY",
            ownerUid: ownerUid
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("OVH_APP_KEY")]),
            id: "tr-04"
        )
        let resp = await dispatcher.dispatch(req, peerUid: wrongUid)

        #expect(resp.error != nil, "TR-04: expected error for wrong peer uid")
        #expect(resp.error?.code == WireErrorCode.denied,
                "TR-04: wrong peerUid must return denied")
    }

    // MARK: - TR-05: ScopePolicy denied

    @Test("TR-05: path outside ScopePolicy blast-radius → wire error invalidParams")
    func test_rotate_scopePolicyDenied_returnsError() async throws {
        // ScopePolicy("mac-laptop") permits only shi/system/mac-laptop/** and shi/shared/**.
        // "OVH_APP_KEY" is outside that blast-radius.
        let policy = ScopePolicy(systemName: "mac-laptop")
        let (dispatcher, _, _, socket) = try await makeDispatcher(
            vendor: "ovh",
            outcome: .rotated,
            seedEntry: "OVH_APP_KEY",
            seedScope: "ovh/OVH_APP_KEY",
            systemScopePolicy: policy
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("OVH_APP_KEY")]),
            id: "tr-05"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(resp.error != nil, "TR-05: expected error when path is outside ScopePolicy")
        #expect(resp.error?.code == WireErrorCode.invalidParams,
                "TR-05: ScopePolicy blast-radius denial must return invalidParams")
    }

    // MARK: - TR-06: driver failure

    @Test("TR-06: driver returns .failed — wire error internalError + audit deny row written")
    func test_rotate_driverFailure_returnsInternalError_andAuditDenyRow() async throws {
        let (dispatcher, _, audit, socket) = try await makeDispatcher(
            vendor: "ovh",
            outcome: .failed(reason: "vendor API 503"),
            seedEntry: "OVH_APP_KEY",
            seedScope: "ovh/OVH_APP_KEY"
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("OVH_APP_KEY")]),
            id: "tr-06"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(resp.error != nil, "TR-06: expected error on driver failure")
        #expect(resp.error?.code == WireErrorCode.internalError,
                "TR-06: driver failure must surface as internalError")
        // Audit deny row with rotationFailed reason must be written.
        let rows = await audit.all()
        let denyRow = rows.first { $0.op == .rotate && $0.allow == .deny && $0.reason == .rotationFailed }
        #expect(denyRow != nil, "TR-06: driver failure must write audit deny + rotationFailed")
    }

    // MARK: - TR-07: missing params

    @Test("TR-07: missing name param → wire error invalidParams")
    func test_rotate_missingParams_returnsInvalidParams() async throws {
        let (dispatcher, _, _, socket) = try await makeDispatcher(
            vendor: "ovh",
            outcome: .rotated,
            seedEntry: "OVH_APP_KEY",
            seedScope: "ovh/OVH_APP_KEY"
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object([:]),  // missing "name"
            id: "tr-07"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(resp.error != nil, "TR-07: expected error for missing params")
        #expect(resp.error?.code == WireErrorCode.invalidParams,
                "TR-07: missing name param must return invalidParams")
    }
}
