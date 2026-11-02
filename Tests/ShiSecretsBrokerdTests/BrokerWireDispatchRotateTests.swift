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

/// Sentinel error thrown by MockRotationDriver.invalidate when shouldInvalidateFail is true.
private enum MockDriverError: Swift.Error, Sendable {
    case invalidateFailure
}

/// Deterministic mock driver for rotate tests.
private struct MockRotationDriver: SecretRotationDriver {
    let vendor: String
    let outcome: RotationOutcome
    /// When true, `invalidate(previous:)` throws `DriverHTTPError.transportFailed`.
    let shouldInvalidateFail: Bool

    init(vendor: String, outcome: RotationOutcome, shouldInvalidateFail: Bool = false) {
        self.vendor = vendor
        self.outcome = outcome
        self.shouldInvalidateFail = shouldInvalidateFail
    }

    func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        _ = entry; _ = trigger
        return outcome
    }

    func invalidate(previous: VaultEntryRef) async throws {
        _ = previous
        if shouldInvalidateFail {
            throw MockDriverError.invalidateFailure
        }
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
        /// Extra entries to seed directly into the bwClient (name → fields).
        bwSeedEntries: [String: [String: String]] = [:],
        /// When true the mock driver's `invalidate` throws (TR-09).
        shouldInvalidateFail: Bool = false,
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
        await drivers.register(MockRotationDriver(vendor: vendor, outcome: outcome, shouldInvalidateFail: shouldInvalidateFail))
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
        // Seed any explicit bwClient entries (used by TR-08 and similar tests that
        // need custom vault content without a corresponding engine seed).
        for (name, fields) in bwSeedEntries {
            await bwClient.seedFakeEntry(name: name, fields: fields)
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

    // MARK: - TR-08: vault entry exists but has no scope field

    @Test("TR-08: vault entry has no 'scope' field → denied error with actionable hint")
    func test_rotate_noScopeField_returnsDeniedWithHint() async throws {
        // A vault entry with only a "value" field and no "scope" field causes the
        // vendor fallback to use the entry name itself. No driver is registered under
        // that name, so the result must be a clear `denied` error that tells the
        // operator how to fix it (add a `scope` field).
        let (dispatcher, _, _, socket) = try await makeDispatcher(
            vendor: "ovh",      // driver registered under "ovh"
            outcome: .rotated,
            // No seedEntry — engine is empty.
            bwSeedEntries: ["MY_API_KEY": ["value": "some-api-key"]]  // no scope field
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("MY_API_KEY")]),
            id: "tr-08"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        #expect(resp.error != nil, "TR-08: expected error when vault entry has no scope field")
        #expect(resp.error?.code == WireErrorCode.denied,
                "TR-08: a missing driver must be denied, not a fake success")
        // Error message must contain the actionable hint about adding a 'scope' field.
        let message = resp.error?.message ?? ""
        #expect(message.contains("scope"), "TR-08: error must mention the 'scope' field")
    }

    // MARK: - TR-09: rotation succeeded but invalidate threw

    @Test("TR-09: invalidate throws → rotation succeeds with invalidationWarning field in result")
    func test_rotate_invalidateThrows_succeedsWithWarning() async throws {
        // The rotation itself succeeds (new credential is live) but the driver's
        // invalidate() method throws. The dispatcher must:
        //   1. Still return a successful result (result != nil, error == nil).
        //   2. Include an "invalidationWarning" field in the result JSON.
        //   3. Write a deny audit row with reason: .rotationFailed for the invalidation failure.
        let (dispatcher, _, audit, socket) = try await makeDispatcher(
            vendor: "ovh",
            outcome: .rotated,
            seedEntry: "OVH_APP_KEY",
            seedScope: "ovh/OVH_APP_KEY",
            shouldInvalidateFail: true
        )
        defer { Task { await socket.shutdown() } }

        let req = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("OVH_APP_KEY")]),
            id: "tr-09"
        )
        let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))

        // Rotation succeeded — result must be present, error must be nil.
        #expect(resp.error == nil, "TR-09: rotation should succeed even when invalidate throws")
        guard let result = resp.result, case .object(let obj) = result else {
            Issue.record("TR-09: result must be a JSON object")
            return
        }
        #expect(obj["secretName"] != nil, "TR-09: secretName must be present")
        // invalidationWarning must be present when invalidate threw.
        guard case .string(let warning) = obj["invalidationWarning"] else {
            Issue.record("TR-09: invalidationWarning must be a string in result when invalidate throws")
            return
        }
        #expect(!warning.isEmpty, "TR-09: invalidationWarning must be non-empty")
        // An audit deny row for the invalidation failure must exist.
        let rows = await audit.all()
        let denyRow = rows.first {
            $0.op == .rotate && $0.allow == .deny && $0.reason == .rotationFailed
        }
        #expect(denyRow != nil, "TR-09: invalidation failure must write audit deny + rotationFailed")
    }
}
