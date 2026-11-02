import Crypto
import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// VaultUnlockRPCTests — feat/vault-unlock-2026-11-01.
//
// Tests the vault.unlock and vault.status JSON-RPC dispatch arms wired
// in BrokerWireDispatch.swift. Uses InMemoryBWClient with fake KDF
// fixture values only — no real master password, no network calls.
//
// Coverage:
//   VaultUnlockRPCDispatchTests  — vault.unlock routing + error paths
//   VaultStatusRPCDispatchTests  — vault.status before and after unlock

// MARK: - Shared helpers

private func makeDispatcher() async throws -> (BrokerWireDispatcher, InMemoryBWClient, UnixSocketServer) {
    let kernel = ShikkiKernel()
    let audit = AuditWriter()
    let seams = SeamsWriter()
    let registry = TokenRegistry()
    let drivers = DriverRegistry()
    let engine = RotationEngine(drivers: drivers, audit: audit, seams: seams, registry: registry)
    let verifier = ManifestVerifier(pinnedPublicKey: Curve25519.Signing.PrivateKey().publicKey)
    let manifestStore = ManifestStore(verifier: verifier, seams: seams)
    let scopeValidator = try ScopeValidator(allowlist: ["ovh/OVH_APP_KEY"])
    let bridge = MCPBridge(bearerAllowlist: ["bearer-1"])
    let socketPath = "/tmp/sh-unlock-\(UUID().uuidString.prefix(8)).s"
    let config = UnixSocketConfig(
        socketPath: socketPath,
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
        bootstrap: StubBootstrapProvider()
    )
    try await daemon.start()
    let dispatcher = BrokerWireDispatcher(daemon: daemon, bridge: bridge, ownerUid: UInt32(geteuid()))
    return (dispatcher, bwClient, socket)
}

// MARK: - vault.unlock dispatch

@Suite("VaultUnlockRPCDispatch")
struct VaultUnlockRPCDispatchTests {

    @Test("vault.unlock with valid fake credentials succeeds (ok: true)")
    func test_vaultUnlock_validCredentials_returnsOk() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let params: JSONValue = .object([
            "masterPassword": .string("fake-password-for-unit-test"),
            "email": .string("operator@example.test"),
        ])
        let request = WireRequest(method: "vault.unlock", params: params, id: "unlock-1")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "unlock-1")
        #expect(response.error == nil, "Expected success but got error: \(String(describing: response.error))")
        guard case .object(let obj) = response.result else {
            Issue.record("Expected object result, got \(String(describing: response.result))")
            return
        }
        #expect(obj["ok"] == .bool(true))
    }

    @Test("vault.unlock with empty password fails with WireErrorCode.denied")
    func test_vaultUnlock_emptyPassword_returnsDenied() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        // InMemoryBWClient rejects empty password — simulates wrong-password failure.
        let params: JSONValue = .object([
            "masterPassword": .string(""),
            "email": .string("operator@example.test"),
        ])
        let request = WireRequest(method: "vault.unlock", params: params, id: "unlock-bad")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "unlock-bad")
        #expect(response.result == nil)
        #expect(response.error?.code == WireErrorCode.denied)
        // The error message must be non-empty so the CLI can display it.
        let msg = response.error?.message ?? ""
        #expect(!msg.isEmpty, "Error message must be non-empty for clear failure feedback")
    }

    @Test("vault.unlock from non-owner UID is rejected (WireErrorCode.denied)")
    func test_vaultUnlock_nonOwnerUid_isRejected() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let params: JSONValue = .object([
            "masterPassword": .string("fake-password-for-unit-test"),
            "email": .string("operator@example.test"),
        ])
        let request = WireRequest(method: "vault.unlock", params: params, id: "unlock-peer")
        // Use a different UID from the owner to simulate a remote peer.
        let peerUid = UInt32(geteuid()) + 1
        let response = await dispatcher.dispatch(request, peerUid: peerUid)

        #expect(response.id == "unlock-peer")
        #expect(response.result == nil)
        #expect(response.error?.code == WireErrorCode.denied)
    }

    @Test("vault.unlock with missing params returns invalidParams error")
    func test_vaultUnlock_missingParams_returnsInvalidParams() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let request = WireRequest(method: "vault.unlock", params: nil, id: "unlock-np")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "unlock-np")
        #expect(response.result == nil)
        #expect(response.error?.code == WireErrorCode.invalidParams)
    }
}

// MARK: - vault.status dispatch

@Suite("VaultStatusRPCDispatch")
struct VaultStatusRPCDispatchTests {

    @Test("vault.status before unlock reports locked: true")
    func test_vaultStatus_beforeUnlock_reportsLocked() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let request = WireRequest(method: "vault.status", params: nil, id: "status-1")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "status-1")
        #expect(response.error == nil)
        guard case .object(let obj) = response.result else {
            Issue.record("Expected object result")
            return
        }
        #expect(obj["locked"] == .bool(true), "Vault must be locked before unlock()")
    }

    @Test("vault.status after unlock reports locked: false")
    func test_vaultStatus_afterUnlock_reportsUnlocked() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        // First unlock with a valid fake password.
        let unlockParams: JSONValue = .object([
            "masterPassword": .string("fake-password-for-unit-test"),
            "email": .string("operator@example.test"),
        ])
        let unlockReq = WireRequest(method: "vault.unlock", params: unlockParams, id: "unlock-pre")
        let unlockResp = await dispatcher.dispatch(unlockReq, peerUid: UInt32(geteuid()))
        guard unlockResp.error == nil else {
            Issue.record("Unlock must succeed before testing status: \(String(describing: unlockResp.error))")
            return
        }

        // Now check status.
        let statusReq = WireRequest(method: "vault.status", params: nil, id: "status-2")
        let statusResp = await dispatcher.dispatch(statusReq, peerUid: UInt32(geteuid()))

        #expect(statusResp.id == "status-2")
        #expect(statusResp.error == nil)
        guard case .object(let obj) = statusResp.result else {
            Issue.record("Expected object result")
            return
        }
        #expect(obj["locked"] == .bool(false), "Vault must report unlocked after unlock()")
    }

    @Test("vault.status from non-owner UID is allowed (status is not secret)")
    func test_vaultStatus_nonOwnerUid_isAllowed() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let request = WireRequest(method: "vault.status", params: nil, id: "status-peer")
        let peerUid = UInt32(geteuid()) + 1
        let response = await dispatcher.dispatch(request, peerUid: peerUid)

        // vault.status reveals no secret material; non-owner access is permitted.
        #expect(response.id == "status-peer")
        #expect(response.error == nil)
        guard case .object(let obj) = response.result else {
            Issue.record("Expected object result")
            return
        }
        #expect(obj["locked"] != nil, "vault.status must include locked field for any caller")
    }
}

// MARK: - vault.simulate.device_lock / vault.simulate.device_unlock production denial

/// spec 7c2e9a14 W2: simulation verbs must be denied in production (no simulationLockSource).
/// This suite uses the same makeDispatcher() helper, which wires no simulationSource.
@Suite("VaultSimulateProductionDenialTests")
struct VaultSimulateProductionDenialTests {

    @Test("vault.simulate.device_lock is denied in production (no simulationSource)")
    func test_simulateDeviceLock_deniedInProduction() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let request = WireRequest(method: "vault.simulate.device_lock", params: nil, id: "sim-lock-1")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "sim-lock-1")
        #expect(response.result == nil, "simulation verb must not succeed in production")
        #expect(
            response.error?.code == WireErrorCode.denied,
            "simulation verb must return WireErrorCode.denied in production, got \(String(describing: response.error?.code))"
        )
        let msg = response.error?.message ?? ""
        #expect(
            msg.contains("not available in production"),
            "error message must say 'not available in production', got: \(msg)"
        )
    }

    @Test("vault.simulate.device_unlock is denied in production (no simulationSource)")
    func test_simulateDeviceUnlock_deniedInProduction() async throws {
        let (dispatcher, _, socket) = try await makeDispatcher()
        defer { Task { await socket.shutdown() } }

        let request = WireRequest(method: "vault.simulate.device_unlock", params: nil, id: "sim-unlock-1")
        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        #expect(response.id == "sim-unlock-1")
        #expect(response.result == nil, "simulation verb must not succeed in production")
        #expect(
            response.error?.code == WireErrorCode.denied,
            "simulation verb must return WireErrorCode.denied in production, got \(String(describing: response.error?.code))"
        )
        let msg = response.error?.message ?? ""
        #expect(
            msg.contains("not available in production"),
            "error message must say 'not available in production', got: \(msg)"
        )
    }
}
