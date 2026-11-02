import Foundation
@testable import ShiSecretsBrokerd
import ShiSecretsKit
import Testing

// SecretRotateE2ETests — in-process dispatcher round-trip for secret.rotate.
//
// Stack: BrokerDaemon → BrokerWireDispatcher (in-process, no real socket)
//
// Follows the same pattern as SecretsLifecycleTests and SecretsGetEndToEndTests:
// drive the full stack in-process via BrokerWireDispatcher.dispatch() directly,
// without a real Unix socket connection. ProductionBrokerClient wire-name coverage
// is provided separately by TCP-WN-05 in BrokerClientWireNameTests.
//
// TCP-E2E-ROT-01  rotate success — dispatcher gets back a RotationResult JSON
//                 object with matching secretName, non-empty oldJtiSuffix, and
//                 a non-empty invalidAt ISO-8601 timestamp.
//
// No real Vaultwarden, no Keychain, no network, no Unix socket.

// kagami-scope: ShiSecretsE2ETests

/// Stub rotation driver for the E2E test — always reports success.
private struct E2EStubRotationDriver: SecretRotationDriver {
    let vendor: String
    func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        _ = entry; _ = trigger
        return .rotated
    }
}

@Suite("SecretRotateE2E", .serialized)
struct SecretRotateE2ETests {

    // MARK: - TCP-E2E-ROT-01

    @Test("TCP-E2E-ROT-01: rotate dispatch — BrokerWireDispatcher returns RotationResult JSON")
    func test_clientRotate_roundTrip_returnsRotationResult() async throws {
        let stack = try await E2ESupport.make(
            scopeAllowlist: ["ovh/**", "ovh/OVH_APP_KEY"]
        )
        defer { Task { await E2ESupport.tearDown(stack) } }
        try await stack.daemon.start()

        // Register a stub driver for vendor "ovh".
        await stack.daemon.drivers.register(E2EStubRotationDriver(vendor: "ovh"))

        // Seed a vault entry in the engine so the dispatcher can look it up.
        await stack.engine.seed(entry: VaultEntryRef(
            name: "OVH_APP_KEY",
            scope: "ovh/OVH_APP_KEY",
            tier: .warm,
            usageState: .warm,
            lastRotated: Date(timeIntervalSinceNow: -3600),
            rotationDue: Date(timeIntervalSinceNow: -60)
        ))

        // Drive the full stack in-process (same pattern as SecretsLifecycleTests).
        let dispatcher = BrokerWireDispatcher(
            daemon: stack.daemon,
            bridge: await stack.daemon.bridge
        )

        // Build the wire request the same way ProductionBrokerClient.rotate does:
        //   params = { "name": "<secretName>" }, method = "secret.rotate"
        let request = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("OVH_APP_KEY")]),
            id: UUID().uuidString
        )

        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        // Must not return an error.
        #expect(response.error == nil,
                "TCP-E2E-ROT-01: expected success, got error: \(String(describing: response.error))")

        // Result must be a JSON object with the RotationResult fields.
        guard case let .object(obj) = response.result else {
            Issue.record("TCP-E2E-ROT-01: result is not a JSON object — got \(String(describing: response.result))")
            return
        }

        guard case let .string(secretName) = obj["secretName"] else {
            Issue.record("TCP-E2E-ROT-01: missing or wrong type for 'secretName' in \(obj)")
            return
        }
        guard case let .string(oldJtiSuffix) = obj["oldJtiSuffix"] else {
            Issue.record("TCP-E2E-ROT-01: missing or wrong type for 'oldJtiSuffix' in \(obj)")
            return
        }
        guard case let .string(invalidAt) = obj["invalidAt"] else {
            Issue.record("TCP-E2E-ROT-01: missing or wrong type for 'invalidAt' in \(obj)")
            return
        }

        #expect(secretName == "OVH_APP_KEY",
                "TCP-E2E-ROT-01: secretName must match the requested name")
        #expect(!oldJtiSuffix.isEmpty,
                "TCP-E2E-ROT-01: oldJtiSuffix must be non-empty")
        #expect(!invalidAt.isEmpty,
                "TCP-E2E-ROT-01: invalidAt must be non-empty ISO-8601 string")
    }
}
