import Foundation
@testable import ShiSecretsBrokerd
@testable import ShiSecretsDrivers
import ShiSecretsKit
import Testing

// MARK: - Local transport stub (not shared with ShiSecretsDriversTests)

/// Minimal recording HTTP transport for this test target.
private actor E2ECapturingTransport: DriverHTTPTransport {
    private var _requests: [DriverHTTPRequest] = []
    private var _scripted: [(method: String, urlFragment: String, response: DriverHTTPResponse)] = []
    private let _defaultResponse: DriverHTTPResponse

    init(defaultStatus: Int = 200) {
        _defaultResponse = DriverHTTPResponse(status: defaultStatus)
    }

    func queue(method: String, urlFragment: String, response: DriverHTTPResponse) {
        _scripted.append((method, urlFragment, response))
    }

    nonisolated func send(_ request: DriverHTTPRequest) async throws -> DriverHTTPResponse {
        await record(request)
    }

    private func record(_ request: DriverHTTPRequest) -> DriverHTTPResponse {
        _requests.append(request)
        for (i, entry) in _scripted.enumerated() {
            if entry.method == request.method && request.url.contains(entry.urlFragment) {
                _scripted.remove(at: i)
                return entry.response
            }
        }
        return _defaultResponse
    }

    func requests() -> [DriverHTTPRequest] { _requests }
}

// SecretRotateProductionCompositionTests — verifies that the production DI
// composition (allV1Drivers wired into the dispatcher) works end-to-end with
// only the HTTP transport faked, not a pre-seeded engine registry.
//
// TCP-E2E-COMP-01  rotate via production-composed drivers — the dispatcher
//                  resolves the vault entry from bwClient (not engine), picks
//                  the real DriverBrevo instance, and completes rotation using
//                  a scripted HTTP transport. This test:
//                    • FAILED on commit 3d71ddb because the dispatcher called
//                      daemon.engine.entry(name:) which always returned nil
//                      when no engine.seed() call was made.
//                    • PASSES after the fix because the dispatcher calls
//                      daemon.bwClient.get(name:) instead.
//
// No real Vaultwarden, no Keychain, no network, no Unix socket.

// kagami-scope: ShiSecretsE2ETests

@Suite("SecretRotateProductionComposition", .serialized)
struct SecretRotateProductionCompositionTests {

    // MARK: - TCP-E2E-COMP-01

    @Test("TCP-E2E-COMP-01: rotate via allV1Drivers composition resolves vault entry from bwClient")
    func test_rotate_productionComposition_resolveFromVault_succeeds() async throws {
        let stack = try await E2ESupport.make(
            scopeAllowlist: ["brevo/**", "brevo/BREVO_API_KEY"]
        )
        defer { Task { await E2ESupport.tearDown(stack) } }
        try await stack.daemon.start()

        // Wire a fake HTTP transport so no real Brevo network call is made.
        let fakeTransport = E2ECapturingTransport()
        await fakeTransport.queue(
            method: "POST",
            urlFragment: "/v3/senders/api-keys",
            response: DriverHTTPResponse(
                status: 201,
                body: try JSONSerialization.data(withJSONObject: ["apiKey": "new-brevo-key-e2e"])
            )
        )

        // Register all production-composition drivers (real vendor logic, fake HTTP).
        let productionDrivers = allV1Drivers(transport: fakeTransport, bwClient: stack.bwClient)
        for driver in productionDrivers {
            await stack.daemon.drivers.register(driver)
        }

        // Unlock the vault and seed the secret entry. The dispatcher reads from
        // bwClient, NOT the engine — no engine.seed() call needed.
        try await stack.bwClient.unlock(masterPassword: "e2e-unlock", email: "e2e@test")
        await stack.bwClient.seedFakeEntry(
            name: "BREVO_API_KEY",
            fields: ["scope": "brevo/BREVO_API_KEY", "value": "test-brevo-credential"]
        )
        // The Brevo driver also reads its admin key from vault.
        // "BREVO_API_KEY" already seeded above — the same entry serves both purposes
        // since DriverBrevo reads get("BREVO_API_KEY")["value"] for the Authorization header.

        let dispatcher = BrokerWireDispatcher(
            daemon: stack.daemon,
            bridge: await stack.daemon.bridge
        )

        let request = WireRequest(
            method: "secret.rotate",
            params: .object(["name": .string("BREVO_API_KEY")]),
            id: UUID().uuidString
        )

        let response = await dispatcher.dispatch(request, peerUid: UInt32(geteuid()))

        // The dispatcher must return a RotationResult JSON object.
        #expect(
            response.error == nil,
            "TCP-E2E-COMP-01: expected success, got error: \(String(describing: response.error))"
        )

        guard case let .object(obj) = response.result else {
            Issue.record("TCP-E2E-COMP-01: result is not a JSON object — got \(String(describing: response.result))")
            return
        }

        guard case let .string(secretName) = obj["secretName"] else {
            Issue.record("TCP-E2E-COMP-01: missing 'secretName' in result \(obj)")
            return
        }
        #expect(secretName == "BREVO_API_KEY",
                "TCP-E2E-COMP-01: secretName must match the requested name")

        // The fake transport must have been called — proving the real driver was used.
        let httpRequests = await fakeTransport.requests()
        #expect(
            httpRequests.contains(where: { $0.url.contains("/v3/senders/api-keys") }),
            "TCP-E2E-COMP-01: expected a call to the Brevo endpoint via allV1Drivers"
        )
    }
}
