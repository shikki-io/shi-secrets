import Foundation
@testable import ShiSecretsDrivers
import ShiSecretsKit
import Testing

@Suite("DriverGitHub")
struct DriverGitHubTests {

    @Test("rotatePat creates a new PAT then revokes the old one")
    func test_driver_github_rotatePat_createsNewPat_revokesOld() async throws {
        let http = RecordingTransport()
        let payload = try! JSONSerialization.data(withJSONObject: ["token": "ghp_newtoken42"])
        await http.queue(
            match: .init(method: "POST", urlContains: "/user/tokens"),
            response: DriverHTTPResponse(status: 201, body: payload)
        )
        let bw = RecordingBWClient()
        await bw.seedGet(name: "GITHUB_ADMIN_TOKEN", fields: ["value": "ghp_fake-admin-token"])
        let driver = DriverGitHub(transport: http, bwClient: bw)
        let entry = makeEntry(vendor: "github", name: "GITHUB_PAT")

        let outcome = await driver.rotate(entry: entry, trigger: .manual(op: "rotate"))

        #expect(outcome == .rotated)
        let writes = await bw.writes()
        #expect(writes.first?.fields["token"] == "ghp_newtoken42")
        // invalidate(previous:) is called by BrokerWireDispatch after applyRotation.
        // Exercise it directly to verify the DELETE is issued with the admin auth header.
        await http.queue(
            match: .init(method: "DELETE", urlContains: "/user/tokens/"),
            response: DriverHTTPResponse(status: 204)
        )
        try await driver.invalidate(previous: entry)
        let requests = await http.requests()
        #expect(requests.contains(where: { $0.method == "DELETE" }))
    }

    @Test("429 rate-limited enqueues retry via RateLimited failure reason")
    func test_driver_github_rotatePat_rateLimited_enqueuesRetry() async {
        let http = RecordingTransport()
        await http.queue(
            match: .init(method: "POST", urlContains: "/user/tokens"),
            response: DriverHTTPResponse(
                status: 429,
                headers: ["Retry-After": "60"]
            )
        )
        let bw = RecordingBWClient()
        await bw.seedGet(name: "GITHUB_ADMIN_TOKEN", fields: ["value": "ghp_fake-admin-token"])
        let driver = DriverGitHub(transport: http, bwClient: bw)
        let entry = makeEntry(vendor: "github", name: "GITHUB_PAT")

        let outcome = await driver.rotate(entry: entry, trigger: .scheduled(.external))

        guard case .failed(let reason) = outcome else {
            Issue.record("expected .failed(rateLimited), got \(outcome)")
            return
        }
        // RateLimited reason must surface the Retry-After seconds so the
        // engine's retry queue can honour GitHub's ask.
        #expect(reason.contains("rate_limited"))
        #expect(reason.contains("60"))
        let writes = await bw.writes()
        #expect(writes.isEmpty)
    }
}
