import Foundation
@testable import ShiSecretsDrivers
import ShiSecretsKit
import Testing

@Suite("DriverBrevo")
struct DriverBrevoTests {

    @Test("rotateApiKey calls the Brevo /v3/senders/api-keys endpoint")
    func test_driver_brevo_rotateApiKey_callsBrevoKeysEndpoint() async {
        let http = RecordingTransport()
        let payload = try! JSONSerialization.data(withJSONObject: ["apiKey": "new-brevo-123"])
        await http.queue(
            match: .init(method: "POST", urlContains: "/v3/senders/api-keys"),
            response: DriverHTTPResponse(status: 200, body: payload)
        )
        let bw = RecordingBWClient()
        await bw.seedGet(name: "BREVO_API_KEY", fields: ["value": "fake-admin-brevo-key"])
        let driver = DriverBrevo(transport: http, bwClient: bw)
        let entry = makeEntry(vendor: "brevo", name: "BREVO_API_KEY")

        let outcome = await driver.rotate(entry: entry, trigger: .manual(op: "rotate"))

        #expect(outcome == .rotated)
        let requests = await http.requests()
        #expect(requests.contains(where: { $0.url.contains("/v3/senders/api-keys") && $0.method == "POST" }))
        let writes = await bw.writes()
        #expect(writes.first?.fields["apiKey"] == "new-brevo-123")
    }

    @Test("unauthorized returns .failed and does not mutate the vault")
    func test_driver_brevo_rotate_unauthorized_returnsFailure() async {
        let http = RecordingTransport()
        await http.queue(
            match: .init(method: "POST", urlContains: "/v3/senders/api-keys"),
            response: DriverHTTPResponse(status: 401)
        )
        let bw = RecordingBWClient()
        await bw.seedGet(name: "BREVO_API_KEY", fields: ["value": "fake-admin-brevo-key"])
        let driver = DriverBrevo(transport: http, bwClient: bw)
        let entry = makeEntry(vendor: "brevo", name: "BREVO_API_KEY")

        let outcome = await driver.rotate(entry: entry, trigger: .scheduled(.warm))

        guard case .failed = outcome else {
            Issue.record("expected .failed, got \(outcome)")
            return
        }
        let writes = await bw.writes()
        #expect(writes.isEmpty)
    }
}
