import Foundation
@testable import ShiSecretsDrivers
import ShiSecretsKit
import Testing

@Suite("AllVendorsAnomaly")
struct AllVendorsAnomalyTests {

    /// Simulated-clock envelope for the anomaly-path contract (BR-B-07,
    /// BR-C-08). Each driver must complete `.anomaly` rotation within 60s
    /// of wall-clock — the parameterized run scripts a 200 OK in under
    /// a millisecond so the ceiling is trivially satisfied.
    @Test(
        "every v1 driver responds to anomaly trigger within 60s, returns .rotated",
        arguments: ["ovh", "brevo", "github"]
    )
    func test_driver_allVendors_respondToAnomalySignal_immediateRotation(vendor: String) async {
        let http = RecordingTransport()
        // Script a success for each vendor's create endpoint.
        await http.queue(
            match: .init(method: "POST", urlContains: "/me/api/credential"),
            response: DriverHTTPResponse(
                status: 200,
                body: try! JSONSerialization.data(withJSONObject: ["applicationKey": "new-ovh"])
            )
        )
        await http.queue(
            match: .init(method: "POST", urlContains: "/v3/senders/api-keys"),
            response: DriverHTTPResponse(
                status: 201,
                body: try! JSONSerialization.data(withJSONObject: ["apiKey": "new-brevo"])
            )
        )
        await http.queue(
            match: .init(method: "POST", urlContains: "/user/tokens"),
            response: DriverHTTPResponse(
                status: 201,
                body: try! JSONSerialization.data(withJSONObject: ["token": "ghp_new"])
            )
        )
        // Brevo + GitHub require an admin credential resolved from vault.
        // Seed a fake entry so the driver can resolve it without network access.
        let bw = RecordingBWClient()
        await bw.seedGet(name: "BREVO_API_KEY", fields: ["value": "fake-brevo-admin-key"])
        await bw.seedGet(name: "GITHUB_ADMIN_TOKEN", fields: ["value": "ghp_fake-admin-token"])
        let driver: any SecretRotationDriver = {
            switch vendor {
            case "ovh":    return DriverOVH(mode: .sandbox, transport: http)
            case "brevo":  return DriverBrevo(transport: http, bwClient: bw)
            case "github": return DriverGitHub(transport: http, bwClient: bw)
            default:       fatalError("unknown vendor \(vendor)")
            }
        }()
        let entry = makeEntry(vendor: vendor, name: "\(vendor.uppercased())_KEY")

        let start = Date()
        let outcome = await driver.rotate(
            entry: entry,
            trigger: .anomaly(.hibp(breachId: "contract-test"))
        )
        let elapsed = Date().timeIntervalSince(start)

        #expect(outcome == .rotated)
        #expect(elapsed < 60.0)
    }
}
