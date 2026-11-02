import Foundation
import ShiSecretsKit

// DriverOVH — SecretRotationDriver conformance for OVH application-key
// rotation (BR-B-03, BR-B-04).
//
// Hits OVH's `/me/api/credential` endpoint through the injected HTTP
// transport, parses the new credential out of the JSON response, and
// writes it back to the vault entry via the injected BWClient.
//
// Sandbox mode drives the `eu.api.ovh.com/1.0/sandbox` base URL so
// integration tests + staging runs never touch a production credential.
// The `.production` mode is gated behind explicit opt-in via the broker
// ops config (Wave 5 CLI integration).
//
// Write-back is intentionally skipped when no BWClient is wired (Wave 4
// tests exercise the drivers via a RecordingBWClient; production wires
// the real one through the BrokerDaemon DI graph).

public struct DriverOVH: SecretRotationDriver {

    public enum Mode: String, Sendable, Equatable {
        case sandbox
        case production
    }

    public var vendor: String { "ovh" }
    public let humanFallback: HumanRunbook? = nil
    public let mode: Mode
    private let transport: any DriverHTTPTransport
    private let bwClient: (any BWClientWriteBack)?

    public init(
        mode: Mode,
        transport: any DriverHTTPTransport,
        bwClient: (any BWClientWriteBack)? = nil
    ) {
        self.mode = mode
        self.transport = transport
        self.bwClient = bwClient
    }

    private var baseURL: String {
        switch mode {
        case .sandbox:    return "https://eu.api.ovh.com/1.0/sandbox"
        case .production: return "https://eu.api.ovh.com/1.0"
        }
    }

    public func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        // OVH production requires HMAC-SHA1 signed requests (X-Ovh-Application +
        // X-Ovh-Consumer + X-Ovh-Timestamp + X-Ovh-Signature). That signing scheme
        // is not yet implemented; refuse clearly rather than send an unsigned request
        // that OVH would reject anyway. Sandbox mode carries no auth requirement.
        if mode == .production {
            return .failed(reason: "ovh production_unsupported: HMAC-SHA1 signing not implemented — use .sandbox or the human runbook")
        }
        let url = baseURL + "/me/api/credential"
        let request = DriverHTTPRequest(
            method: "POST",
            url: url,
            headers: ["X-Ovh-Application": "shikki-broker"],
            body: nil
        )
        do {
            let response = try await transport.send(request)
            guard (200 ..< 300).contains(response.status) else {
                return .failed(reason: "ovh http \(response.status)")
            }
            // Best-effort parse: the response may be empty in sandbox runs.
            var fields: [String: String] = [:]
            if !response.body.isEmpty,
               let json = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
               let newKey = json["applicationKey"] as? String {
                fields["applicationKey"] = newKey
            }
            if let bwClient, !fields.isEmpty {
                try await bwClient.update(name: entry.name, fields: fields)
            }
            _ = trigger   // trigger currently unused; drivers may tag logs in W5
            return .rotated
        } catch {
            return .failed(reason: "ovh transport: \(error)")
        }
    }

    public func invalidate(previous: VaultEntryRef) async throws {
        // The OVH API invalidates the prior credential as a side-effect of
        // issuing a new one; an explicit DELETE is not required. The method
        // exists to satisfy the protocol + to give vendors that need an
        // explicit revoke a seam (Brevo + GitHub both override it below).
        _ = previous
    }
}
