import Foundation
import ShiSecretsKit

// DriverBrevo — SecretRotationDriver conformance for Brevo's
// transactional-email API key rotation (BR-B-03, BR-B-04).
//
// POSTs to `/v3/senders/api-keys` to create a new key, then issues a
// DELETE against the old key's id (when the caller's VaultEntryRef
// carries the prior id). The write-back carries the new `apiKey` so
// downstream consumers can swap on next fetch without seeing a gap.
//
// Brevo requires `api-key` auth on every request; the header is left
// empty here so tests can assert the header presence without hard-coding
// the actual broker auth string — production wires it at BrokerDaemon
// construction time.

public struct DriverBrevo: SecretRotationDriver {

    public var vendor: String { "brevo" }
    public let humanFallback: HumanRunbook? = nil
    private let transport: any DriverHTTPTransport
    private let bwClient: (any BWClientWriteBack)?
    private let baseURL: String

    public init(
        transport: any DriverHTTPTransport,
        bwClient: (any BWClientWriteBack)? = nil,
        baseURL: String = "https://api.brevo.com"
    ) {
        self.transport = transport
        self.bwClient = bwClient
        self.baseURL = baseURL
    }

    public func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        // Resolve the Brevo admin API key from the vault. The key must be stored
        // under "BREVO_API_KEY" with a "value" field — never plaintext config.
        guard let bw = bwClient else {
            return .failed(reason: "brevo vault_misconfigured: bwClient not wired — cannot resolve admin key")
        }
        let adminKey: String
        do {
            let fields = try await bw.get(name: "BREVO_API_KEY")
            let candidate = fields["value"] ?? ""
            guard !candidate.isEmpty else {
                return .failed(reason: "brevo vault_misconfigured: BREVO_API_KEY absent from vault")
            }
            adminKey = candidate
        } catch {
            return .failed(reason: "brevo vault_misconfigured: get(BREVO_API_KEY) threw \(error)")
        }
        let request = DriverHTTPRequest(
            method: "POST",
            url: baseURL + "/v3/senders/api-keys",
            headers: ["api-key": adminKey],
            body: nil
        )
        do {
            let response = try await transport.send(request)
            guard response.status == 200 || response.status == 201 else {
                return .failed(reason: "brevo http \(response.status)")
            }
            var fields: [String: String] = [:]
            if !response.body.isEmpty,
               let json = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
               let newKey = json["apiKey"] as? String {
                fields["apiKey"] = newKey
            }
            if let bwClient, !fields.isEmpty {
                try await bwClient.update(name: entry.name, fields: fields)
            }
            _ = trigger
            return .rotated
        } catch {
            return .failed(reason: "brevo transport: \(error)")
        }
    }

    public func invalidate(previous: VaultEntryRef) async throws {
        // DELETE of the old api-key is a single round-trip; swallow non-2xx
        // here since invalidation failure must not re-fail the rotation
        // itself (engine already updated last_rotated).
        // Best-effort: if we cannot resolve the admin key, skip the DELETE.
        guard let bw = bwClient,
              let fields = try? await bw.get(name: "BREVO_API_KEY"),
              let adminKey = fields["value"], !adminKey.isEmpty else {
            return
        }
        let request = DriverHTTPRequest(
            method: "DELETE",
            url: baseURL + "/v3/senders/api-keys/\(previous.name)",
            headers: ["api-key": adminKey],
            body: nil
        )
        _ = try? await transport.send(request)
    }
}
