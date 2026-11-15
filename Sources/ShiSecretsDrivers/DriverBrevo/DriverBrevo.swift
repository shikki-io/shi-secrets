import Foundation
import ShiSecretsKit

// DriverBrevo — SecretRotationDriver conformance for Brevo's
// transactional-email API key rotation (BR-B-03, BR-B-04).
//
// POSTs to `/v3/senders/api-keys` to create a new key, then issues a
// DELETE against the old key's id via `invalidate(previous:)`. The
// write-back carries the new `apiKey` so downstream consumers can swap
// on next fetch without seeing a gap.
//
// Admin key sourcing: vault entry named "BREVO_API_KEY" with a "value"
// field. Create it before rotating: `shi secrets set BREVO_API_KEY <key>`.
// Both the POST and DELETE require this header — never plaintext config.

// MARK: - Typed Codable response models

/// The JSON object Brevo returns on a successful POST /v3/senders/api-keys.
private struct BrevoCreateKeyResponse: Decodable {
    let apiKey: String
}

// MARK: - DriverBrevo

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

    // MARK: - Admin key resolution

    /// Resolves the Brevo admin API key from the vault. The key must be stored
    /// under the vault entry "BREVO_API_KEY" with a "value" field.
    private func resolveAdminKey() async throws -> String {
        guard let bw = bwClient else {
            throw DriverError.vaultMisconfigured(
                reason: "bwClient not wired — cannot resolve admin key"
            )
        }
        let fields = try await bw.get(name: "BREVO_API_KEY")
        let candidate = fields["value"] ?? ""
        guard !candidate.isEmpty else {
            throw DriverError.vaultMisconfigured(
                reason: "admin key 'BREVO_API_KEY' not found in vault. " +
                        "Create a vault entry named 'BREVO_API_KEY' with a 'value' field " +
                        "containing the Brevo admin API key, then retry."
            )
        }
        return candidate
    }

    // MARK: - SecretRotationDriver

    public func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        let adminKey: String
        do {
            adminKey = try await resolveAdminKey()
        } catch let e as DriverError {
            return .failed(reason: "brevo \(e.localizedDescription)")
        } catch {
            return .failed(reason: "brevo vault_misconfigured: \(error)")
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
            // Typed decode — fail if the vendor rotated the key but the response
            // doesn't carry the new value (vault would keep the stale key).
            let decoded: BrevoCreateKeyResponse
            do {
                decoded = try JSONDecoder().decode(BrevoCreateKeyResponse.self, from: response.body)
            } catch {
                return .failed(
                    reason: "brevo rotated at vendor but response missing required field " +
                            "'apiKey' — vault not updated. Fetch the new key from the Brevo " +
                            "dashboard and update the vault manually. Decode error: \(error)"
                )
            }
            // Write the new key to the vault. If this fails the vendor has already rotated;
            // surface the fact so the operator can recover.
            guard let bw = bwClient else {
                return .failed(
                    reason: "brevo rotated at vendor but bwClient is nil — vault not updated. " +
                            "New key exists at vendor; update the vault manually."
                )
            }
            do {
                try await bw.update(name: entry.name, fields: ["apiKey": decoded.apiKey])
            } catch {
                return .failed(
                    reason: "brevo rotated at vendor but vault write-back failed — " +
                            "new key exists at vendor, vault still holds the old value. " +
                            "Update the vault manually. Write-back error: \(error)"
                )
            }
            _ = trigger
            return .rotated
        } catch {
            return .failed(reason: "brevo transport: \(error)")
        }
    }

    /// Revokes the previous API key at Brevo. Throws on missing admin credential,
    /// transport failure, or a non-2xx response so the caller can surface a
    /// "rotated but old credential NOT invalidated" warning.
    public func invalidate(previous: VaultEntryRef) async throws {
        let adminKey = try await resolveAdminKey()
        let request = DriverHTTPRequest(
            method: "DELETE",
            url: baseURL + "/v3/senders/api-keys/\(previous.name)",
            headers: ["api-key": adminKey],
            body: nil
        )
        let response = try await transport.send(request)
        guard (200 ..< 300).contains(response.status) else {
            throw DriverHTTPError.transportFailed(
                message: "brevo invalidate http \(response.status)"
            )
        }
    }

    // MARK: - Error catalogue

    public enum DriverError: Swift.Error, Sendable, Equatable {
        case vaultMisconfigured(reason: String)
    }
}
