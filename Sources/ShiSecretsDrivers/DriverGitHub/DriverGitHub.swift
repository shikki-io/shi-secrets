import Foundation
import ShiSecretsKit

// DriverGitHub — SecretRotationDriver conformance for GitHub fine-grained
// personal-access-token rotation (BR-B-03, BR-B-04).
//
// Sequence:
//   1. POST /user/tokens         → create a new PAT (new-token body)
//   2. write-back via BWClient   → vault now holds the new token
//   3. DELETE /user/tokens/:id   → invalidate(previous:) — revokes old PAT
//
// Admin token sourcing: vault entry named "GITHUB_ADMIN_TOKEN" with a "value"
// field. Create it before rotating: `shi secrets set GITHUB_ADMIN_TOKEN <pat>`.
//
// Rate-limit handling: when the create call returns `429`, the driver
// surfaces `.failed(reason: "rate_limited, retry_after=<n>s")`. The
// rotation engine's `handleFailure` path treats this like any other
// failure and enqueues retry at now+5min — Wave 5's CLI will surface
// the Retry-After duration for ops runbooks.

// MARK: - Typed Codable response models

/// The JSON object GitHub returns on a successful POST /user/tokens.
private struct GitHubCreateTokenResponse: Decodable {
    let token: String
}

// MARK: - DriverGitHub

public struct DriverGitHub: SecretRotationDriver {

    public var vendor: String { "github" }
    public let humanFallback: HumanRunbook? = nil
    private let transport: any DriverHTTPTransport
    private let bwClient: (any BWClientWriteBack)?
    private let baseURL: String

    public init(
        transport: any DriverHTTPTransport,
        bwClient: (any BWClientWriteBack)? = nil,
        baseURL: String = "https://api.github.com"
    ) {
        self.transport = transport
        self.bwClient = bwClient
        self.baseURL = baseURL
    }

    // MARK: - Admin token resolution

    /// Resolves the GitHub admin PAT from the vault. The token must be stored
    /// under the vault entry "GITHUB_ADMIN_TOKEN" with a "value" field.
    private func resolveAdminToken() async throws -> String {
        guard let bw = bwClient else {
            throw DriverError.vaultMisconfigured(
                reason: "bwClient not wired — cannot resolve admin token"
            )
        }
        let fields = try await bw.get(name: "GITHUB_ADMIN_TOKEN")
        let candidate = fields["value"] ?? ""
        guard !candidate.isEmpty else {
            throw DriverError.vaultMisconfigured(
                reason: "admin token 'GITHUB_ADMIN_TOKEN' not found in vault. " +
                        "Create a vault entry named 'GITHUB_ADMIN_TOKEN' with a 'value' field " +
                        "containing a GitHub PAT with fine-grained token admin scope, then retry."
            )
        }
        return candidate
    }

    // MARK: - SecretRotationDriver

    public func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        let adminToken: String
        do {
            adminToken = try await resolveAdminToken()
        } catch let e as DriverError {
            return .failed(reason: "github \(e.localizedDescription)")
        } catch {
            return .failed(reason: "github vault_misconfigured: \(error)")
        }
        let request = DriverHTTPRequest(
            method: "POST",
            url: baseURL + "/user/tokens",
            headers: [
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer \(adminToken)",
            ],
            body: nil
        )
        do {
            let response = try await transport.send(request)
            if response.status == 429 {
                let retryAfter = response.headers["Retry-After"] ?? "unknown"
                return .failed(reason: "rate_limited, retry_after=\(retryAfter)s")
            }
            guard response.status == 200 || response.status == 201 else {
                return .failed(reason: "github http \(response.status)")
            }
            // Typed decode — fail if the vendor rotated but the response is missing the token.
            let decoded: GitHubCreateTokenResponse
            do {
                decoded = try JSONDecoder().decode(GitHubCreateTokenResponse.self, from: response.body)
            } catch {
                return .failed(
                    reason: "github rotated at vendor but response missing required field " +
                            "'token' — vault not updated. Fetch the new PAT from GitHub and " +
                            "update the vault manually. Decode error: \(error)"
                )
            }
            guard let bw = bwClient else {
                return .failed(
                    reason: "github rotated at vendor but bwClient is nil — vault not updated. " +
                            "New token exists at vendor; update the vault manually."
                )
            }
            do {
                try await bw.update(name: entry.name, fields: ["token": decoded.token])
            } catch {
                return .failed(
                    reason: "github rotated at vendor but vault write-back failed — " +
                            "new token exists at vendor, vault still holds the old value. " +
                            "Update the vault manually. Write-back error: \(error)"
                )
            }
            _ = trigger
            return .rotated
        } catch {
            return .failed(reason: "github transport: \(error)")
        }
    }

    /// Revokes the previous PAT at GitHub. Throws on missing admin token,
    /// transport failure, or non-2xx so the caller can surface a
    /// "rotated but old credential NOT invalidated" warning.
    public func invalidate(previous: VaultEntryRef) async throws {
        let adminToken = try await resolveAdminToken()
        let request = DriverHTTPRequest(
            method: "DELETE",
            url: baseURL + "/user/tokens/\(previous.name)",
            headers: [
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer \(adminToken)",
            ],
            body: nil
        )
        let response = try await transport.send(request)
        guard (200 ..< 300).contains(response.status) else {
            throw DriverHTTPError.transportFailed(
                message: "github invalidate http \(response.status)"
            )
        }
    }

    // MARK: - Error catalogue

    public enum DriverError: Swift.Error, Sendable, Equatable {
        case vaultMisconfigured(reason: String)
    }
}
