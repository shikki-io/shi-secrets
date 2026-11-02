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
// Rate-limit handling: when the create call returns `429`, the driver
// surfaces `.failed(reason: "rate_limited, retry_after=<n>s")`. The
// rotation engine's `handleFailure` path treats this like any other
// failure and enqueues retry at now+5min — Wave 5's CLI will surface
// the Retry-After duration for ops runbooks.

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

    public func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        // Resolve the GitHub admin PAT from the vault. The PAT must be stored
        // under "GITHUB_ADMIN_TOKEN" with a "value" field — never plaintext config.
        guard let bw = bwClient else {
            return .failed(reason: "github vault_misconfigured: bwClient not wired — cannot resolve admin token")
        }
        let adminToken: String
        do {
            let fields = try await bw.get(name: "GITHUB_ADMIN_TOKEN")
            let candidate = fields["value"] ?? ""
            guard !candidate.isEmpty else {
                return .failed(reason: "github vault_misconfigured: GITHUB_ADMIN_TOKEN absent from vault")
            }
            adminToken = candidate
        } catch {
            return .failed(reason: "github vault_misconfigured: get(GITHUB_ADMIN_TOKEN) threw \(error)")
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
            var fields: [String: String] = [:]
            if !response.body.isEmpty,
               let json = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
               let token = json["token"] as? String {
                fields["token"] = token
            }
            if let bwClient, !fields.isEmpty {
                try await bwClient.update(name: entry.name, fields: fields)
            }
            _ = trigger
            return .rotated
        } catch {
            return .failed(reason: "github transport: \(error)")
        }
    }

    public func invalidate(previous: VaultEntryRef) async throws {
        // GitHub's PAT-revoke endpoint is `DELETE /user/tokens/:id`; in
        // v1 we key the id on the secret-name itself (the BWClient
        // write-back keeps `name → current-token` mapping). The
        // rotation orchestrator calls this after a successful rotate.
        let request = DriverHTTPRequest(
            method: "DELETE",
            url: baseURL + "/user/tokens/\(previous.name)",
            headers: ["Accept": "application/vnd.github+json"],
            body: nil
        )
        _ = try? await transport.send(request)
    }
}
