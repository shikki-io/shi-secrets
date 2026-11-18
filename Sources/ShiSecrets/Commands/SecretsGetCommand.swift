// SecretsGetCommand — `shi secrets get <uri> [--ephemeral|--value]`
//
// Resolves a single shi-secret:// URI.
// Default: returns ephemeral token (not plaintext).
// --value flag returns plaintext; audit-logged + warned per BR-SSEC-05.
// TP-SSEC-08: get URI --ephemeral returns token; --value returns plaintext + audit-warn.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsClient
import ShiSecretsKit

/// `shi secrets get <uri> [--ephemeral] [--value] [--json]`
public struct SecretsGetCommand {

    public let uri: String
    public let ephemeral: Bool
    public let value: Bool
    public let json: Bool

    public init(uri: String, ephemeral: Bool = false, value: Bool = false, json: Bool = false) {
        self.uri = uri
        self.ephemeral = ephemeral
        self.value = value
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        // Validate URI format first.
        let parsedURI: ShiSecretURI
        do {
            parsedURI = try ShiSecretURI.parse(uri)
        } catch {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            return 1
        }

        let client = ShiSecretsAPIClient(socket: brokerSocket)

        if value {
            // BR-SSEC-05: plaintext requires explicit flag; audit-logged + warned.
            fputs("WARNING: --value returns plaintext. This resolve is audit-logged.\n", stderr)
            do {
                let plaintext = try await client.resolveValue(uri: parsedURI)
                if json {
                    let escaped = plaintext
                        .replacingOccurrences(of: "\\", with: "\\\\")
                        .replacingOccurrences(of: "\"", with: "\\\"")
                    print("{\"uri\":\"\(uri)\",\"value\":\"\(escaped)\"}")
                } else {
                    print(plaintext)
                }
                return 0
            } catch {
                if let code = reportVaultAuthRequired(error, json: json) { return code }
                fputs("ERROR: \(error.localizedDescription)\n", stderr)
                return 1
            }
        } else {
            // Default: ephemeral token (BR-SSEC-05).
            do {
                let token = try await client.requestEphemeral(uri: parsedURI)
                if json {
                    print("{\"uri\":\"\(uri)\",\"ephemeral_token\":\"\(token)\"}")
                } else {
                    print(token)
                }
                return 0
            } catch {
                if let code = reportVaultAuthRequired(error, json: json) { return code }
                fputs("ERROR: \(error.localizedDescription)\n", stderr)
                return 1
            }
        }
    }
}
