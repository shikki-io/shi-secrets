// SecretsListCommand — `shi secrets list [--namespace <ns>] [--json]`
//
// Lists available secret URIs (names only, NEVER values).
// TP-SSEC-07: returns valid JSON array of URIs with no values leaked.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsClient
import ShiSecretsKit

/// `shi secrets list [--namespace <ns>] [--json]`
public struct SecretsListCommand {

    public let namespace: String?
    public let json: Bool

    public init(namespace: String? = nil, json: Bool = false) {
        self.namespace = namespace
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        // Connect to broker and list URIs filtered by namespace.
        let client = ShiSecretsAPIClient(socket: brokerSocket)
        do {
            let uris = try await client.listURIs(namespace: namespace)
            if json {
                let arr = "[" + uris.map { "\"\($0)\"" }.joined(separator: ", ") + "]"
                print(arr)
            } else {
                if uris.isEmpty {
                    fputs("(no entries)\n", stderr)
                } else {
                    uris.forEach { print($0) }
                }
            }
            return 0
        } catch {
            if let code = reportVaultAuthRequired(error, json: json) { return code }
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}
