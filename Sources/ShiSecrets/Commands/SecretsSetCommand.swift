// SecretsSetCommand — `shi secrets set <uri>=<value>`
//
// Writes a secret through broker → backend.
// Invalidates cache on success.
// TP-SSEC-09: writes through broker → backend, invalidates cache.
//
// W3+W4 of features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md.

import Foundation
import ShiSecretsClient
import ShiSecretsKit

/// `shi secrets set <uri>=<value> [--json]`
///
/// Value may be supplied as `<uri>=<value>` positional argument,
/// or as `-` to read from stdin (avoids shell history per BR-CRED-01).
public struct SecretsSetCommand {

    public let uriEqualsValue: String
    public let json: Bool

    public init(uriEqualsValue: String, json: Bool = false) {
        self.uriEqualsValue = uriEqualsValue
        self.json = json
    }

    public func run(brokerSocket: String) async throws -> Int32 {
        // Parse `<uri>=<value>` form.
        guard let eqIdx = uriEqualsValue.firstIndex(of: "=") else {
            fputs("ERROR: argument must be in <uri>=<value> form.\n", stderr)
            return 1
        }
        let rawURI = String(uriEqualsValue[uriEqualsValue.startIndex..<eqIdx])
        let rawValue = String(uriEqualsValue[uriEqualsValue.index(after: eqIdx)...])

        // Resolve value: "-" means read from stdin.
        let resolvedValue: String
        if rawValue == "-" {
            guard let line = readLine(strippingNewline: true) else {
                fputs("ERROR: no value on stdin\n", stderr)
                return 1
            }
            resolvedValue = line
        } else {
            resolvedValue = rawValue
        }

        let parsedURI: ShiSecretURI
        do {
            parsedURI = try ShiSecretURI.parse(rawURI)
        } catch {
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            return 1
        }

        let client = ShiSecretsAPIClient(socket: brokerSocket)
        do {
            try await client.set(uri: parsedURI, value: resolvedValue)
            if json {
                print("{\"uri\":\"\(rawURI)\",\"status\":\"ok\"}")
            } else {
                fputs("set \(rawURI) OK\n", stderr)
            }
            return 0
        } catch {
            if let code = reportVaultAuthRequired(error, json: json) { return code }
            fputs("ERROR: \(error.localizedDescription)\n", stderr)
            return 1
        }
    }
}
