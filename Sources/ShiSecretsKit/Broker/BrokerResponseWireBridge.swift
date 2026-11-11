import Foundation

// BrokerResponseWireBridge — encodes the in-process `BrokerResponse`
// enum onto the JSON-RPC `WireResponse` surface.
//
// Phase 0.3b (BR-G-04 wire half) of features/shikkisecrets-broker-completion.md.
//
// This is the encoder half of the bridge. The decoder half (dispatch
// table that maps JSON-RPC method names → BrokerDaemon handler) is
// Phase 0.3c, blocked on the daemon's handler surface expanding to
// cover the full 10-method JSON-RPC namespace
// (secret.{get,list,set,rotate}, token.{revoke,…}, audit.{…}).
//
// Each non-deny case becomes a JSONValue result envelope with a
// discriminator `type` field; `.deny(reason)` maps to a `WireError` with
// a broker-specific code derived from `DenyReason`.

extension BrokerResponse {

    /// Encode this `BrokerResponse` as a JSON-RPC `WireResponse` for a
    /// request with the given id.
    ///
    /// On success cases, the `result` is a JSONValue with shape
    /// `{ "type": "<case>", ...case-specific fields }`. On `.deny`, the
    /// `WireResponse.error` carries the closed-set `DenyReason` as both
    /// the JSON-RPC code (see `WireErrorCode.deny*` mapping) and the
    /// string in `error.data.reason`.
    public func toWireResponse(id: String?) throws -> WireResponse {
        switch self {

        case .ephemeralToken(let sbt):
            let claimsValue = try jsonValue(encoding: sbt.claims)
            let payload: [String: JSONValue] = [
                "type": .string("ephemeralToken"),
                "claims": claimsValue,
            ]
            return WireResponse(id: id, result: .object(payload))

        case .boundPlaintext(let jti, let plaintext):
            let payload: [String: JSONValue] = [
                "type": .string("boundPlaintext"),
                "jti": .string(jti),
                "plaintext": .string(plaintext),
            ]
            return WireResponse(id: id, result: .object(payload))

        case .dbCredentials(let jti, let creds, let policy):
            let payload: [String: JSONValue] = [
                "type": .string("dbCredentials"),
                "jti": .string(jti),
                "credentials": try jsonValue(encoding: creds),
                "policy": try jsonValue(encoding: policy),
            ]
            return WireResponse(id: id, result: .object(payload))

        case .oauthPair(let jti, let pair, let policy):
            let payload: [String: JSONValue] = [
                "type": .string("oauthPair"),
                "jti": .string(jti),
                "pair": try jsonValue(encoding: pair),
                "policy": try jsonValue(encoding: policy),
            ]
            return WireResponse(id: id, result: .object(payload))

        case .connectionBundle(let jti, let bundle, let policy):
            let payload: [String: JSONValue] = [
                "type": .string("connectionBundle"),
                "jti": .string(jti),
                "bundle": try jsonValue(encoding: bundle),
                "policy": try jsonValue(encoding: policy),
            ]
            return WireResponse(id: id, result: .object(payload))

        case .deny(let reason):
            if let auth = VaultAuthRequired(denyReason: reason) {
                return WireResponse(id: id, error: auth.wireError())
            }
            let code = wireCode(for: reason)
            let dataPayload: JSONValue = .object([
                "reason": .string(reason.rawValue),
            ])
            return WireResponse(
                id: id,
                error: WireError(code: code, message: "Denied: \(reason.rawValue)", data: dataPayload)
            )
        }
    }

    /// Map a closed-set `DenyReason` to its JSON-RPC error code. Codes
    /// already-defined in `WireErrorCode` are reused; everything else
    /// falls through to the broker-generic `denied = -32000`.
    private func wireCode(for reason: AuditRow.DenyReason) -> Int {
        switch reason {
        case .scopeDenied, .scopePatternDenied, .scopeTooLong:
            return WireErrorCode.scopeViolation
        case .manifestSigFailed, .brokerSessionInvalid:
            return WireErrorCode.bootstrapFailed
        default:
            return WireErrorCode.denied
        }
    }
}

/// Encode any `Encodable` as a `JSONValue` via a JSON round-trip. This
/// keeps the bridge from caring about the specific Codable structures
/// (`Claims`, `DBCredentials`, `RefreshPolicy`, …) — they each ship
/// their own Codable conformance and we just rehydrate the encoded
/// payload into the schema-agnostic JSONValue tree.
private func jsonValue<T: Encodable>(encoding value: T) throws -> JSONValue {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let data = try encoder.encode(value)
    return try JSONDecoder().decode(JSONValue.self, from: data)
}
