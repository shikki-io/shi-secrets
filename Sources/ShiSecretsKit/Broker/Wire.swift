import Foundation

// Wire — JSON-RPC 2.0 envelope for the ShiSecrets broker socket transport.
//
// Phase 0.1 (BR-G-01 socket accept loop + BR-G-02 wire framing per
// features/shikkisecrets-broker-completion.md).
//
// Live in `ShiSecretsKit` (not `ShiSecretsBrokerd`) so the future
// `ShiSecretsClient` library target can import them without taking a
// dep on the daemon.
//
// Framing: newline-delimited JSON (NDJSON). Each frame is one JSON
// object terminated by `\n` (0x0A). Frames MUST NOT contain unescaped
// newlines. Max frame size: 65536 bytes (BR-WIRE-01). Larger frames are
// rejected with `-32600 InvalidRequest`.
//
// Method names follow `<namespace>.<verb>` (e.g. `secret.get`,
// `token.revoke`). The daemon-side bridge (Phase 0.2) maps wire methods
// to BrokerRequest / handleRequest call paths.

/// Maximum wire frame size in bytes. Anything larger is rejected before
/// JSON decode runs (BR-WIRE-01).
public let WireMaxFrameSize: Int = 65_536

/// JSON-RPC 2.0 standard error codes (subset used by the broker).
public enum WireErrorCode {
    public static let parseError      = -32700
    public static let invalidRequest  = -32600
    public static let methodNotFound  = -32601
    public static let invalidParams   = -32602
    public static let internalError   = -32603
    // Broker-specific (per BR-G-04 deny reasons mapped to wire space).
    public static let denied          = -32000
    public static let scopeViolation  = -32001
    public static let rateLimit       = -32002
    public static let bootstrapFailed = -32003
    // Expected vault states (not faults): the caller must act, and the
    // error `data` carries the machine-readable reason and the remedy
    // command. See `VaultAuthRequired`. -32603 stays for real internal errors.
    public static let notLoggedIn     = -32004
    public static let vaultLocked     = -32005
}

/// Untyped JSON tree for `params` and `result` payloads where the wire
/// envelope must stay schema-agnostic. Method-specific decoders pull
/// concrete params out of this via `.decode(_:)` helpers (Phase 0.2).
public enum JSONValue: Codable, Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let v = try? c.decode(Bool.self)              { self = .bool(v);   return }
        if let v = try? c.decode(Int64.self)             { self = .int(v);    return }
        if let v = try? c.decode(Double.self)            { self = .double(v); return }
        if let v = try? c.decode(String.self)            { self = .string(v); return }
        if let v = try? c.decode([JSONValue].self)       { self = .array(v);  return }
        if let v = try? c.decode([String: JSONValue].self) { self = .object(v); return }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unrecognized JSON value")
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null:           try c.encodeNil()
        case .bool(let v):    try c.encode(v)
        case .int(let v):     try c.encode(v)
        case .double(let v):  try c.encode(v)
        case .string(let v):  try c.encode(v)
        case .array(let v):   try c.encode(v)
        case .object(let v):  try c.encode(v)
        }
    }
}

/// A JSON-RPC 2.0 request frame.
public struct WireRequest: Codable, Sendable, Equatable {
    /// Always `"2.0"`. Validated on decode.
    public let jsonrpc: String
    /// `<namespace>.<verb>` form, e.g. `secret.get`, `token.revoke`.
    public let method: String
    /// Method-specific params. Schema-agnostic at the envelope layer.
    public let params: JSONValue?
    /// Request id; if nil the request is a notification (no response expected).
    public let id: String?

    public init(method: String, params: JSONValue? = nil, id: String?) {
        self.jsonrpc = "2.0"
        self.method = method
        self.params = params
        self.id = id
    }
}

/// A JSON-RPC 2.0 response frame. Exactly one of `result` or `error` is
/// non-nil (validated on decode).
public struct WireResponse: Codable, Sendable, Equatable {
    /// Always `"2.0"`. Validated on decode.
    public let jsonrpc: String
    /// Matches the request `id`; may be nil for parse errors before any
    /// id could be recovered.
    public let id: String?
    /// Present on success.
    public let result: JSONValue?
    /// Present on failure.
    public let error: WireError?

    public init(id: String?, result: JSONValue) {
        self.jsonrpc = "2.0"
        self.id = id
        self.result = result
        self.error = nil
    }

    public init(id: String?, error: WireError) {
        self.jsonrpc = "2.0"
        self.id = id
        self.result = nil
        self.error = error
    }

    /// Convenience constructor for the parse-error path (no recoverable id).
    public static func parseError(message: String = "Parse error") -> WireResponse {
        WireResponse(id: nil, error: WireError(code: WireErrorCode.parseError, message: message))
    }

    /// Convenience for invalid-request (envelope valid JSON but
    /// jsonrpc != "2.0", missing method, etc.).
    public static func invalidRequest(id: String?, message: String = "Invalid request") -> WireResponse {
        WireResponse(id: id, error: WireError(code: WireErrorCode.invalidRequest, message: message))
    }

    /// Convenience for method-not-found.
    public static func methodNotFound(id: String?, method: String) -> WireResponse {
        WireResponse(
            id: id,
            error: WireError(
                code: WireErrorCode.methodNotFound,
                message: "Method not found: \(method)"
            )
        )
    }
}

/// JSON-RPC 2.0 error object.
public struct WireError: Codable, Sendable, Equatable {
    public let code: Int
    public let message: String
    public let data: JSONValue?

    public init(code: Int, message: String, data: JSONValue? = nil) {
        self.code = code
        self.message = message
        self.data = data
    }
}

// MARK: - Framing helpers

/// Encodes a single wire frame: JSON-encode then append `\n`.
/// Throws if the encoded payload exceeds `WireMaxFrameSize`.
public func encodeWireFrame<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    var data = try encoder.encode(value)
    if data.count >= WireMaxFrameSize {
        throw WireFramingError.frameTooLarge(size: data.count, max: WireMaxFrameSize)
    }
    data.append(0x0A)  // '\n'
    return data
}

/// Errors raised by the framing layer (BEFORE message-level JSON-RPC errors).
public enum WireFramingError: Swift.Error, Sendable, Equatable {
    case frameTooLarge(size: Int, max: Int)
    case missingTerminator
    case invalidUTF8
}

/// Splits an accumulated buffer at the first `\n` and returns
/// `(frame, remainder)` where `frame` excludes the terminator. Returns
/// nil if no complete frame is available.
public func extractNextFrame(from buffer: Data) -> (frame: Data, remainder: Data)? {
    guard let newlineIdx = buffer.firstIndex(of: 0x0A) else { return nil }
    let frame = buffer[buffer.startIndex..<newlineIdx]
    let remainder = buffer[(newlineIdx + 1)..<buffer.endIndex]
    return (Data(frame), Data(remainder))
}

/// Decode an extracted frame as a WireRequest. Validates `jsonrpc == "2.0"`.
public func decodeWireRequest(_ frame: Data) throws -> WireRequest {
    let req = try JSONDecoder().decode(WireRequest.self, from: frame)
    guard req.jsonrpc == "2.0" else {
        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: [],
                debugDescription: "jsonrpc must be \"2.0\", got \(req.jsonrpc)"
            )
        )
    }
    return req
}
