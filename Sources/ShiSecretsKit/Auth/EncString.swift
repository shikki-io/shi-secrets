// EncString.swift — the Bitwarden/Vaultwarden wire type for an encrypted field.
//
// WHY THIS FILE EXISTS
//
// Every string in a Bitwarden vault — the item name, the notes, each custom
// field — travels as an EncString. The server NEVER inspects it, never
// validates it, and never decrypts it. That is the entire product: the host
// stores bytes it cannot read.
//
// The consequence, which is what bit us: POST a plaintext string where an
// EncString belongs and the server answers 200 OK. It stored your plaintext
// exactly as asked. Nothing anywhere reports an error — until a real client
// fetches the item, tries to parse `name`, fails, and renders
// `[error: cannot decrypt]`. The desktop app is stricter and drops the item,
// which is why the vault looked EMPTY there and merely broken on the web.
//
// shi-secrets wrote plaintext and read plaintext, so it was self-consistent
// and appeared to work end-to-end. Read and write were wrong in the same
// direction. See `docs/vault-encryption.md`.
//
// FORMAT
//
//     <type>.<base64 iv>|<base64 ciphertext>|<base64 mac>
//
// type 2 — AesCbc256_HmacSha256_B64. The only type we WRITE.
// type 0 — AesCbc256_B64, no MAC. Legacy; we can read it, we never emit it,
//          because unauthenticated CBC is malleable — an attacker with write
//          access to the server can flip plaintext bits without the key.
//
// Types 1, 3, 4, 5, 6 are RSA/other schemes used for org and share keys. We
// do not handle them; `parse` rejects them by name rather than guessing.

import Foundation

/// A parsed Bitwarden EncString.
public struct EncString: Equatable, Sendable {

    /// The encryption scheme byte that prefixes the string.
    public enum EncType: Int, Sendable {
        /// AES-256-CBC, no authentication. Readable for compatibility, never written.
        case aesCbc256_B64 = 0
        /// AES-256-CBC + HMAC-SHA256 over (iv ‖ ciphertext). The one we write.
        case aesCbc256_HmacSha256_B64 = 2
    }

    public let type: EncType
    public let iv: Data
    public let ciphertext: Data
    /// Present iff `type == .aesCbc256_HmacSha256_B64`.
    public let mac: Data?

    public init(type: EncType, iv: Data, ciphertext: Data, mac: Data?) {
        self.type = type
        self.iv = iv
        self.ciphertext = ciphertext
        self.mac = mac
    }

    // MARK: - Serialisation

    /// The wire form: `2.<iv>|<ct>|<mac>`.
    public var serialized: String {
        var parts = [iv.base64EncodedString(), ciphertext.base64EncodedString()]
        if let mac { parts.append(mac.base64EncodedString()) }
        return "\(type.rawValue).\(parts.joined(separator: "|"))"
    }

    // MARK: - Parsing

    public enum ParseError: Error, Equatable, CustomStringConvertible {
        /// No `<digits>.` prefix at all — almost certainly a plaintext string
        /// written by a client that did not encrypt. This is the error that
        /// would have caught our own bug on the first read-back.
        case notAnEncString(prefix: String)
        case unsupportedType(Int)
        case wrongPartCount(expected: Int, got: Int)
        case invalidBase64(part: String)
        /// AES-CBC has a 16-byte block; anything else is not our ciphertext.
        case badIVLength(Int)

        public var description: String {
            switch self {
            case .notAnEncString(let prefix):
                return """
                    not an EncString (starts with \"\(prefix)\") — this field holds \
                    PLAINTEXT, which means it was written by a client that did not \
                    encrypt it. The value is readable by anyone with database access.
                    """
            case .unsupportedType(let t):
                return "unsupported EncString type \(t) (we handle 0 and 2)"
            case .wrongPartCount(let expected, let got):
                return "EncString has \(got) `|`-separated parts, expected \(expected)"
            case .invalidBase64(let part):
                return "EncString part is not valid base64: \(part)"
            case .badIVLength(let n):
                return "EncString IV is \(n) bytes, expected 16 (AES block size)"
            }
        }
    }

    /// Parse a wire string. Throws rather than returning nil so the REASON
    /// survives to the caller — "cannot decrypt" with no cause is exactly the
    /// message that left this bug undiagnosed for weeks.
    public static func parse(_ raw: String) throws -> EncString {
        guard let dot = raw.firstIndex(of: "."),
              let typeValue = Int(raw[raw.startIndex..<dot]),
              dot != raw.startIndex else {
            throw ParseError.notAnEncString(prefix: String(raw.prefix(12)))
        }
        guard let type = EncType(rawValue: typeValue) else {
            throw ParseError.unsupportedType(typeValue)
        }

        let body = String(raw[raw.index(after: dot)...])
        let parts = body.components(separatedBy: "|")
        let expected = (type == .aesCbc256_HmacSha256_B64) ? 3 : 2
        guard parts.count == expected else {
            throw ParseError.wrongPartCount(expected: expected, got: parts.count)
        }

        func decode(_ s: String) throws -> Data {
            guard let d = Data(base64Encoded: s) else {
                throw ParseError.invalidBase64(part: String(s.prefix(16)))
            }
            return d
        }

        let iv = try decode(parts[0])
        guard iv.count == 16 else { throw ParseError.badIVLength(iv.count) }

        return EncString(
            type: type,
            iv: iv,
            ciphertext: try decode(parts[1]),
            mac: expected == 3 ? try decode(parts[2]) : nil
        )
    }

    /// True when the string is *shaped* like an EncString. Cheap check used by
    /// the audit path to tell a plaintext row from an encrypted one without
    /// needing a key.
    public static func looksEncrypted(_ raw: String) -> Bool {
        (try? parse(raw)) != nil
    }
}
