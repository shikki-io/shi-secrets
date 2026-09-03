// BitwardenCrypto.swift — the client half of Vaultwarden's zero-knowledge model.
//
// The server stores ciphertext it cannot read. That property is produced
// ENTIRELY here; there is no server-side check that would notice if this file
// were wrong, or absent. It was absent.
//
// ── THE KEY LADDER ────────────────────────────────────────────────────
//
//   master password ─PBKDF2(email, N)→ masterKey (32B)
//                    ─HKDF-Expand────→ stretched enc (32B) + mac (32B)
//                                         │
//   account `Key` (an EncString) ─decrypt┘→ userKey (64B)
//                                              │
//                                    enc = userKey[0..<32]
//                                    mac = userKey[32..<64]
//                                              │
//   every cipher field ────────encrypt/decrypt┘
//
// ── WHY AN API KEY IS NOT ENOUGH ──────────────────────────────────────
//
// This is the wall the original implementation hit, and the reason it
// concluded encryption was unnecessary.
//
// The `client_credentials` grant authenticates you to the API. It does NOT
// unlock the vault: the token response carries `Key` — the user's symmetric
// key — but wrapped under the STRETCHED MASTER KEY, which is derived from the
// master password. No password, no userKey, no plaintext. That is the design
// working correctly, not an obstacle to route around.
//
// So an unattended process cannot mint the key from nothing. It needs the
// operator to unlock once; after that it holds the 64-byte userKey (see
// `VaultUnlock`) and runs on its own. The master password is never stored.
//
// ── CHOICES THAT ARE NOT NEGOTIABLE ───────────────────────────────────
//
// * Encrypt-then-MAC, over (iv ‖ ciphertext), verified BEFORE decrypting.
//   Verifying after — or not at all — turns CBC into a padding oracle.
// * Constant-time MAC comparison, via `HMAC.isValidAuthenticationCode`.
//   A `==` on Data leaks the position of the first differing byte.
// * A fresh random IV per encryption. Reusing one across two values under
//   the same key reveals whether their first 16 bytes match.
// * PBKDF2 only. Argon2id (kdf 1) is REFUSED by name rather than silently
//   mis-derived into a key that produces "cannot decrypt" with no cause.

import Foundation
import Crypto
#if canImport(CommonCrypto)
import CommonCrypto
#endif

public enum BitwardenCryptoError: Error, Equatable, CustomStringConvertible {
    case unsupportedKDF(Int)
    case pbkdf2Failed(status: Int32)
    case aesFailed(status: Int32)
    case macMismatch
    case macMissing
    case badUserKeyLength(Int)
    case plaintextIsNotUTF8

    public var description: String {
        switch self {
        case .unsupportedKDF(let k):
            return """
                vault uses KDF type \(k) (Argon2id), which this client does not \
                implement. Deriving with the wrong KDF yields a key that fails to \
                unwrap with no explanation, so we refuse instead of guessing.
                """
        case .pbkdf2Failed(let s):   return "PBKDF2 failed (CommonCrypto status \(s))"
        case .aesFailed(let s):      return "AES-CBC failed (CommonCrypto status \(s))"
        case .macMismatch:
            return """
                MAC verification failed — the ciphertext was modified, or the key \
                is wrong. Not decrypted: an unauthenticated CBC decrypt is a \
                padding oracle.
                """
        case .macMissing:            return "type-2 EncString carried no MAC"
        case .badUserKeyLength(let n): return "user key is \(n) bytes, expected 64 (32 enc ‖ 32 mac)"
        case .plaintextIsNotUTF8:    return "decrypted bytes are not valid UTF-8"
        }
    }
}

/// The two halves of a Bitwarden symmetric key. Held together so a caller can
/// never pass the enc key where the mac key belongs.
public struct SymmetricKeyPair: Sendable {
    public let encKey: SymmetricKey   // 32 bytes, AES-256
    public let macKey: SymmetricKey   // 32 bytes, HMAC-SHA256

    public init(encKey: SymmetricKey, macKey: SymmetricKey) {
        self.encKey = encKey
        self.macKey = macKey
    }

    /// Split a 64-byte user key into its enc ‖ mac halves.
    public init(userKey: Data) throws {
        guard userKey.count == 64 else {
            throw BitwardenCryptoError.badUserKeyLength(userKey.count)
        }
        self.encKey = SymmetricKey(data: userKey.prefix(32))
        self.macKey = SymmetricKey(data: userKey.suffix(32))
    }
}

public enum BitwardenCrypto {

    /// Bitwarden's KDF identifiers, as returned by `/identity/accounts/prelogin`.
    public enum KDFType: Int, Sendable {
        case pbkdf2SHA256 = 0
        case argon2id     = 1
    }

    // MARK: - Step 1: master password → master key

    /// PBKDF2-SHA256 over the master password, salted with the account email.
    ///
    /// The salt is the email lowercased and trimmed — Bitwarden's own
    /// normalisation. Get it wrong and every derived key is silently different.
    public static func masterKey(
        masterPassword: String,
        email: String,
        kdf: KDFType,
        iterations: Int
    ) throws -> SymmetricKey {
        guard kdf == .pbkdf2SHA256 else {
            throw BitwardenCryptoError.unsupportedKDF(kdf.rawValue)
        }
        let salt = Data(email.trimmingCharacters(in: .whitespacesAndNewlines)
                             .lowercased().utf8)
        let derived = try pbkdf2SHA256(
            password: masterPassword, salt: salt,
            iterations: iterations, keyLength: 32
        )
        return SymmetricKey(data: derived)
    }

    /// HKDF-Expand the 32-byte master key into the pair that unwraps `Key`.
    ///
    /// Expand ONLY — no extract step. The master key is already the PRK; adding
    /// an extract would produce a different, wrong key.
    public static func stretchMasterKey(_ masterKey: SymmetricKey) -> SymmetricKeyPair {
        SymmetricKeyPair(
            encKey: HKDF<SHA256>.expand(pseudoRandomKey: masterKey,
                                        info: Data("enc".utf8), outputByteCount: 32),
            macKey: HKDF<SHA256>.expand(pseudoRandomKey: masterKey,
                                        info: Data("mac".utf8), outputByteCount: 32)
        )
    }

    // MARK: - Step 2: unwrap the account key

    /// Decrypt the account's protected symmetric key into the raw 64-byte
    /// user key. `protectedKey` is the `Key` field of the token/profile response.
    public static func unwrapUserKey(
        protectedKey: String,
        stretched: SymmetricKeyPair
    ) throws -> Data {
        let enc = try EncString.parse(protectedKey)
        return try decryptToData(enc, using: stretched)
    }

    // MARK: - Step 3: field encryption

    /// Encrypt a UTF-8 string into a type-2 EncString.
    public static func encrypt(_ plaintext: String, using keys: SymmetricKeyPair) throws -> EncString {
        try encrypt(Data(plaintext.utf8), using: keys)
    }

    public static func encrypt(_ plaintext: Data, using keys: SymmetricKeyPair) throws -> EncString {
        // A fresh IV per call, from the CSPRNG. `SymmetricKey(size:)` is used
        // as the random source rather than `UInt8.random` — the latter goes
        // through SystemRandomNumberGenerator, which is secure on Apple
        // platforms today but is not contractually a CSPRNG.
        let iv = SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }

        let ciphertext = try aesCBC(
            operation: CCOperation(kCCEncrypt),
            data: plaintext, key: keys.encKey, iv: iv
        )
        let mac = Data(HMAC<SHA256>.authenticationCode(
            for: iv + ciphertext, using: keys.macKey
        ))
        return EncString(type: .aesCbc256_HmacSha256_B64,
                         iv: iv, ciphertext: ciphertext, mac: mac)
    }

    /// Decrypt an EncString to a UTF-8 string.
    public static func decrypt(_ enc: EncString, using keys: SymmetricKeyPair) throws -> String {
        let data = try decryptToData(enc, using: keys)
        guard let s = String(data: data, encoding: .utf8) else {
            throw BitwardenCryptoError.plaintextIsNotUTF8
        }
        return s
    }

    public static func decryptToData(_ enc: EncString, using keys: SymmetricKeyPair) throws -> Data {
        if enc.type == .aesCbc256_HmacSha256_B64 {
            guard let mac = enc.mac else { throw BitwardenCryptoError.macMissing }
            // Verify BEFORE decrypting, in constant time. Both halves matter:
            // decrypting first makes a padding oracle, and a byte-wise compare
            // makes a timing oracle.
            guard HMAC<SHA256>.isValidAuthenticationCode(
                mac, authenticating: enc.iv + enc.ciphertext, using: keys.macKey
            ) else {
                throw BitwardenCryptoError.macMismatch
            }
        }
        return try aesCBC(
            operation: CCOperation(kCCDecrypt),
            data: enc.ciphertext, key: keys.encKey, iv: enc.iv
        )
    }

    // MARK: - Primitives (CommonCrypto — macOS-only package, see Package.swift)

    static func pbkdf2SHA256(
        password: String, salt: Data, iterations: Int, keyLength: Int
    ) throws -> Data {
        var out = Data(count: keyLength)
        let pw = Array(password.utf8)
        let status: Int32 = out.withUnsafeMutableBytes { outBuf in
            salt.withUnsafeBytes { saltBuf in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pw, pw.count,
                    saltBuf.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    outBuf.bindMemory(to: UInt8.self).baseAddress, keyLength
                )
            }
        }
        guard status == kCCSuccess else {
            throw BitwardenCryptoError.pbkdf2Failed(status: status)
        }
        return out
    }

    static func aesCBC(
        operation: CCOperation, data: Data, key: SymmetricKey, iv: Data
    ) throws -> Data {
        let keyBytes = key.withUnsafeBytes { Data($0) }
        // +1 block: PKCS#7 on encrypt can grow the output by a full block.
        let capacity = data.count + kCCBlockSizeAES128
        var out = Data(count: capacity)
        var moved = 0
        let status: Int32 = out.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { dataBuf in
                iv.withUnsafeBytes { ivBuf in
                    keyBytes.withUnsafeBytes { keyBuf in
                        CCCrypt(
                            operation, CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBuf.baseAddress, keyBytes.count,
                            ivBuf.baseAddress,
                            dataBuf.baseAddress, data.count,
                            outBuf.baseAddress, capacity,
                            &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw BitwardenCryptoError.aesFailed(status: status)
        }
        return out.prefix(moved)
    }
}
