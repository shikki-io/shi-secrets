import Testing
@testable import ShiSecretsKit
import Foundation
import Crypto

// Tests for the client-side encryption that shi-secrets shipped WITHOUT.
//
// The bug these exist to prevent: `createCipher` assigned the plaintext name
// and value straight into the request body, Vaultwarden answered 200, and
// nothing anywhere disagreed — because a zero-knowledge server never inspects
// what it stores. The system was self-consistent (it read back the plaintext
// it wrote), so an end-to-end test of shi-secrets ALONE would still pass.
//
// That is the shape of the trap, so the suite is built around it:
//   * a vector computed outside Swift, so the ladder cannot be self-confirming
//   * an assertion that ciphertext does NOT contain the plaintext
//   * a structural check that the request type cannot carry plaintext at all

@Suite("Bitwarden EncString + key ladder")
struct BitwardenCryptoTests {

    // MARK: - The key ladder, against an independently computed vector

    // Computed with Python's hashlib/hmac, not with this code:
    //
    //   pw    = "correct horse battery staple"
    //   email = "Test@Example.COM "        ← deliberately messy
    //   salt  = email.strip().lower()      → "test@example.com"
    //   mk    = pbkdf2_hmac('sha256', pw, salt, 600_000, 32)
    //
    // A self-generated expectation would pass even if the derivation were
    // wrong, which is precisely how the original defect survived.

    @Test("PBKDF2 master key matches an independently computed vector")
    func masterKeyMatchesExternalVector() throws {
        let key = try BitwardenCrypto.masterKey(
            masterPassword: "correct horse battery staple",
            email: "Test@Example.COM ",
            kdf: .pbkdf2SHA256, iterations: 600_000
        )
        let b64 = key.withUnsafeBytes { Data($0) }.base64EncodedString()
        #expect(b64 == "vDKY7nW/Ay6C6JtXqe0QC9cBRmBfrTgqxOmnxr72Kqw=")
    }

    @Test("HKDF stretch matches an independently computed vector")
    func stretchMatchesExternalVector() throws {
        let master = try BitwardenCrypto.masterKey(
            masterPassword: "correct horse battery staple",
            email: "Test@Example.COM ",
            kdf: .pbkdf2SHA256, iterations: 600_000
        )
        let pair = BitwardenCrypto.stretchMasterKey(master)
        let enc = pair.encKey.withUnsafeBytes { Data($0) }.base64EncodedString()
        let mac = pair.macKey.withUnsafeBytes { Data($0) }.base64EncodedString()
        #expect(enc == "K43QKeQSF403TeYbjuA+cutDLAU7e+1u4R036dtASZo=")
        #expect(mac == "lss8Sbx9MFISnOkZFeu8pdI42jSKNm9Buc661Mb5byU=")
    }

    @Test("email salt is normalised — case and whitespace must not change the key")
    func emailSaltIsNormalised() throws {
        let a = try BitwardenCrypto.masterKey(masterPassword: "pw", email: "  Ops@Obyw.One ",
                                              kdf: .pbkdf2SHA256, iterations: 5_000)
        let b = try BitwardenCrypto.masterKey(masterPassword: "pw", email: "ops@obyw.one",
                                              kdf: .pbkdf2SHA256, iterations: 5_000)
        #expect(a.withUnsafeBytes { Data($0) } == b.withUnsafeBytes { Data($0) })
    }

    @Test("Argon2id is refused by name, not silently mis-derived")
    func argon2IsRefused() {
        #expect(throws: BitwardenCryptoError.unsupportedKDF(1)) {
            try BitwardenCrypto.masterKey(masterPassword: "pw", email: "a@b.c",
                                          kdf: .argon2id, iterations: 3)
        }
    }

    // MARK: - EncString round trip

    private func keys() -> SymmetricKeyPair {
        SymmetricKeyPair(encKey: SymmetricKey(size: .bits256),
                         macKey: SymmetricKey(size: .bits256))
    }

    @Test("encrypt → serialize → parse → decrypt returns the original")
    func roundTrip() throws {
        let k = keys()
        let secret = "hunter2 — with a unicode dash and a ' quote"
        let wire = try BitwardenCrypto.encrypt(secret, using: k).serialized
        let back = try BitwardenCrypto.decrypt(try EncString.parse(wire), using: k)
        #expect(back == secret)
    }

    @Test("the wire form is a type-2 EncString")
    func wireFormIsType2() throws {
        let wire = try BitwardenCrypto.encrypt("x", using: keys()).serialized
        #expect(wire.hasPrefix("2."))
        #expect(wire.components(separatedBy: "|").count == 3)
    }

    // THE test. If this ever fails, the vault is being written in the clear.
    @Test("ciphertext does not contain the plaintext")
    func ciphertextDoesNotLeakPlaintext() throws {
        let secret = "SUPERSECRETTOKEN"
        let wire = try BitwardenCrypto.encrypt(secret, using: keys()).serialized
        #expect(!wire.contains(secret))
        #expect(!Data(base64Encoded: wire.components(separatedBy: "|")[1])
                    .map { String(decoding: $0, as: UTF8.self) }!
                    .contains(secret))
    }

    @Test("a fresh IV per call — the same plaintext twice gives two ciphertexts")
    func ivIsNotReused() throws {
        let k = keys()
        let a = try BitwardenCrypto.encrypt("same", using: k)
        let b = try BitwardenCrypto.encrypt("same", using: k)
        #expect(a.iv != b.iv)
        #expect(a.ciphertext != b.ciphertext)
    }

    @Test("empty string survives the round trip")
    func emptyStringRoundTrips() throws {
        let k = keys()
        let wire = try BitwardenCrypto.encrypt("", using: k).serialized
        #expect(try BitwardenCrypto.decrypt(try EncString.parse(wire), using: k) == "")
    }

    @Test("a value larger than one AES block survives")
    func longValueRoundTrips() throws {
        let k = keys()
        let secret = String(repeating: "abcdefgh", count: 512)   // 4 KiB
        let wire = try BitwardenCrypto.encrypt(secret, using: k).serialized
        #expect(try BitwardenCrypto.decrypt(try EncString.parse(wire), using: k) == secret)
    }

    // MARK: - Tamper + wrong key

    @Test("a flipped ciphertext bit is rejected by the MAC, not decrypted")
    func tamperedCiphertextIsRejected() throws {
        let k = keys()
        let enc = try BitwardenCrypto.encrypt("transfer 10 EUR", using: k)
        var ct = enc.ciphertext
        ct[0] ^= 0x01
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64,
                                 iv: enc.iv, ciphertext: ct, mac: enc.mac)
        #expect(throws: BitwardenCryptoError.macMismatch) {
            try BitwardenCrypto.decrypt(tampered, using: k)
        }
    }

    @Test("a flipped IV bit is rejected — the MAC covers the IV too")
    func tamperedIVIsRejected() throws {
        let k = keys()
        let enc = try BitwardenCrypto.encrypt("transfer 10 EUR", using: k)
        var iv = enc.iv
        iv[0] ^= 0x01
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64,
                                 iv: iv, ciphertext: enc.ciphertext, mac: enc.mac)
        #expect(throws: BitwardenCryptoError.macMismatch) {
            try BitwardenCrypto.decrypt(tampered, using: k)
        }
    }

    @Test("the wrong key fails at the MAC, before any decryption happens")
    func wrongKeyFailsAtTheMAC() throws {
        let enc = try BitwardenCrypto.encrypt("secret", using: keys())
        #expect(throws: BitwardenCryptoError.macMismatch) {
            try BitwardenCrypto.decrypt(enc, using: keys())
        }
    }

    // MARK: - Parsing, including the plaintext case that started all this

    @Test("a plaintext field is reported as plaintext, not as 'cannot decrypt'")
    func plaintextIsNamedAsSuch() {
        // Exactly what shi-secrets used to write.
        #expect(throws: EncString.ParseError.notAnEncString(prefix: "GH_TOKEN")) {
            try EncString.parse("GH_TOKEN")
        }
        #expect(EncString.looksEncrypted("ghp_AAAAAAAAAAAAAAAAAAAA") == false)
    }

    @Test("looksEncrypted accepts what we emit")
    func looksEncryptedAcceptsOurOutput() throws {
        let wire = try BitwardenCrypto.encrypt("v", using: keys()).serialized
        #expect(EncString.looksEncrypted(wire))
    }

    @Test("a type-2 EncString missing its MAC is rejected, not decrypted anyway")
    func missingMacIsRejected() throws {
        let enc = try BitwardenCrypto.encrypt("v", using: keys())
        let noMac = "2.\(enc.iv.base64EncodedString())|\(enc.ciphertext.base64EncodedString())"
        #expect(throws: EncString.ParseError.wrongPartCount(expected: 3, got: 2)) {
            try EncString.parse(noMac)
        }
    }

    @Test("an RSA EncString type is refused rather than misread as AES")
    func unsupportedTypeIsRefused() {
        #expect(throws: EncString.ParseError.unsupportedType(4)) {
            try EncString.parse("4.\(Data(repeating: 0, count: 16).base64EncodedString())|AA==")
        }
    }

    @Test("a 12-byte IV is refused — that is GCM's size, not CBC's")
    func badIVLengthIsRefused() {
        let shortIV = Data(repeating: 0, count: 12).base64EncodedString()
        #expect(throws: EncString.ParseError.badIVLength(12)) {
            try EncString.parse("2.\(shortIV)|AA==|AA==")
        }
    }

    // MARK: - The account-key unwrap, end to end

    @Test("unwrapUserKey recovers a 64-byte key wrapped under the stretched key")
    func unwrapUserKeyRoundTrip() throws {
        let master = try BitwardenCrypto.masterKey(
            masterPassword: "pw", email: "ops@obyw.one",
            kdf: .pbkdf2SHA256, iterations: 5_000
        )
        let stretched = BitwardenCrypto.stretchMasterKey(master)

        // Stand in for the server's `Key`: a random 64-byte user key, wrapped.
        let userKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
                    + SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let wrapped = try BitwardenCrypto.encrypt(userKey, using: stretched).serialized

        let recovered = try BitwardenCrypto.unwrapUserKey(protectedKey: wrapped, stretched: stretched)
        #expect(recovered == userKey)

        let pair = try SymmetricKeyPair(userKey: recovered)
        let wire = try BitwardenCrypto.encrypt("field", using: pair).serialized
        #expect(try BitwardenCrypto.decrypt(try EncString.parse(wire), using: pair) == "field")
    }

    @Test("a wrong master password fails at unwrap — the server cannot tell us")
    func wrongMasterPasswordFailsAtUnwrap() throws {
        let right = BitwardenCrypto.stretchMasterKey(
            try BitwardenCrypto.masterKey(masterPassword: "right", email: "a@b.c",
                                          kdf: .pbkdf2SHA256, iterations: 5_000))
        let wrong = BitwardenCrypto.stretchMasterKey(
            try BitwardenCrypto.masterKey(masterPassword: "wrong", email: "a@b.c",
                                          kdf: .pbkdf2SHA256, iterations: 5_000))
        let userKey = Data(repeating: 7, count: 64)
        let wrapped = try BitwardenCrypto.encrypt(userKey, using: right).serialized

        #expect(throws: BitwardenCryptoError.macMismatch) {
            try BitwardenCrypto.unwrapUserKey(protectedKey: wrapped, stretched: wrong)
        }
    }

    @Test("a user key of the wrong length is refused, not silently truncated")
    func shortUserKeyIsRefused() {
        #expect(throws: BitwardenCryptoError.badUserKeyLength(32)) {
            try SymmetricKeyPair(userKey: Data(repeating: 0, count: 32))
        }
    }

    // MARK: - The vault key is a separate thing from the access token

    @Test("a fresh session is LOCKED — no key means no write, not a plaintext write")
    func freshSessionIsLocked() async throws {
        let session = VaultSessionKey()
        #expect(await session.isUnlocked == false)
        await #expect(throws: VaultUnlockError.self) { try await session.require() }
    }

    @Test("lock() drops the key")
    func lockDropsTheKey() async throws {
        let session = VaultSessionKey()
        await session.unlock(with: keys())
        #expect(await session.isUnlocked)
        await session.lock()
        #expect(await session.isUnlocked == false)
    }
}
