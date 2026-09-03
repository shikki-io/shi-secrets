// VaultUnlock.swift — turning a master password into a session key, once.
//
// The operator's constraint, stated plainly: "I don't want to type a different
// password than mine, and I want the bot to be capable alone. If someone
// steals my mac it cannot log in."
//
// Those are compatible, but only in this shape:
//
//   * The master password is typed ONCE, at unlock. It is never stored,
//     never written to disk, never put in an env var, never logged.
//   * What survives the unlock is the 64-byte userKey — the thing that
//     actually encrypts and decrypts. The bot holds it and runs unattended
//     for as long as the session lives.
//   * The password cannot be recovered from the userKey, so a dump of the
//     broker's memory or Keychain does not yield the vault login.
//   * At rest the Keychain item is `WhenUnlockedThisDeviceOnly`: a stolen,
//     powered-off mac has no key, and the item does not travel in a backup.
//
// This is why the API key alone was never enough. `client_credentials`
// authenticates the CALL; the master password unlocks the DATA. Conflating
// the two is what produced a vault full of plaintext.

import Foundation
import Crypto

/// Everything needed to derive the vault key, as reported by the server.
public struct VaultKDFParameters: Sendable, Equatable {
    public let kdf: BitwardenCrypto.KDFType
    public let iterations: Int

    public init(kdf: BitwardenCrypto.KDFType, iterations: Int) {
        self.kdf = kdf
        self.iterations = iterations
    }

    /// Bitwarden's own default for PBKDF2 accounts since 2023. Used only when
    /// the server declines to say, which should not happen.
    public static let pbkdf2Default = VaultKDFParameters(kdf: .pbkdf2SHA256, iterations: 600_000)
}

public enum VaultUnlockError: Error, CustomStringConvertible {
    case preloginFailed(httpStatus: Int)
    case preloginMalformed
    case accountKeyMissing
    case locked

    public var description: String {
        switch self {
        case .preloginFailed(let s): return "prelogin failed (HTTP \(s))"
        case .preloginMalformed:     return "prelogin response was not the expected shape"
        case .accountKeyMissing:
            return """
                the server returned no account `Key`. Without the protected \
                symmetric key there is nothing to unwrap, and any value written \
                would have to be plaintext — which is the bug this replaces.
                """
        case .locked:
            return "vault is locked — run `shi secrets unlock` first"
        }
    }
}

/// Holds the unwrapped vault key for the life of a session.
///
/// An actor so the key cannot be read while it is being replaced, and so
/// nothing can copy it out synchronously from another thread.
public actor VaultSessionKey {
    private var keys: SymmetricKeyPair?

    public init() {}

    public func unlock(with keys: SymmetricKeyPair) { self.keys = keys }

    /// Drop the key. Called on lock, on sign-out, and on shutdown.
    public func lock() { self.keys = nil }

    public var isUnlocked: Bool { keys != nil }

    /// The key pair, or a clear error. Never returns a "default" — a caller
    /// that silently proceeded without a key is how plaintext got written.
    public func require() throws -> SymmetricKeyPair {
        guard let keys else { throw VaultUnlockError.locked }
        return keys
    }
}

public enum VaultUnlock {

    /// Ask the server for the account's KDF parameters.
    ///
    /// Unauthenticated by design — the parameters are needed BEFORE a login is
    /// possible. Modern Vaultwarden answers for unknown emails too, with
    /// plausible values, so that this endpoint cannot be used to enumerate
    /// accounts. A wrong password therefore fails at MAC verification, not here.
    public static func fetchKDFParameters(
        baseURL: URL, email: String, session: URLSession
    ) async throws -> VaultKDFParameters {
        var request = URLRequest(url: baseURL.appendingPathComponent("identity/accounts/prelogin"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(["email": email.lowercased()])

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw VaultUnlockError.preloginMalformed
        }
        guard (200...299).contains(http.statusCode) else {
            throw VaultUnlockError.preloginFailed(httpStatus: http.statusCode)
        }

        // Vaultwarden lower-cases these; upstream Bitwarden capitalises them.
        // Accept both — a case mismatch here would silently fall back to the
        // default iteration count and derive a key that never unwraps.
        struct Prelogin: Decodable {
            let kdf: Int?, kdfIterations: Int?
            let Kdf: Int?, KdfIterations: Int?
        }
        guard let p = try? JSONDecoder().decode(Prelogin.self, from: data) else {
            throw VaultUnlockError.preloginMalformed
        }
        let raw = p.kdf ?? p.Kdf ?? 0
        guard let kdf = BitwardenCrypto.KDFType(rawValue: raw) else {
            throw BitwardenCryptoError.unsupportedKDF(raw)
        }
        return VaultKDFParameters(
            kdf: kdf,
            iterations: p.kdfIterations ?? p.KdfIterations ?? 600_000
        )
    }

    /// Run the full ladder: password → masterKey → stretched → userKey → pair.
    ///
    /// `protectedKey` is the account's `Key`, as returned alongside the access
    /// token. A wrong master password surfaces here as `macMismatch`, which is
    /// the correct and only signal — the server cannot tell us.
    public static func deriveSessionKeys(
        masterPassword: String,
        email: String,
        parameters: VaultKDFParameters,
        protectedKey: String
    ) throws -> SymmetricKeyPair {
        let master = try BitwardenCrypto.masterKey(
            masterPassword: masterPassword, email: email,
            kdf: parameters.kdf, iterations: parameters.iterations
        )
        let stretched = BitwardenCrypto.stretchMasterKey(master)
        let userKey = try BitwardenCrypto.unwrapUserKey(
            protectedKey: protectedKey, stretched: stretched
        )
        return try SymmetricKeyPair(userKey: userKey)
    }
}
