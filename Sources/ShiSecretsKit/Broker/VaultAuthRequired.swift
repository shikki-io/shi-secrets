import Foundation

// VaultAuthRequired - the vault needs the operator to act before a request
// can be served. This is an EXPECTED state, not a server fault, so it travels
// on its own wire codes (never -32603) and always names the command to run.
//
// Two states, because the vault has two gates:
//   notLoggedIn  no valid session with the vault server (never signed in,
//                session expired, credentials missing, broker has no session)
//   vaultLocked  signed in, but the vault key is not derived in memory
//
// The master password, session key and any secret value never appear in a
// message, a log line or the wire `data` - only a reason and a command.

public struct VaultAuthRequired: Swift.Error, Sendable, Equatable, CustomStringConvertible {

    public enum Kind: String, Sendable, Equatable {
        case notLoggedIn = "not_logged_in"
        case vaultLocked = "vault_locked"
    }

    public let kind: Kind
    /// The exact command the operator runs to leave this state.
    public let remedy: String

    public init(kind: Kind, remedy: String) {
        self.kind = kind
        self.remedy = remedy
    }

    // MARK: Remedies (single owner of the command strings)

    public static let unlockCommand = "shi secrets unlock"
    public static let credentialsCommand = "shi secrets setup vault-credentials"
    public static let brokerStartCommand = "shi secrets brokerd start"

    public static let locked = VaultAuthRequired(kind: .vaultLocked, remedy: unlockCommand)
    /// Session missing or expired: unlock re-authenticates, then derives the key.
    public static let sessionExpired = VaultAuthRequired(kind: .notLoggedIn, remedy: unlockCommand)
    public static let credentialsMissing = VaultAuthRequired(kind: .notLoggedIn, remedy: credentialsCommand)
    public static let brokerHasNoSession = VaultAuthRequired(kind: .notLoggedIn, remedy: brokerStartCommand)

    // MARK: Presentation

    /// Human sentence naming the state and the command.
    public var message: String {
        switch (kind, remedy) {
        case (.vaultLocked, _):
            return "Vault is locked. Run: \(remedy)"
        case (.notLoggedIn, Self.credentialsCommand):
            return "Not logged in to the vault: no credentials are stored. Run: \(remedy)"
        case (.notLoggedIn, Self.brokerStartCommand):
            return "Not logged in to the vault: the broker has no session. Run: \(remedy)"
        case (.notLoggedIn, _):
            return "Not logged in to the vault (session missing or expired). Run: \(remedy)"
        }
    }

    public var description: String { message }

    /// Process exit code, distinct from the generic failure code 1.
    public var exitCode: Int32 {
        switch kind {
        case .vaultLocked: return 3
        case .notLoggedIn: return 4
        }
    }

    /// `--json` body: same reason and remedy as the wire `data`.
    public var jsonString: String {
        let obj: [String: String] = [
            "error": kind.rawValue, "reason": kind.rawValue,
            "remedy": remedy, "message": message,
        ]
        let data = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: Wire

    public var wireCode: Int {
        switch kind {
        case .vaultLocked: return WireErrorCode.vaultLocked
        case .notLoggedIn: return WireErrorCode.notLoggedIn
        }
    }

    public func wireError() -> WireError {
        WireError(
            code: wireCode,
            message: message,
            data: .object(["reason": .string(kind.rawValue), "remedy": .string(remedy)])
        )
    }

    /// Rebuilds the state from a wire error; nil for any other error.
    public init?(wireError: WireError) {
        let kind: Kind
        switch wireError.code {
        case WireErrorCode.vaultLocked: kind = .vaultLocked
        case WireErrorCode.notLoggedIn: kind = .notLoggedIn
        default: return nil
        }
        var remedy = Self.unlockCommand
        if case let .object(obj)? = wireError.data, case let .string(r)? = obj["remedy"], !r.isEmpty {
            remedy = r
        }
        self.init(kind: kind, remedy: remedy)
    }

    // MARK: Audit deny reasons

    public init?(denyReason: AuditRow.DenyReason) {
        switch denyReason {
        case .vaultNotLoggedIn: self = .sessionExpired
        case .vaultLocked: self = .locked
        default: return nil
        }
    }

    public var denyReason: AuditRow.DenyReason {
        kind == .vaultLocked ? .vaultLocked : .vaultNotLoggedIn
    }

    // MARK: Classification

    /// Maps a vault-layer error to the expected state it represents, or nil
    /// when it is a genuine failure that must stay an internal error.
    public static func classify(_ error: Swift.Error) -> VaultAuthRequired? {
        if let e = error as? VaultAuthRequired { return e }
        if let e = error as? VaultUnlockError, case .locked = e { return .locked }
        if let e = error as? VaultwardenClientError {
            switch e {
            case .notAuthenticated: return .sessionExpired
            case .credentialsNotLoaded: return .credentialsMissing
            default: return nil
            }
        }
        return nil
    }
}
