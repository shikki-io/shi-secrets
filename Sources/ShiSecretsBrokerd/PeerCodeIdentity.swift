// PeerCodeIdentity — who the caller IS, not just which uid it runs as.
//
// W3 of spec c4e9a1f7 (enterprise safety hardening), BR-H-04:
// "secrets-brokerd ... with its peer check bound to the caller's team id".
//
// WHY THE EXISTING CHECK IS NOT ENOUGH. `PeerCred.peerCredentials(fd:)`
// answers "which uid opened this socket", and the socket is mode 0600 owned
// by that uid, so a *different user* already cannot reach the broker. What it
// cannot answer is "is the thing on the other end OUR binary". The red-team
// audit (~/.shikki/reports/redteam-binary-audit-2026-11-07.md, decision
// d3c44a4f) names that as the top-impact gap: the brokerd ran as a DEBUG
// build with no hardened runtime, so "any same-user process (or attacker with
// local code exec) can task_for_pid/attach a debugger, inject via
// DYLD_INSERT_LIBRARIES, and read broker memory". Hardening the daemon stops
// the attach; this file stops the *socket* being a same-user API for any
// process that happens to know the path.
//
// WHY THE AUDIT TOKEN AND NOT THE PID. `LOCAL_PEERPID` is available and
// simpler, and it is the wrong primitive: between reading the pid and
// evaluating its code signature the process can exit and the pid be reused,
// so the signature checked belongs to a different program than the one on the
// socket (the classic code-signing TOCTOU). The audit token identifies the
// peer process *instance*, and Security's `kSecGuestAttributeAudit` consumes
// it directly — which is why Apple documents the audit token as the input for
// exactly this check. Both `LOCAL_PEERTOKEN` (sys/un.h) and
// `kSecGuestAttributeAudit` (Security/SecCode.h) are public SDK, verified
// against MacOSX.sdk before this file was written.
//
// WHY `anchor apple generic and certificate leaf[subject.OU]`. That is the
// documented form of "signed by my team, by a certificate Apple issued".
// Pinning the cdhash instead would bind to ONE build of the client and break
// on every release; naming only the signing identifier would accept anybody
// who copies the identifier string. Team OU is the identity the operator
// actually controls (SH7MZH647S), and the same one the daemon itself signs
// with.
//
// FAIL-CLOSED, BUT NOT SILENTLY ARMED. The default is `.off`: an operator's
// locally built `shi` is ad-hoc signed and would be refused, so a check armed
// by default would brick every dev worktree's `shi secret get` on upgrade —
// a gate that gets reverted protects nothing. `[peer] require_team_id` in
// secrets-brokerd.toml arms it, and once armed a caller that fails is
// REFUSED. `SHI_SECRETS_PEER_CHECK=observe` downgrades an armed check to
// logging for one launch, which is a launch particular, not a setting.

import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Security's guest API (`SecCodeCopyGuestWithAttributes`,
// `kSecGuestAttributeAudit`) is declared under `#if TARGET_OS_OSX` in
// SecCode.h — it does not exist on iOS even though Darwin does. So the
// platform gate below is `os(macOS)`, not `canImport(Darwin)`: the broker
// daemon is a macOS launchd service, and a half-available check compiled on
// a platform that cannot answer is how an absent capability starts reading
// as a passing one.
#if os(macOS)
import Security
#endif

// MARK: - Policy

/// What the broker does with a caller's code identity.
public enum PeerCodePolicy: Sendable, Equatable {
    /// No identity work at all. The uid check still applies.
    case off
    /// Evaluate the requirement and LOG the verdict; admit the caller either
    /// way. The escape hatch for a release that refuses a caller it should
    /// not — the operator can see the verdict before it is enforced.
    case observe(teamID: String)
    /// Evaluate the requirement and REFUSE a caller that fails it.
    case enforce(teamID: String)

    /// The team id this policy is bound to, or nil when off.
    public var teamID: String? {
        switch self {
        case .off: return nil
        case .observe(let t), .enforce(let t): return t
        }
    }

    /// True when a failing caller is refused rather than merely logged.
    public var refusesOnFailure: Bool {
        switch self {
        case .enforce: return true
        case .off, .observe: return false
        }
    }

    /// Resolve the effective policy from the configured team id and the
    /// one-launch env downgrade.
    ///
    /// `requireTeamID == nil` is `.off` whatever the env says: an env var
    /// cannot arm a check the settings did not ask for, because then a
    /// launch environment would decide a security posture the operator never
    /// wrote down.
    public static func resolve(
        requireTeamID: String?,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> PeerCodePolicy {
        guard let teamID = requireTeamID, !teamID.isEmpty else { return .off }
        if environment["SHI_SECRETS_PEER_CHECK"]?.lowercased() == "observe" {
            return .observe(teamID: teamID)
        }
        return .enforce(teamID: teamID)
    }
}

// MARK: - Errors

public enum PeerCodeIdentityError: Swift.Error, Sendable, Equatable, CustomStringConvertible {
    /// The platform has no code-signing identity to read (Linux).
    case unsupportedPlatform
    /// `getsockopt(LOCAL_PEERTOKEN)` failed — not a unix socket, or the peer
    /// is already gone.
    case auditTokenUnavailable(errno: Int32)
    /// Security could not resolve the audit token to a running program.
    case guestNotFound(status: Int32)
    /// The requirement text did not compile. A bug in the requirement, never
    /// the caller's fault — and it must not read as "caller refused".
    case requirementInvalid(status: Int32, requirement: String)
    /// The caller is signed, and not by us.
    case requirementNotMet(status: Int32, teamID: String)

    public var description: String {
        switch self {
        case .unsupportedPlatform:
            return "peer code identity: unsupported platform (no code signing)"
        case .auditTokenUnavailable(let e):
            return "peer code identity: LOCAL_PEERTOKEN failed (errno=\(e))"
        case .guestNotFound(let s):
            return "peer code identity: audit token resolved to no running program (OSStatus=\(s))"
        case .requirementInvalid(let s, let r):
            return "peer code identity: requirement did not compile (OSStatus=\(s)): \(r)"
        case .requirementNotMet(let s, let t):
            return "peer code identity: caller is not signed by team \(t) (OSStatus=\(s))"
        }
    }
}

// MARK: - The requirement

/// The code requirement a caller must satisfy, as text.
///
/// Exposed as a type rather than built inline at the call site so the exact
/// string is greppable, testable without a socket, and written in exactly one
/// place. A requirement assembled by string interpolation at three call sites
/// is three requirements.
public struct PeerCodeRequirement: Sendable, Equatable {
    public let teamID: String

    public init(teamID: String) {
        self.teamID = teamID
    }

    /// `anchor apple generic and certificate leaf[subject.OU] = "<team>"`
    public var text: String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
    }
}

// MARK: - The audit token

/// The peer's audit token, read from a connected unix-domain socket.
///
/// Darwin only: `LOCAL_PEERTOKEN` has no Linux equivalent, and Linux has no
/// code signatures to check, so the whole plane is `.unsupportedPlatform`
/// there rather than a half-answer.
public func peerAuditToken(fd: Int32) throws -> [UInt32] {
    #if os(macOS)
    // audit_token_t is 8 x unsigned int (mach/message.h). Read it as a
    // UInt32 buffer so no Mach type crosses this boundary.
    let count = 8
    var token = [UInt32](repeating: 0, count: count)
    var len = socklen_t(MemoryLayout<UInt32>.size * count)
    let result = token.withUnsafeMutableBytes { raw -> Int32 in
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, raw.baseAddress, &len)
    }
    guard result == 0 else {
        throw PeerCodeIdentityError.auditTokenUnavailable(errno: errno)
    }
    guard len == socklen_t(MemoryLayout<UInt32>.size * count) else {
        // A short read is not a token. Refusing is the only honest answer:
        // a truncated token passed to Security would identify some other
        // process, or none.
        throw PeerCodeIdentityError.auditTokenUnavailable(errno: EINVAL)
    }
    return token
    #else
    throw PeerCodeIdentityError.unsupportedPlatform
    #endif
}

// MARK: - The check

/// Evaluates a connected peer against a code requirement.
public struct PeerCodeAuthorizer: Sendable {

    public let policy: PeerCodePolicy

    public init(policy: PeerCodePolicy) {
        self.policy = policy
    }

    /// Check the peer on `fd` against the policy.
    ///
    /// - Returns: `true` when the connection may proceed.
    /// - Note: never throws. A refusal is a `false` plus a logged reason,
    ///   because the accept loop's only correct response to any failure is
    ///   the same one (close the fd), and an `Error` that every caller
    ///   converts to a bool is a type pretending to offer a choice.
    public func admits(fd: Int32, log: (String) -> Void = PeerCodeAuthorizer.logToStderr) -> Bool {
        guard let teamID = policy.teamID else { return true }
        let requirement = PeerCodeRequirement(teamID: teamID)
        do {
            try Self.verify(fd: fd, requirement: requirement)
            return true
        } catch {
            let reason = (error as? PeerCodeIdentityError)?.description
                ?? "peer code identity: \(error)"
            if policy.refusesOnFailure {
                log("shikki-brokerd: REFUSED connection — \(reason) requirement=\(requirement.text)")
                return false
            }
            log("shikki-brokerd: WARN observe-only, connection ADMITTED — \(reason) requirement=\(requirement.text)")
            return true
        }
    }

    /// The whole check, separated from the policy so a test can assert the
    /// verdict for a known-good peer (this process, signed or not) without
    /// going through an accept loop.
    public static func verify(fd: Int32, requirement: PeerCodeRequirement) throws {
        #if os(macOS)
        let token = try peerAuditToken(fd: fd)
        let tokenData = token.withUnsafeBytes { Data($0) }

        var code: SecCode?
        let attributes: [CFString: Any] = [kSecGuestAttributeAudit: tokenData]
        let copyStatus = SecCodeCopyGuestWithAttributes(
            nil, attributes as CFDictionary, SecCSFlags(rawValue: 0), &code)
        guard copyStatus == errSecSuccess, let peerCode = code else {
            throw PeerCodeIdentityError.guestNotFound(status: Int32(copyStatus))
        }

        var secRequirement: SecRequirement?
        let compileStatus = SecRequirementCreateWithString(
            requirement.text as CFString, SecCSFlags(rawValue: 0), &secRequirement)
        guard compileStatus == errSecSuccess, let req = secRequirement else {
            throw PeerCodeIdentityError.requirementInvalid(
                status: Int32(compileStatus), requirement: requirement.text)
        }

        let checkStatus = SecCodeCheckValidity(peerCode, SecCSFlags(rawValue: 0), req)
        guard checkStatus == errSecSuccess else {
            throw PeerCodeIdentityError.requirementNotMet(
                status: Int32(checkStatus), teamID: requirement.teamID)
        }
        #else
        throw PeerCodeIdentityError.unsupportedPlatform
        #endif
    }

    /// Default sink. Separate so tests capture the line instead of the
    /// terminal, and so every refusal is one grep away in launchd's log.
    public static func logToStderr(_ line: String) {
        FileHandle.standardError.write(Data((line + "\n").utf8))
    }
}
