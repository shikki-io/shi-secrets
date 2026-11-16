import Foundation
@testable import ShiSecretsBrokerd
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// PeerCodeIdentityTests — W3 of spec c4e9a1f7 (BR-H-04), test T-07.
//
// WHAT CAN AND CANNOT BE ASSERTED HERE, STATED UP FRONT.
// T-07 reads "a peer whose team id mismatches is refused". The peer in a
// unit test is the TEST RUNNER ITSELF (`socketpair(2)` connects this process
// to this process), and a `swift test` binary is ad-hoc signed — it has no
// team id at all. So:
//
//   · "a mismatching team is refused"  → assertable, and asserted below with
//     a team id that cannot match anything (`ZZZZZZZZZZ`). The runner fails
//     the requirement, and `.enforce` returns false.
//   · "OUR team is admitted"           → NOT assertable in a unit test. It
//     needs a peer signed by SH7MZH647S, which only exists after the release
//     pipeline signs one. Asserting it against an ad-hoc runner would mean
//     weakening the check until the test passes — pinning the defect. It is
//     the release gate's job, and scripts/release-brokerd.sh verifies it on
//     the real artifact.
//
// Everything that does NOT need a signed peer is covered exhaustively:
// policy resolution, the requirement text, the audit-token read, the
// observe/enforce split, and the settings parse.

/// The socket-level tests need `LOCAL_PEERTOKEN` and Security's guest API,
/// both macOS-only. They are marked `.enabled(if:)` rather than `#if`-ed out
/// so a Linux run reports them as SKIPPED — a test that silently returns on
/// the wrong platform is counted as passing, which is the `0|0|0|0` shape.
private let hasCodeSigning: Bool = {
    #if os(macOS)
    return true
    #else
    return false
    #endif
}()

@Suite("PeerCodePolicy — resolution")
struct PeerCodePolicyResolutionTests {

    @Test("T-07.1: no configured team id → off, and no env can arm it")
    func test_absentTeamID_isOff_andEnvCannotArmIt() {
        #expect(PeerCodePolicy.resolve(requireTeamID: nil, environment: [:]) == .off)
        #expect(PeerCodePolicy.resolve(requireTeamID: "", environment: [:]) == .off)
        // The whole point: a launch environment must not be able to turn on a
        // security check the operator never wrote down, because then the
        // posture lives in whoever wrote the launchd plist.
        #expect(PeerCodePolicy.resolve(
            requireTeamID: nil,
            environment: ["SHI_SECRETS_PEER_CHECK": "enforce"]) == .off)
    }

    @Test("T-07.2: a configured team id enforces by default — fail closed")
    func test_configuredTeamID_enforcesByDefault() {
        let policy = PeerCodePolicy.resolve(requireTeamID: "SH7MZH647S", environment: [:])
        #expect(policy == .enforce(teamID: "SH7MZH647S"))
        #expect(policy.refusesOnFailure)
        #expect(policy.teamID == "SH7MZH647S")
    }

    @Test("T-07.3: SHI_SECRETS_PEER_CHECK=observe downgrades an armed check, and only that value")
    func test_observeEnv_downgradesArmedCheck() {
        #expect(PeerCodePolicy.resolve(
            requireTeamID: "SH7MZH647S",
            environment: ["SHI_SECRETS_PEER_CHECK": "observe"]) == .observe(teamID: "SH7MZH647S"))
        // Case-insensitive, because an operator typing OBSERVE means observe.
        #expect(PeerCodePolicy.resolve(
            requireTeamID: "SH7MZH647S",
            environment: ["SHI_SECRETS_PEER_CHECK": "OBSERVE"]) == .observe(teamID: "SH7MZH647S"))
        // Anything else is NOT a downgrade. A typo must not silently disarm.
        for value in ["off", "0", "disabled", "yes", "observ", ""] {
            #expect(PeerCodePolicy.resolve(
                requireTeamID: "SH7MZH647S",
                environment: ["SHI_SECRETS_PEER_CHECK": value]) == .enforce(teamID: "SH7MZH647S"),
                "value \"\(value)\" must not disarm the check")
        }
    }

    @Test("T-07.4: observe does not refuse, enforce does")
    func test_refusesOnFailure_splitsTheTwoModes() {
        #expect(PeerCodePolicy.off.refusesOnFailure == false)
        #expect(PeerCodePolicy.observe(teamID: "X").refusesOnFailure == false)
        #expect(PeerCodePolicy.enforce(teamID: "X").refusesOnFailure == true)
        #expect(PeerCodePolicy.off.teamID == nil)
    }
}

@Suite("PeerCodeRequirement — the requirement text")
struct PeerCodeRequirementTests {

    @Test("T-07.5: the requirement is anchor-apple-generic plus the team OU, quoted")
    func test_requirementText_isTheDocumentedTeamForm() {
        let req = PeerCodeRequirement(teamID: "SH7MZH647S")
        #expect(req.text == "anchor apple generic and certificate leaf[subject.OU] = \"SH7MZH647S\"")
        // `anchor apple generic` is what makes it "a certificate Apple issued":
        // without it, any self-signed cert carrying that OU would satisfy the
        // leaf clause.
        #expect(req.text.hasPrefix("anchor apple generic and "))
        // The team id must be QUOTED. Unquoted, a team id that happens to be
        // a requirement keyword would change the expression's meaning.
        #expect(req.text.contains("\"SH7MZH647S\""))
    }

    @Test("T-07.6: the team id is not interpolated anywhere else — one source for the string")
    func test_requirementText_variesOnlyByTeamID() {
        let a = PeerCodeRequirement(teamID: "AAAAAAAAAA").text
        let b = PeerCodeRequirement(teamID: "BBBBBBBBBB").text
        #expect(a.replacingOccurrences(of: "AAAAAAAAAA", with: "BBBBBBBBBB") == b)
    }
}

@Suite("PeerCodeAuthorizer — against a real socket peer")
struct PeerCodeAuthorizerTests {

    /// Connected socketpair — the peer is this process.
    private func socketPair() -> (Int32, Int32)? {
        var fds = [Int32](repeating: -1, count: 2)
        let result = fds.withUnsafeMutableBufferPointer { ptr -> Int32 in
            socketpair(AF_UNIX, Int32(SOCK_STREAM), 0, ptr.baseAddress)
        }
        guard result == 0 else { return nil }
        return (fds[0], fds[1])
    }

    @Test("T-07.7: policy off admits without touching the socket at all")
    func test_policyOff_admits() {
        var lines: [String] = []
        // fd -1 is deliberately invalid: `.off` must not read the socket, so
        // an unreadable fd still admits. If this ever fails, the fast path
        // has started doing work an unarmed deployment did not ask for.
        let admitted = PeerCodeAuthorizer(policy: .off).admits(fd: -1) { lines.append($0) }
        #expect(admitted)
        #expect(lines.isEmpty)
    }

    @Test("T-07.8: a peer whose team id mismatches is REFUSED, and the reason names the requirement",
          .enabled(if: hasCodeSigning))
    func test_mismatchingTeam_isRefused_withNamedRequirement() {
        guard let (server, client) = socketPair() else {
            Issue.record("socketpair failed")
            return
        }
        defer { close(server); close(client) }

        var lines: [String] = []
        // No Apple team id is ten Zs, so the test runner cannot satisfy this
        // whatever it is signed with.
        let authorizer = PeerCodeAuthorizer(policy: .enforce(teamID: "ZZZZZZZZZZ"))
        let admitted = authorizer.admits(fd: server) { lines.append($0) }

        #expect(admitted == false, "an enforced mismatching team must be refused")
        #expect(lines.count == 1)
        let line = lines.first ?? ""
        #expect(line.contains("REFUSED"))
        // The refusal carries the requirement it evaluated, so an operator
        // reading launchd's log knows what to fix rather than that "something
        // was refused".
        #expect(line.contains("anchor apple generic"))
        #expect(line.contains("ZZZZZZZZZZ"))
    }

    @Test("T-07.9: the same failing peer in observe mode is ADMITTED, and says so",
          .enabled(if: hasCodeSigning))
    func test_sameFailingPeer_inObserveMode_isAdmitted() {
        guard let (server, client) = socketPair() else {
            Issue.record("socketpair failed")
            return
        }
        defer { close(server); close(client) }

        var lines: [String] = []
        let admitted = PeerCodeAuthorizer(policy: .observe(teamID: "ZZZZZZZZZZ"))
            .admits(fd: server) { lines.append($0) }

        #expect(admitted, "observe must never refuse — that is the whole escape hatch")
        #expect(lines.count == 1)
        let line = lines.first ?? ""
        #expect(line.contains("observe-only"))
        #expect(line.contains("ADMITTED"))
        // Paired with T-07.8 this is the real assertion: ONE peer, ONE
        // verdict, two different consequences. If both tests passed because
        // the check silently did nothing, T-07.8 would have admitted.
    }

    @Test("T-07.10: an invalid fd under an armed policy is refused, not admitted",
          .enabled(if: hasCodeSigning))
    func test_invalidFD_underArmedPolicy_isRefused() {
        var lines: [String] = []
        let admitted = PeerCodeAuthorizer(policy: .enforce(teamID: "SH7MZH647S"))
            .admits(fd: -1) { lines.append($0) }
        // "I could not identify the caller" must mean refused, never admitted.
        #expect(admitted == false)
        #expect(lines.first?.contains("REFUSED") == true)
    }

    @Test("T-07.11: the audit token is 8 words and is readable from a live socket",
          .enabled(if: hasCodeSigning))
    func test_auditToken_isReadFromTheSocket() throws {
        guard let (server, client) = socketPair() else {
            Issue.record("socketpair failed")
            return
        }
        defer { close(server); close(client) }
        let token = try peerAuditToken(fd: server)
        #expect(token.count == 8, "audit_token_t is 8 x UInt32 (mach/message.h)")
        // An all-zero token would mean getsockopt wrote nothing and returned
        // 0 — the shape that reads as a successful read of nobody.
        #expect(token.contains { $0 != 0 }, "an all-zero audit token is not a token")
    }

    @Test("T-07.12: reading a token from a non-socket fd fails rather than inventing one",
          .enabled(if: hasCodeSigning))
    func test_auditToken_onNonSocket_throws() {
        #expect(throws: PeerCodeIdentityError.self) {
            _ = try peerAuditToken(fd: -1)
        }
    }
}

@Suite("BrokerdSettings — the [peer] section")
struct BrokerdSettingsPeerTests {

    @Test("T-07.13: [peer] require_team_id parses, and an absent section is off")
    func test_peerSection_parses() throws {
        let armed = try BrokerdSettings.parse(toml: """
            [scope]
            allowlist = ["shi/**"]

            [peer]
            require_team_id = "SH7MZH647S"
            """)
        #expect(armed.requirePeerTeamID == "SH7MZH647S")
        #expect(armed.peerCodePolicy(environment: [:]) == .enforce(teamID: "SH7MZH647S"))

        let unarmed = try BrokerdSettings.parse(toml: """
            [scope]
            allowlist = ["shi/**"]
            """)
        #expect(unarmed.requirePeerTeamID == nil)
        #expect(unarmed.peerCodePolicy(environment: [:]) == .off)
    }

    @Test("T-07.14: an empty require_team_id is the same statement as an absent one")
    func test_emptyTeamID_isAbsent() throws {
        let settings = try BrokerdSettings.parse(toml: """
            [peer]
            require_team_id = ""
            """)
        #expect(settings.requirePeerTeamID == nil)
        #expect(settings.peerCodePolicy(environment: [:]) == .off)
    }

    @Test("T-07.15: require_team_id outside the [peer] section is NOT read")
    func test_teamID_atTopLevel_isIgnored() throws {
        // Section-scoped on purpose: a top-level key that silently armed the
        // check would mean two spellings of one setting, and the one nobody
        // documented would be the one in people's files.
        let settings = try BrokerdSettings.parse(toml: """
            require_team_id = "SH7MZH647S"

            [scope]
            allowlist = ["**"]
            """)
        #expect(settings.requirePeerTeamID == nil)
    }

    @Test("T-07.16: the generated default config ships the [peer] block commented out")
    func test_writtenDefaultConfig_documentsThePeerBlockWithoutArmingIt() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("brokerd-peer-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("secrets-brokerd.toml")

        try BrokerdSettings.writeDefaultIfMissing(at: path)
        let text = try String(contentsOf: path, encoding: .utf8)

        #expect(text.contains("[peer]"))
        #expect(text.contains("# require_team_id = \"SH7MZH647S\""))
        // And the written file must parse to OFF — a freshly installed daemon
        // does not refuse the operator's own build.
        let parsed = try BrokerdSettings.parse(toml: text)
        #expect(parsed.requirePeerTeamID == nil)
    }
}

@Suite("UnixSocketConfig — carries the policy")
struct UnixSocketConfigPeerPolicyTests {

    @Test("T-07.17: the policy defaults to off, so an existing deployment is unchanged")
    func test_configDefault_isOff() {
        let config = UnixSocketConfig(socketPath: "/tmp/x.sock", expectedUid: 501)
        #expect(config.peerCodePolicy == .off)
    }

    @Test("T-07.18: the policy is carried, and two configs differing only by policy are not equal")
    func test_configCarriesPolicy_andEqualityNotices() {
        let off = UnixSocketConfig(socketPath: "/tmp/x.sock", expectedUid: 501)
        let armed = UnixSocketConfig(
            socketPath: "/tmp/x.sock", expectedUid: 501,
            peerCodePolicy: .enforce(teamID: "SH7MZH647S"))
        #expect(armed.peerCodePolicy == .enforce(teamID: "SH7MZH647S"))
        #expect(off != armed)
    }
}
