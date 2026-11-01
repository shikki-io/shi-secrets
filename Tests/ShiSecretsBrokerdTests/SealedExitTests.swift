// SealedExitTests — verifies the sealed-exit helpers that prevent the
// keychainCredentialsMissing crash-loop.
//
// Spec: fix/secrets-broker-unseal-2026-11-01
// Invariant: a missing or malformed Keychain entry must produce exit(0)
// so launchd (KeepAlive.SuccessfulExit=false) stops restarting the agent.
//
// Tests never touch the real Keychain: all inputs are synthetic
// BootstrapError values.

import Foundation
import Testing
@testable import ShiSecretsBrokerd
import ShiSecretsKit

@Suite("SealedExit helpers — keychainCredentialsMissing crash-loop prevention")
struct SealedExitTests {

    // MARK: - sealedExitCode

    @Test("keychainCredentialsMissing → exit code 0 (stops launchd restart)")
    func missingCredentials_exitCode0() {
        let code = sealedExitCode(for: BootstrapError.keychainCredentialsMissing)
        #expect(code == 0, "Clean exit must be 0 so KeepAlive.SuccessfulExit=false stops restart")
    }

    @Test("keychainCredentialsMalformed → exit code 0 (stops launchd restart)")
    func malformedCredentials_exitCode0() {
        let code = sealedExitCode(for: BootstrapError.keychainCredentialsMalformed)
        #expect(code == 0, "Malformed Keychain blob is a config gap, not a transient error")
    }

    @Test("vaultwardenConnectFailed → nil (transient; launchd may retry)")
    func vaultwardenConnectFailed_nilCode() {
        let code = sealedExitCode(for: BootstrapError.vaultwardenConnectFailed(message: "timeout"))
        #expect(code == nil, "Network failure is transient — launchd should retry")
    }

    @Test("keychainOSError → nil (unexpected OS state; launchd may retry)")
    func keychainOSError_nilCode() {
        let code = sealedExitCode(for: BootstrapError.keychainOSError(status: -25300))
        #expect(code == nil)
    }

    @Test("arbitrary non-BootstrapError → nil")
    func nonBootstrapError_nilCode() {
        struct Unrelated: Error {}
        let code = sealedExitCode(for: Unrelated())
        #expect(code == nil)
    }

    // MARK: - sealedExitMessage

    @Test("missing credentials message contains remediation command")
    func missingCredentials_messageContainsSetupCommand() {
        let msg = sealedExitMessage(for: BootstrapError.keychainCredentialsMissing)
        #expect(msg != nil, "keychainCredentialsMissing must produce a message")
        #expect(msg?.contains("shi secrets setup vault-credentials") == true,
                "Message must reference the remediation command")
        #expect(msg?.contains("launchctl kickstart") == true,
                "Message must show how to restart after seeding")
    }

    @Test("malformed credentials message mentions --force flag")
    func malformedCredentials_messageMentionsForce() {
        let msg = sealedExitMessage(for: BootstrapError.keychainCredentialsMalformed)
        #expect(msg != nil)
        #expect(msg?.contains("--force") == true,
                "Malformed entry requires --force to overwrite; message must say so")
    }

    @Test("vaultwardenConnectFailed → nil message (no sealed-exit path)")
    func vaultwardenConnectFailed_nilMessage() {
        let msg = sealedExitMessage(for: BootstrapError.vaultwardenConnectFailed(message: "x"))
        #expect(msg == nil)
    }

    // MARK: - Consistency: code and message always agree

    @Test("sealedExitCode and sealedExitMessage agree on keychainCredentialsMissing")
    func agreeMissing() {
        let e = BootstrapError.keychainCredentialsMissing
        #expect((sealedExitCode(for: e) != nil) == (sealedExitMessage(for: e) != nil),
                "Code and message must both be non-nil or both nil for the same error")
    }

    @Test("sealedExitCode and sealedExitMessage agree on keychainCredentialsMalformed")
    func agreeMalformed() {
        let e = BootstrapError.keychainCredentialsMalformed
        #expect((sealedExitCode(for: e) != nil) == (sealedExitMessage(for: e) != nil))
    }

    @Test("sealedExitCode and sealedExitMessage agree on vaultwardenConnectFailed")
    func agreeTransient() {
        let e = BootstrapError.vaultwardenConnectFailed(message: "net")
        #expect((sealedExitCode(for: e) != nil) == (sealedExitMessage(for: e) != nil))
    }
}
