import Foundation
@testable import ShiSecretsKit
import Testing

// A READ-ONLY audit of the real vault.
//
// Opt-in via VAULTWARDEN_AUDIT_LIVE=1, and deliberately separate from
// VAULTWARDEN_LIVE_TEST — that one WRITES a test item, and the whole point of
// this file is to look at a production vault without touching it.
//
// It answers one question the operator needs answered before deciding
// anything: how many items are sitting on the server in plaintext?
//
// No key and no unlock are required. "Is this string shaped like an
// EncString" is decidable without one, which also means this runs on a
// machine that cannot decrypt.
//
//   VAULTWARDEN_AUDIT_LIVE=1 swift test --filter VaultEncryptionAuditLiveTests

@Suite("VaultEncryptionAuditLiveTests", .serialized)
struct VaultEncryptionAuditLiveTests {

    private var enabled: Bool {
        ProcessInfo.processInfo.environment["VAULTWARDEN_AUDIT_LIVE"] == "1"
    }

    @Test("live vault encryption audit — READ ONLY (VAULTWARDEN_AUDIT_LIVE=1)")
    func auditLiveVault() async throws {
        guard enabled else { return }

        let creds = try KeychainVaultCredentials().load()
        let client = try VaultwardenClient(
            credentials: creds,
            configYmlVaultServer: creds.serverURL.absoluteString
        )
        try await client.connect()

        let audit = try await client.auditEncryption()

        // Printed, not just asserted: the operator is running this to SEE the
        // number, and a bare pass/fail would hide it.
        print("""

            ── live vault encryption audit ─────────────────────────────
              server     \(creds.serverURL.absoluteString)
              items      \(audit.total)
              encrypted  \(audit.encrypted)
              PLAINTEXT  \(audit.plaintext)
            ────────────────────────────────────────────────────────────
            """)
        if !audit.plaintextNames.isEmpty {
            print("  plaintext item names (already exposed by definition):")
            for name in audit.plaintextNames.sorted() { print("    • \(name)") }
            print("""

              These are readable by anyone with the database, and invisible to
              every Bitwarden client. Do NOT delete them — re-encrypt, then
              ROTATE each credential at its source.

            """)
        }

        // Not an assertion on `isClean`: a red suite here would say "the code
        // is broken", and it is not — the DATA is. The number is the output.
        #expect(audit.total >= 0)
    }
}
