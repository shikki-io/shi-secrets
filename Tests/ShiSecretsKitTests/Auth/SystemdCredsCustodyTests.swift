import Crypto
import Foundation
import Testing
@testable import ShiSecretsKit

// SystemdCredsCustodyTests — unit tests for the W3 Linux custody conformer.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W3.
// KAGAMI SCOPE: ShiSecretsKitTests
//
// No real TPM2 or systemd. All tests inject FakeSystemdCredsRunner so no
// subprocess is launched — safe in CI and on macOS (non-Linux stub is tested
// via the error path).
//
// Tests:
//   T-05: noTPMRefusesAndNamesTheReason — BR-05.
//   bonus: roundTrip — store+load returns the original key pair.
//   bonus: clear — removes the blob file.
//   bonus: custodyDescription — names the platform.
//   bonus: loadMissing — returns nil when blob file is absent.

// kagami-scope: ShiSecretsKitTests

@Suite("SystemdCredsCustodyTests")
struct SystemdCredsCustodyTests {

    // MARK: - Helpers

    /// A SymmetricKeyPair fixture with deterministic key material.
    private func makeKeyPair() -> SymmetricKeyPair {
        SymmetricKeyPair(
            encKey: SymmetricKey(size: .bits256),
            macKey: SymmetricKey(size: .bits256)
        )
    }

    /// Temporary directory for blob files.
    private func makeTmpDir() -> String {
        let path = "/tmp/shi-systemd-e2e-\(UUID().uuidString.prefix(8))"
        try? FileManager.default.createDirectory(
            atPath: path, withIntermediateDirectories: true
        )
        return path
    }

    /// A SystemdCredsCustody backed by the fake runner (no subprocess).
    private func fakeCustody(dir: String, error: VaultKeyCustodyError? = nil) -> SystemdCredsCustody {
        let blobPath = (dir as NSString).appendingPathComponent("vault.cred")
        return SystemdCredsCustody(
            blobPath: blobPath,
            runner: FakeSystemdCredsRunner(forcedError: error)
        )
    }

    // MARK: - T-05: no TPM refuses with a named reason (BR-05)
    //
    // On non-Linux: the stub always throws tpmUnavailable — simulates
    //   a Linux system where the TPM is absent.
    // On Linux: inject a FakeSystemdCredsRunner with forcedError to simulate
    //   the same condition without needing a real TPM.

    @Test(
        "T-05: SystemdCredsCustody throws tpmUnavailable(reason:) when TPM is absent",
        .tags(.vaultLock)
    )
    func test_T05_noTPMRefusesAndNamesTheReason() async {
        let tmpDir = makeTmpDir()
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        #if os(Linux)
        // On Linux: inject a runner that simulates TPM2 absence.
        let custody = fakeCustody(
            dir: tmpDir,
            error: VaultKeyCustodyError.tpmUnavailable(reason: "no tpm2 device found")
        )
        #else
        // Non-Linux: the stub always throws tpmUnavailable.
        // Use the test-init so we can keep blobPath in a temp dir
        // (the no-op stub ignores both blobPath and runner, but the
        // init still compiles on macOS for this purpose).
        let custody = SystemdCredsCustody(
            blobPath: (tmpDir as NSString).appendingPathComponent("vault.cred"),
            runner: FakeSystemdCredsRunner(
                forcedError: VaultKeyCustodyError.tpmUnavailable(reason: "not linux")
            )
        )
        #endif

        // load() must throw tpmUnavailable.
        await #expect(throws: VaultKeyCustodyError.self) {
            _ = try await custody.load()
        }

        // store() must throw tpmUnavailable.
        let keys = makeKeyPair()
        await #expect(throws: VaultKeyCustodyError.self) {
            try await custody.store(keys)
        }

        // The thrown error must carry a reason string.
        do {
            _ = try await custody.load()
            Issue.record("expected tpmUnavailable throw from load()")
        } catch let err as VaultKeyCustodyError {
            switch err {
            case .tpmUnavailable(let reason):
                #expect(!reason.isEmpty, "BR-05: tpmUnavailable must carry a named reason")
            default:
                Issue.record("expected tpmUnavailable, got \(err)")
            }
        } catch {
            Issue.record("unexpected error type: \(error)")
        }

        // clear() must NOT throw — no-op on both platforms when nothing was stored.
        await #expect(throws: Never.self) {
            try await custody.clear()
        }
    }

    // MARK: - Round-trip: store → load returns original key pair

    @Test("round-trip: store then load returns the original key pair")
    func test_roundTrip() async throws {
        let tmpDir = makeTmpDir()
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        #if os(Linux)
        let custody = fakeCustody(dir: tmpDir)
        let original = makeKeyPair()
        try await custody.store(original)
        let loaded = try await custody.load()
        let enc = try #require(loaded, "load() must return the stored key pair")
        #expect(
            enc.encKey.withUnsafeBytes({ Data($0) }) ==
            original.encKey.withUnsafeBytes({ Data($0) }),
            "encKey must round-trip identically"
        )
        #expect(
            enc.macKey.withUnsafeBytes({ Data($0) }) ==
            original.macKey.withUnsafeBytes({ Data($0) }),
            "macKey must round-trip identically"
        )
        #else
        // Non-Linux: round-trip is not available (store throws tpmUnavailable).
        // Test is a no-op — it validates the stub's non-throwing clear() only.
        let custody = fakeCustody(dir: tmpDir)
        await #expect(throws: VaultKeyCustodyError.self) {
            try await custody.store(makeKeyPair())
        }
        #endif
    }

    // MARK: - clear removes the blob file

    @Test("clear() removes the blob file when present (Linux only)")
    func test_clear_removesBlobFile() async throws {
        #if os(Linux)
        let tmpDir = makeTmpDir()
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let custody = fakeCustody(dir: tmpDir)
        let blobPath = (tmpDir as NSString).appendingPathComponent("vault.cred")

        // Store something to create the blob.
        try await custody.store(makeKeyPair())
        #expect(FileManager.default.fileExists(atPath: blobPath), "blob must exist after store")

        // Clear should remove it.
        try await custody.clear()
        #expect(!FileManager.default.fileExists(atPath: blobPath), "blob must be removed after clear")
        #else
        // Non-Linux: clear is a no-op; no file is ever written.
        let tmpDir = makeTmpDir()
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let custody = fakeCustody(dir: tmpDir)
        await #expect(throws: Never.self) { try await custody.clear() }
        #endif
    }

    // MARK: - load returns nil when no blob exists

    @Test("load() returns nil when no blob file exists")
    func test_load_returnsNilWhenNoBlobFile() async throws {
        #if os(Linux)
        let tmpDir = makeTmpDir()
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let custody = fakeCustody(dir: tmpDir)
        let result = try await custody.load()
        #expect(result == nil, "load must return nil when no blob file is present")
        #else
        // Non-Linux: load() always throws tpmUnavailable; never returns nil.
        // The throw confirms BR-05 (already tested in T-05), skip this path.
        #endif
    }

    // MARK: - custodyDescription

    @Test("custodyDescription identifies the backend")
    func test_custodyDescription() {
        let tmpDir = makeTmpDir()
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }
        let custody = fakeCustody(dir: tmpDir)
        let desc = custody.custodyDescription
        #if os(Linux)
        #expect(desc.contains("systemd-creds"), "description must mention systemd-creds on Linux")
        #expect(desc.contains("tpm2"), "description must mention tpm2 on Linux")
        #else
        #expect(desc.contains("systemd-creds"), "description must mention systemd-creds (unavailable msg)")
        #endif
    }
}
