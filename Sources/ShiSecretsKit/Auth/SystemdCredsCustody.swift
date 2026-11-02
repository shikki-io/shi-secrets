import Crypto
import Foundation

// SystemdCredsCustody — Linux TPM2 / systemd-creds VaultKeyCustody implementation.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W3.
//
// BR-05: On Linux the vault key is sealed to the machine with `systemd-creds` and
// TPM2 and reaches the broker through CREDENTIALS_DIRECTORY. No TPM means a
// refusal with a named reason — never a plaintext fallback.
//
// Architecture:
//   - `store()` runs `systemd-creds encrypt --tpm2-device=auto --tpm2-pcrs=0+7`
//     and writes the sealed blob to a sidecar file alongside the custody path.
//   - `load()` reads the blob and runs `systemd-creds decrypt` to unseal it.
//   - `clear()` removes the sidecar blob (best-effort, no throw per BR-06).
//   - Non-Linux stub always throws `tpmUnavailable("systemd-creds not available")`.
//
// Test seam: an injected `SystemdCredsRunner` replaces the real subprocess calls
// so no TPM is needed in CI (T-05).
//
// Real-device proof (AC-W3-2): reboot nuc-dev with a sealed credential, verify
// the vault opens without a password. Operator-recorded in the PR; not automated.

// MARK: - SystemdCredsRunner (test seam protocol)

/// Abstracts the `systemd-creds` subprocess so tests can inject a fake runner.
public protocol SystemdCredsRunner: Sendable {
    /// Encrypt (seal) the given plaintext bytes and return the sealed blob.
    /// - Parameter data: plaintext 64-byte vault key pair
    /// - Returns: opaque sealed blob
    /// - Throws: `VaultKeyCustodyError.tpmUnavailable(reason:)` when TPM2 is absent
    func encrypt(_ data: Data) async throws -> Data

    /// Decrypt (unseal) the sealed blob and return the original plaintext.
    /// - Parameter blob: sealed blob produced by `encrypt`
    /// - Returns: original plaintext
    /// - Throws: `VaultKeyCustodyError.tpmUnavailable(reason:)` on TPM error
    func decrypt(_ blob: Data) async throws -> Data
}

// MARK: - Linux implementation

#if os(Linux)
import ShellKit

/// Linux production runner: shells out to `systemd-creds`.
/// Requires: systemd ≥ 251, `systemd-creds` on PATH, TPM2 present.
public struct ProductionSystemdCredsRunner: SystemdCredsRunner, Sendable {

    private static let timeout: TimeInterval = 30
    private let executor: any ShellExecutorProtocol

    public init(executor: any ShellExecutorProtocol = TimedShellExecutor()) {
        self.executor = executor
    }

    public func encrypt(_ data: Data) async throws -> Data {
        // systemd-creds encrypt reads from stdin when source is "-".
        // --tpm2-device=auto picks the first available TPM2 device.
        // --tpm2-pcrs=0+7: seals to firmware measurements (PCR-0) and
        // Secure Boot state (PCR-7) so a tampered boot chain cannot unseal.
        let blob = try await runProcess(
            arguments: [
                "systemd-creds", "encrypt",
                "--tpm2-device=auto",
                "--tpm2-pcrs=0+7",
                "-",   // source: stdin
                "-",   // destination: stdout
            ],
            stdin: data
        )
        guard !blob.isEmpty else {
            throw VaultKeyCustodyError.tpmUnavailable(
                reason: "systemd-creds encrypt produced empty output"
            )
        }
        return blob
    }

    public func decrypt(_ blob: Data) async throws -> Data {
        let blob = try await runProcess(
            arguments: [
                "systemd-creds", "decrypt",
                "-",   // source: stdin
                "-",   // destination: stdout
            ],
            stdin: blob
        )
        guard !blob.isEmpty else {
            throw VaultKeyCustodyError.tpmUnavailable(
                reason: "systemd-creds decrypt produced empty output"
            )
        }
        return blob
    }

    // MARK: - Process runner

    /// One `systemd-creds` run through ShellKit (timeout, SIGTERM/SIGKILL
    /// escalation, concurrency cap) — never a raw `Process`.
    private func runProcess(arguments: [String], stdin: Data) async throws -> Data {
        let result: ShellCommandResult
        do {
            result = try await executor.run(
                arguments, cwd: nil, env: nil, timeout: Self.timeout, stdin: stdin
            )
        } catch {
            throw VaultKeyCustodyError.tpmUnavailable(
                reason: "systemd-creds launch failed: \(error)"
            )
        }
        guard result.exitCode == 0 else {
            let reason = result.stderrString.trimmingCharacters(in: .whitespacesAndNewlines)
            throw VaultKeyCustodyError.tpmUnavailable(
                reason: reason.isEmpty ? "exit \(result.exitCode)" : reason
            )
        }
        return result.stdout
    }
}

/// Linux SystemdCredsCustody — seals and unseals the vault key pair via
/// `systemd-creds` + TPM2.
public struct SystemdCredsCustody: VaultKeyCustody, Sendable {

    /// Path where the sealed blob is written (alongside the custody path).
    private let blobPath: String
    /// Subprocess runner (production or injected test double).
    private let runner: any SystemdCredsRunner

    /// Production init. The state directory is injected by the caller (the
    /// broker's resolved layout) — the kit holds no home-directory literal.
    /// `credentialsDirectory` is systemd's `CREDENTIALS_DIRECTORY`, when set,
    /// and wins over the state directory.
    public init(stateDirectory: String, credentialsDirectory: String? = nil) {
        let base = credentialsDirectory ?? stateDirectory
        self.blobPath = (base as NSString).appendingPathComponent("vault.cred")
        self.runner   = ProductionSystemdCredsRunner()
    }

    /// Test-only init: inject a runner and an explicit blob path.
    public init(blobPath: String, runner: any SystemdCredsRunner) {
        self.blobPath = blobPath
        self.runner   = runner
    }

    // MARK: - VaultKeyCustody

    public nonisolated var custodyDescription: String {
        "systemd-creds (linux, tpm2, blob=\(blobPath))"
    }

    public func load() async throws -> SymmetricKeyPair? {
        guard FileManager.default.fileExists(atPath: blobPath) else {
            return nil
        }
        guard let blob = try? Data(contentsOf: URL(fileURLWithPath: blobPath)) else {
            return nil
        }
        let plaintext = try await runner.decrypt(blob)
        return try deserializeVaultKeyPair(plaintext)
    }

    public func store(_ keys: SymmetricKeyPair) async throws {
        let plaintext = serializeVaultKeyPair(keys)
        let blob = try await runner.encrypt(plaintext)
        let dir = URL(fileURLWithPath: blobPath).deletingLastPathComponent().path
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        try blob.write(to: URL(fileURLWithPath: blobPath), options: [.atomic])
        // 0o600: owner-read/write only.
        try? FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: Int16(0o600))],
            ofItemAtPath: blobPath
        )
    }

    public func clear() async throws {
        // Best-effort: no throw per BR-06 lock-must-not-be-blocked contract.
        try? FileManager.default.removeItem(atPath: blobPath)
    }
}

#else

// MARK: - Non-Linux stub

/// On non-Linux platforms (macOS, iOS, …), systemd-creds is unavailable.
/// All operations throw `tpmUnavailable` so callers fall back to the
/// platform-appropriate custody (AppleKeychainCustody on macOS).
public struct SystemdCredsCustody: VaultKeyCustody, Sendable {

    public init() {}

    /// Test-only init (matches the Linux signature so tests compile on macOS).
    public init(blobPath: String, runner: any SystemdCredsRunner) {}

    public nonisolated var custodyDescription: String {
        "systemd-creds (unavailable on this platform)"
    }

    public func load() async throws -> SymmetricKeyPair? {
        throw VaultKeyCustodyError.tpmUnavailable(
            reason: "systemd-creds is only available on Linux"
        )
    }

    public func store(_ keys: SymmetricKeyPair) async throws {
        throw VaultKeyCustodyError.tpmUnavailable(
            reason: "systemd-creds is only available on Linux"
        )
    }

    public func clear() async throws {
        // No-op — nothing was ever stored.
    }
}

#endif

// MARK: - Test helpers (all platforms)

/// Fake systemd-creds runner for T-05 and CI.
/// Encrypts with a trivial in-memory XOR (not secure — test-only) to avoid
/// any OS dependency. The actual byte pattern is irrelevant; correctness is
/// that encrypt(decrypt(x)) == x AND that a missing TPM2 path is tested via
/// `noTPMRunner`.
public struct FakeSystemdCredsRunner: SystemdCredsRunner, Sendable {

    /// If non-nil, both encrypt() and decrypt() throw this error.
    public let forcedError: VaultKeyCustodyError?

    public init(forcedError: VaultKeyCustodyError? = nil) {
        self.forcedError = forcedError
    }

    public func encrypt(_ data: Data) async throws -> Data {
        if let err = forcedError { throw err }
        // Trivial reversible transform: prepend a 1-byte magic tag + XOR with 0xFF.
        var out = Data([0xFE])
        out.append(contentsOf: data.map { $0 ^ 0xFF })
        return out
    }

    public func decrypt(_ blob: Data) async throws -> Data {
        if let err = forcedError { throw err }
        guard blob.first == 0xFE else {
            throw VaultKeyCustodyError.tpmUnavailable(reason: "fake: bad magic tag")
        }
        return Data(blob.dropFirst().map { $0 ^ 0xFF })
    }
}
