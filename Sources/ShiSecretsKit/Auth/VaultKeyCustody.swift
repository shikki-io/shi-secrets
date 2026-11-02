import Crypto
import Foundation

// VaultKeyCustody — protocol + stock conformers for vault key persistence.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W0.
//
// BR-01: master password is never stored; only the derived 64-byte key pair.
// BR-02: macOS — WhenUnlockedThisDeviceOnly, no backup, no sync (AppleKeychainCustody, W1).
// BR-05: Linux — systemd-creds + TPM2 (SystemdCredsCustody, W3).
//
// Stock conformers in this file:
//   FileBackedVaultKeyCustody  — file on disk; used by --dry-run + E2E tests.
//   InMemoryVaultKeyCustody    — pure in-memory; used by unit tests.
//
// W1 adds: AppleKeychainCustody (kSecAttrAccessibleWhenUnlockedThisDeviceOnly).
// W3 adds: SystemdCredsCustody (systemd-creds + TPM2).

// MARK: - Error

public enum VaultKeyCustodyError: Error, Sendable, Equatable, CustomStringConvertible {
    /// Stored bytes could not be decoded into a SymmetricKeyPair.
    case malformedData(expectedBytes: Int, gotBytes: Int)
    /// Linux: no TPM2 available; refusing plaintext fallback (BR-05).
    case tpmUnavailable(reason: String)
    /// macOS: data protection keychain unavailable — staying memory-only (BR-02).
    case dataProtectionUnavailable

    public var description: String {
        switch self {
        case .malformedData(let exp, let got):
            return "vault key custody: expected \(exp) bytes, got \(got)"
        case .tpmUnavailable(let r):
            return "vault key custody: no TPM2 (\(r)) — refusing memory-only fallback (BR-05)"
        case .dataProtectionUnavailable:
            return "vault key custody: data protection keychain unavailable — staying memory-only (BR-02)"
        }
    }
}

// MARK: - Protocol

/// Cross-platform protocol for persisting the derived vault session key.
///
/// BR-01: the master password is NEVER stored. Only the derived 64-byte
/// SymmetricKeyPair is persisted. Platform implementations:
///   - `FileBackedVaultKeyCustody`  — file on disk (--dry-run + E2E tests)
///   - `InMemoryVaultKeyCustody`    — in-process only (unit tests)
///   - `AppleKeychainCustody`       — WhenUnlockedThisDeviceOnly (W1)
///   - `SystemdCredsCustody`        — systemd-creds + TPM2 (W3)
public protocol VaultKeyCustody: Sendable {
    /// Load the persisted key pair. Returns `nil` when no key is stored.
    func load() async throws -> SymmetricKeyPair?

    /// Persist the key pair. Called immediately after a successful unlock.
    func store(_ keys: SymmetricKeyPair) async throws

    /// Delete the persisted key. Called by vault.lock. No-op if absent.
    func clear() async throws

    /// Human-readable custody name for vault.status reporting.
    var custodyDescription: String { get }
}

// MARK: - Serialisation helpers

/// Encode a SymmetricKeyPair to 64 raw bytes (32 enc + 32 mac).
public func serializeVaultKeyPair(_ pair: SymmetricKeyPair) -> Data {
    pair.encKey.withUnsafeBytes { Data($0) }
        + pair.macKey.withUnsafeBytes { Data($0) }
}

/// Decode a SymmetricKeyPair from 64 raw bytes.
public func deserializeVaultKeyPair(_ data: Data) throws -> SymmetricKeyPair {
    guard data.count == 64 else {
        throw VaultKeyCustodyError.malformedData(expectedBytes: 64, gotBytes: data.count)
    }
    return SymmetricKeyPair(
        encKey: SymmetricKey(data: data.prefix(32)),
        macKey: SymmetricKey(data: data.suffix(32))
    )
}

// MARK: - FileBackedVaultKeyCustody

/// File-backed VaultKeyCustody.
///
/// Stores the 64-byte key pair at `fileURL` with mode 0o600. Used by
/// `--dry-run` mode (E2E tests) and can be used for development.
///
/// BR-01 compliance: the file holds raw key bytes, never the master password.
/// No encryption of the stored bytes — filesystem permissions are the only
/// boundary here. For production macOS use `AppleKeychainCustody` (W1).
public struct FileBackedVaultKeyCustody: VaultKeyCustody, Sendable {

    private let fileURL: URL

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    public func load() async throws -> SymmetricKeyPair? {
        let path = fileURL.path
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let data = try Data(contentsOf: fileURL, options: [])
        guard !data.isEmpty else { return nil }
        return try deserializeVaultKeyPair(data)
    }

    public func store(_ keys: SymmetricKeyPair) async throws {
        let data = serializeVaultKeyPair(keys)
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true, attributes: nil
        )
        try data.write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o600)],
            ofItemAtPath: fileURL.path
        )
    }

    public func clear() async throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        try FileManager.default.removeItem(at: fileURL)
    }

    public var custodyDescription: String {
        "file (\(fileURL.lastPathComponent))"
    }
}

// MARK: - InMemoryVaultKeyCustody

/// Pure in-memory VaultKeyCustody for unit tests.
///
/// No I/O; no OS calls. All state is dropped when the process exits or
/// when `clear()` is called. Useful for tests that need the custody
/// protocol but don't care about persistence.
public actor InMemoryVaultKeyCustody: VaultKeyCustody {

    private var stored: SymmetricKeyPair?

    public init() {}

    public func load() async throws -> SymmetricKeyPair? { stored }

    public func store(_ keys: SymmetricKeyPair) async throws { stored = keys }

    public func clear() async throws { stored = nil }

    public nonisolated var custodyDescription: String { "memory (test only)" }
}
