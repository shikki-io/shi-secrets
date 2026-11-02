import Foundation

// VaultReencryptor — wire layer type for the vault.reencrypt verb.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W4.
//
// BR-10: Legacy plaintext entries are re-encrypted by an explicit verb that
// reports a count, and the values are flagged for rotation.
//
// This implementation covers the "list + count" phase per the spec's
// Out-of-scope note: "Rotating the plaintext-era secret values themselves;
// `reencrypt` only lists them."
//
// Wire: vault.reencrypt → BrokerWireDispatch.dispatchVaultReencrypt
//       → VaultReencryptResult {count: Int}
//
// VaultReencryptResult is declared in ShiSecretsClient/BrokerClient.swift
// as a public type shared by the client and daemon layers.

import Foundation

// MARK: - VaultReencryptResult

/// Result returned by vault.reencrypt (BR-10).
/// Declared in ShiSecretsKit so both ShiSecretsBrokerd and ShiSecretsClient can reference it.
public struct VaultReencryptResult: Sendable, Codable, Equatable {
    /// Number of items re-encrypted (or that would be re-encrypted in dry-run).
    public let count: Int
    /// Items that could not be re-encrypted: name → reason. Empty on full success.
    public let failures: [String: String]

    public init(count: Int, failures: [String: String] = [:]) {
        self.count = count
        self.failures = failures
    }
}

// MARK: - VaultReencryptError

/// Errors produced by the vault.reencrypt verb (BR-10).
public enum VaultReencryptError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The BWClient's VaultwardenClient was not wired before reEncryptLegacyPlaintext was called.
    case notWired
    /// One or more items could not be re-encrypted; failures maps name → reason.
    case partialFailure([String: String])

    public var description: String {
        switch self {
        case .notWired:
            return "vault.reencrypt: VaultwardenClient not wired — call wire(client:) before reEncryptLegacyPlaintext"
        case .partialFailure(let f):
            return "vault.reencrypt: \(f.count) item(s) failed — \(f.keys.joined(separator: ", "))"
        }
    }
}
