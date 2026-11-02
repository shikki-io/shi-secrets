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
