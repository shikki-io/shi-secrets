// VaultwardenWireModels — Codable wire types for FakeVaultwardenServer.
//
// These mirror the private types in VaultwardenClient.swift so the fake server
// and the real client can't drift without a JSONDecoder failure catching the
// mismatch at test time.
//
// Naming follows the actual Bitwarden Identity / API JSON keys, including
// Vaultwarden's capitalisation quirks (Key, Kdf, KdfIterations).
//
// Used only by ShiSecretsE2ETests — never exported or linked into production
// targets.

// MARK: - Token endpoint

/// Response body for POST /identity/connect/token.
/// Mirrors VaultwardenClient's private TokenResponse.
struct VWTokenResponse: Encodable, Sendable {
    let access_token: String
    let expires_in: Int
    let token_type: String
    /// Vaultwarden capitalises this field.
    let Key: String?
    let Kdf: Int?
    let KdfIterations: Int?
}

// MARK: - Prelogin endpoint

/// Response body for POST /identity/accounts/prelogin.
struct VWPreloginResponse: Encodable, Sendable {
    let Kdf: Int
    let KdfIterations: Int
}

// MARK: - Cipher endpoints

/// Decoded request body for POST /api/ciphers.
/// Only name and notes are required; other fields (type, secureNote, …) are ignored.
struct VWCipherCreateRequest: Decodable, Sendable {
    let name: String    // EncString wire form
    let notes: String   // EncString wire form
}

/// Response body for POST /api/ciphers.
struct VWCipherCreateResponse: Encodable, Sendable {
    let id: String
    let name: String
}

/// Response body for GET /api/ciphers/{id}.
struct VWCipherItemResponse: Encodable, Sendable {
    let id: String
    let name: String
    let notes: String?
}

/// Single item in the cipher list array.
struct VWCipherListItem: Encodable, Sendable {
    let id: String
    let name: String
}

/// Response body for GET /api/ciphers.
struct VWCipherListResponse: Encodable, Sendable {
    let data: [VWCipherListItem]
}

/// Response body for DELETE /api/ciphers/{id} and other no-content responses.
struct VWEmpty: Encodable, Sendable {}

/// Error body for 4xx responses.
struct VWErrorBody: Encodable, Sendable {
    let error: String
    let error_description: String?
}
