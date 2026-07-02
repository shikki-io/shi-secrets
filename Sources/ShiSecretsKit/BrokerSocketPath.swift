// BrokerSocketPath.swift
// Single source of truth for the shikki-secrets-brokerd socket path.
// Backlog 209d7d6c (#44) + operator's DRY golden-rule callout 2026-07-02.
//
// Before this file: the string
//   "~/.local/share/shikki/run/secrets-brokerd.sock"
// was hardcoded in 10 sites across ShiSecrets, ShiSecretsClient, and
// ShiSecretsBrokerd. Any future migration (Keychain, XDG-runtime, test
// override) had to touch every one of them. Now this type owns it.
//
// Placement in ShiSecretsKit (the shared kit) so both the daemon
// (ShiSecretsBrokerd) and the client library (ShiSecretsClient) — plus
// the CLI (ShiSecrets) that consumes both — resolve the same value.

import Foundation

/// Canonical resolution of the shikki-secrets-brokerd unix-domain-socket
/// path. Prefers the operator override `SHIKKI_BROKER_SOCKET`, falls back
/// to the XDG-native `~/.local/share/shikki/run/secrets-brokerd.sock` —
/// aligned with shikki's `LaunchAgentManager` plist / `ShikkiPaths.dataRoot()`.
public enum BrokerSocketPath {

    /// Env variable operators use to point clients + daemon at a custom
    /// socket path (dev, test, alternate install).
    public static let envKey = "SHIKKI_BROKER_SOCKET"

    /// Suffix under `$HOME` for the XDG-aligned default install path.
    /// Exposed so callers that need the un-expanded form (e.g. error
    /// messages, doctor descriptions) can render it without re-hardcoding.
    public static let xdgSuffix = "/.local/share/shikki/run/secrets-brokerd.sock"

    /// Fully-resolved socket path. Env override wins; XDG default is the
    /// fallback. Reads env at call time so a mutating test process can
    /// change it between calls.
    ///
    /// - Parameters:
    ///   - env: environment table. Defaults to the process env.
    ///   - homeDirectory: `$HOME` root. Defaults to `NSHomeDirectory()`.
    public static func resolve(
        env: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: String = NSHomeDirectory()
    ) -> String {
        if let overridden = env[envKey], !overridden.isEmpty {
            return overridden
        }
        return homeDirectory + xdgSuffix
    }

    /// Human-readable form for messages: `~/.local/share/shikki/run/secrets-brokerd.sock`.
    /// Never expands `~` — used in doctor descriptions, help strings, error hints.
    public static let humanReadableXDGPath = "~" + xdgSuffix
}
