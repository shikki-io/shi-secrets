import Foundation

// BrokerdSettings — TOML config loader for the broker daemon.
//
// W4.1 of spec e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91
//
// Loads from ~/.shikki/settings/secrets-brokerd.toml using the same
// hand-parsing pattern as Bootstrap.readVaultURLFromTOML (no SPM deps).
//
// Config file shape:
//
//   vault_url = "https://vw.example.com"
//
//   [scope]
//   # Glob patterns allowed for secret.get requests.
//   # Empty list (the default) DENIES all reads.
//   # "**" matches anything (DEV ONLY — never use in production).
//   allowlist = ["**"]
//
// Config-chain for scopeAllowlist (highest priority first):
//   1. Explicit TOML file path (test injection via loadOrDefault(from:))
//   2. Default path ~/.shikki/settings/secrets-brokerd.toml
//   3. Fallback: ["**"] (dev-friendly, logged as WARN)
//
// Note: vaultURL is also extracted here for future migration of
// Bootstrap.readVaultURLFromTOML into this consolidated type.
// For now, Bootstrap continues to use its own reader for compatibility.

public struct BrokerdSettings: Sendable, Equatable {

    // MARK: - Properties

    /// Optional override for the Vaultwarden server URL.
    /// `nil` means: fall through to the Bootstrap config-chain.
    public let vaultURL: URL?

    /// Glob patterns allowed for `secret.get` requests.
    /// Empty list means deny-all reads. `["**"]` is the dev-friendly default.
    public let scopeAllowlist: [String]

    /// Apple Developer Team ID every CALLER must be signed by — `[peer]
    /// require_team_id` (W3 of spec c4e9a1f7, BR-H-04).
    ///
    /// `nil` means the code-identity check is OFF and the daemon says so at
    /// boot. It is deliberately not defaulted to the fleet team id: an
    /// operator's locally built `shi` is ad-hoc signed, so a default-armed
    /// check would refuse every dev worktree's `shi secret get` the moment
    /// this version is installed. See PeerCodeIdentity.swift.
    ///
    /// Unlike `scopeAllowlist`, an unreadable config does NOT fall back to
    /// permissive here — `loadOrDefault` returns an empty allowlist on
    /// malformed TOML and the daemon refuses to start, so the peer value is
    /// never reached in that path.
    public let requirePeerTeamID: String?

    // MARK: - Init

    public init(scopeAllowlist: [String], vaultURL: URL?, requirePeerTeamID: String? = nil) {
        self.scopeAllowlist = scopeAllowlist
        self.vaultURL = vaultURL
        self.requirePeerTeamID = requirePeerTeamID
    }

    /// The effective peer policy for this configuration, including the
    /// one-launch `SHI_SECRETS_PEER_CHECK=observe` downgrade.
    public func peerCodePolicy(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> PeerCodePolicy {
        PeerCodePolicy.resolve(requireTeamID: requirePeerTeamID, environment: environment)
    }

    // MARK: - Convenience

    /// True when the allowlist is exactly `["**"]` — the dev-mode wildcard.
    /// Used by Main.swift to emit a WARN about the prod alternative.
    public var isWildcardAllowlist: Bool {
        scopeAllowlist == ["**"]
    }

    // MARK: - TOML loading

    /// Load settings from a TOML file at `path`.
    ///
    /// - Throws: `BrokerdSettingsError.malformedTOML` when the file content
    ///   is syntactically invalid (e.g. unclosed section header, unterminated
    ///   array).
    /// - Returns: parsed settings; `scopeAllowlist` is `[]` when `[scope]`
    ///   section is absent.
    public static func load(from path: URL) throws -> BrokerdSettings {
        guard let text = try? String(contentsOf: path, encoding: .utf8) else {
            throw BrokerdSettingsError.malformedTOML(reason: "Could not read file at \(path.path)")
        }
        return try parse(toml: text)
    }

    /// Load settings from `path`, returning dev-friendly defaults when the
    /// file is absent.
    ///
    /// - Parameter path: TOML file URL. When the file does not exist,
    ///   returns `BrokerdSettings(scopeAllowlist: ["**"], vaultURL: nil)`.
    public static func loadOrDefault(from path: URL) -> BrokerdSettings {
        guard FileManager.default.fileExists(atPath: path.path) else {
            return BrokerdSettings(scopeAllowlist: ["**"], vaultURL: nil)
        }
        do {
            return try load(from: path)
        } catch {
            // v0.4.2 @ronin FINDING-2 fix: malformed-TOML must NOT silently
            // revert to the maximally-permissive `["**"]` default. Attacker
            // who can write the config (e.g. via symlink race on
            // ~/.shikki/settings/) would otherwise get wildcard scope. Refuse
            // by returning an empty allowlist; Main.swift's empty-check at
            // boot time (HIGH-6 guard) will then exit 78 with a clear error.
            FileHandle.standardError.write(Data(
                "shikki-secrets-brokerd: WARN refusing malformed allowlist at \(path.path) — empty allowlist returned; daemon will refuse to start.\n".utf8
            ))
            return BrokerdSettings(scopeAllowlist: [], vaultURL: nil)
        }
    }

    /// Load from the canonical default path `~/.shikki/settings/secrets-brokerd.toml`.
    public static func loadOrDefault(homeDirectory: String = NSHomeDirectory()) -> BrokerdSettings {
        let path = (homeDirectory as NSString)
            .appendingPathComponent(".shikki/settings/secrets-brokerd.toml")
        return loadOrDefault(from: URL(fileURLWithPath: path))
    }

    /// Write a dev-seed config file at `path` if and only if the file does
    /// not already exist. The written file contains a `[scope] allowlist = ["**"]`
    /// entry plus explanatory comments.
    ///
    /// This is idempotent: calling it on an existing file is a no-op.
    public static func writeDefaultIfMissing(at path: URL) throws {
        guard !FileManager.default.fileExists(atPath: path.path) else {
            return // no-op — do not overwrite operator-customized config
        }
        let defaultContent = """
            # secrets-brokerd configuration
            # Generated by shikki-secrets-brokerd on first boot.
            # Edit this file to customize behavior.
            #
            # vault_url = "https://vw.example.com"

            [scope]
            # Glob patterns allowed for secret.get requests.
            # Empty list DENIES all reads; secret.set and secret.list still work.
            # "**" matches anything — DEV ONLY. Never use in production.
            # Production examples: "shi/**", "ci/**", "verify-*"
            allowlist = ["**"]

            [peer]
            # Apple Developer Team ID every CALLER must be signed by
            # (spec c4e9a1f7 BR-H-04). Commented out on purpose: a locally
            # built `shi` is ad-hoc signed and would be REFUSED, so arming
            # this on a dev machine breaks `shi secret get`. Uncomment on a
            # machine that runs installed, signed binaries only.
            #
            # require_team_id = "SH7MZH647S"
            #
            # To see what the check WOULD do without refusing anybody, launch
            # the daemon once with SHI_SECRETS_PEER_CHECK=observe.
            """
        try defaultContent.write(to: path, atomically: true, encoding: .utf8)
    }

    // MARK: - Hand-parser (intentionally minimal — same pattern as Bootstrap.readVaultURLFromTOML)

    /// Parse a minimal TOML subset: top-level key = value, [section], array values.
    ///
    /// Supported shapes:
    ///   - `key = "value"` (quoted strings)
    ///   - `[section]`
    ///   - `key = ["item1", "item2"]` (string arrays, single-line only)
    ///   - `# comment` (ignored)
    ///   - Blank lines (ignored)
    ///
    /// Multi-line arrays are NOT supported by this parser. If a line contains
    /// an unclosed `[` in the section header position, it throws malformedTOML.
    static func parse(toml text: String) throws -> BrokerdSettings {
        var currentSection: String? = nil
        var scopeAllowlist: [String] = []
        var vaultURL: URL? = nil
        var requirePeerTeamID: String? = nil

        let lines = text.components(separatedBy: "\n")
        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespaces)

            // Skip blank and comment lines
            if line.isEmpty || line.hasPrefix("#") { continue }

            // Section header: [section-name]
            if line.hasPrefix("[") {
                guard line.hasSuffix("]") else {
                    throw BrokerdSettingsError.malformedTOML(
                        reason: "Unclosed section header: \(line)"
                    )
                }
                currentSection = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                continue
            }

            // Key = value
            guard let eqIdx = line.firstIndex(of: "=") else { continue }
            let key = line[..<eqIdx].trimmingCharacters(in: .whitespaces)
            let rawValue = line[line.index(after: eqIdx)...].trimmingCharacters(in: .whitespaces)

            if currentSection == "scope" && key == "allowlist" {
                scopeAllowlist = try parseStringArray(rawValue)
            } else if currentSection == "peer" && key == "require_team_id" {
                let stripped = stripQuotes(rawValue)
                // An empty value is the same statement as an absent key, and
                // `PeerCodePolicy.resolve` already treats "" as off — kept nil
                // here so the two spellings cannot diverge later.
                requirePeerTeamID = stripped.isEmpty ? nil : stripped
            } else if currentSection == nil && key == "vault_url" {
                let stripped = stripQuotes(rawValue)
                if !stripped.isEmpty, let url = URL(string: stripped) {
                    vaultURL = url
                }
            }
        }

        return BrokerdSettings(
            scopeAllowlist: scopeAllowlist,
            vaultURL: vaultURL,
            requirePeerTeamID: requirePeerTeamID)
    }

    /// Parse a single-line TOML string array: `["foo", "bar", "baz"]`.
    private static func parseStringArray(_ raw: String) throws -> [String] {
        var s = raw.trimmingCharacters(in: .whitespaces)
        guard s.hasPrefix("[") else {
            throw BrokerdSettingsError.malformedTOML(reason: "Expected array starting with '[', got: \(s)")
        }
        guard s.hasSuffix("]") else {
            throw BrokerdSettingsError.malformedTOML(reason: "Unclosed array (multi-line not supported): \(s)")
        }
        // Drop surrounding [ ]
        s = String(s.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
        if s.isEmpty { return [] }

        // Split on commas, strip quotes from each element
        var result: [String] = []
        for part in s.components(separatedBy: ",") {
            let elem = part.trimmingCharacters(in: .whitespaces)
            if elem.isEmpty { continue }
            let stripped = stripQuotes(elem)
            result.append(stripped)
        }
        return result
    }

    /// Strip surrounding `"..."` or `'...'` from a TOML string value.
    private static func stripQuotes(_ s: String) -> String {
        var r = s
        if (r.hasPrefix("\"") && r.hasSuffix("\"")) ||
           (r.hasPrefix("'") && r.hasSuffix("'")) {
            r = String(r.dropFirst().dropLast())
        }
        return r
    }
}

// MARK: - Errors

public enum BrokerdSettingsError: Swift.Error, Sendable, Equatable {
    /// The TOML file is syntactically invalid.
    case malformedTOML(reason: String)
}
