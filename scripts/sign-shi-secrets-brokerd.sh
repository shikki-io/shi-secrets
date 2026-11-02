#!/usr/bin/env bash
# sign-shi-secrets-brokerd.sh — Team-sign shi-secrets-brokerd with SH7MZH647S.
#
# spec: 7c2e9a14 vault-lock-per-platform rev 3, W1.
#
# TEAM-SIGN PHASE (current):
#   Sign with the OBYW.ONE Apple Distribution identity only — no entitlements,
#   no provisioning profile required.  The resulting binary:
#     - Carries a stable SH7MZH647S team identifier so standard login-keychain
#       items (credentials + OAuth token) survive upgrades without re-prompting.
#     - Uses AppleKeychainCustody in memory-only mode because
#       keychain-access-groups is absent.  The vault session key is NOT
#       persisted to disk — re-entry of the master password is required after
#       a daemon restart.
#
# .APP FOLLOW-UP (next milestone):
#   Bundle the binary in a signed .app, register
#   io.shikki.vault-key in the Apple Developer Portal under App ID
#   io.shikki.secrets-brokerd, obtain the provisioning profile, then
#   re-sign with:
#     codesign --sign "$IDENTITY" \
#              --entitlements Sources/ShiSecretsBrokerd/ShikkiSecretsBrokerd.entitlements \
#              --timestamp --options runtime --force "$BINARY_PATH"
#   Restore the entitlements dict (keychain-access-groups SH7MZH647S.io.shikki.vault-key)
#   before that step — see the comment block in ShikkiSecretsBrokerd.entitlements.
#
# Usage:
#   ./scripts/sign-shi-secrets-brokerd.sh [--binary <path>]
#
# Default binary path: .build/release/shi-secrets-brokerd
# Override: SHI_CODESIGN_IDENTITY env var
#
# Prerequisites:
#   - Apple Distribution: OBYW.ONE (SH7MZH647S) cert in your login keychain.
#   - codesign(1) available (Xcode command line tools).
#   - NO provisioning profile required for this team-sign phase.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Identity ─────────────────────────────────────────────────────────────────
# Default: OBYW.ONE Apple Distribution (SH7MZH647S) per @db decision 2026-06-19.
IDENTITY="${SHI_CODESIGN_IDENTITY:-Apple Distribution: OBYW.ONE (SH7MZH647S)}"

# ── Binary path ──────────────────────────────────────────────────────────────
BINARY_PATH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--binary <path>]" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$BINARY_PATH" ]]; then
    BINARY_PATH="$REPO_ROOT/.build/release/shi-secrets-brokerd"
fi

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "✘ binary not found at: $BINARY_PATH" >&2
    echo "  Build first: swift build -c release --product shi-secrets-brokerd" >&2
    exit 1
fi

echo "→ Signing (team-sign, no entitlements): $BINARY_PATH"
echo "  Identity: $IDENTITY"
echo "  Entitlements: none (team-sign phase — see .app follow-up in script header)"

# ── Sign ─────────────────────────────────────────────────────────────────────
# No --entitlements flag: team-sign only.
# The standard login-keychain items (io.shikki.vault / vault-credentials and
# io.shikki.vault-key / access-token) are keyed by team ID and survive upgrades.
codesign \
    --sign "$IDENTITY" \
    --timestamp \
    --options runtime \
    --force \
    "$BINARY_PATH"

# ── Verify ───────────────────────────────────────────────────────────────────
echo "→ Verifying signature..."
codesign --verify --verbose=2 "$BINARY_PATH"

TEAM_ID=$(codesign -d --verbose=2 "$BINARY_PATH" 2>&1 \
    | grep TeamIdentifier \
    | awk -F= '{print $NF}' \
    | tr -d ' ')

echo "→ TeamIdentifier: $TEAM_ID"

if [[ "$TEAM_ID" != "SH7MZH647S" ]]; then
    echo "✘ TeamIdentifier mismatch — expected SH7MZH647S, got $TEAM_ID" >&2
    exit 1
fi

echo "✓ shi-secrets-brokerd signed with team SH7MZH647S (no entitlements)"
echo ""
echo "Install and restart (never overwrite a signed binary — SIGKILLs the running daemon):"
echo "  1. Write to a new path, then rename atomically:"
echo "     cp $BINARY_PATH ~/.shikki/bin/shikki-secrets-brokerd.new"
echo "     mv ~/.shikki/bin/shikki-secrets-brokerd.new ~/.shikki/bin/shikki-secrets-brokerd"
echo "  2. Restart the daemon:"
echo "     launchctl unload ~/Library/LaunchAgents/io.shikki.secrets-brokerd.plist"
echo "     launchctl load -w ~/Library/LaunchAgents/io.shikki.secrets-brokerd.plist"
echo "  3. Unlock and check vault status:"
echo "     shi secrets unlock"
echo "     shi secrets brokerd status   # reports 'memory only — ...' until .app step"
echo ""
echo "Note: vault session key is NOT persisted (memory-only custody)."
echo "  Re-entry of the master password is required after each daemon restart."
echo "  See .app follow-up in the script header to enable persistent custody."
