#!/usr/bin/env bash
# sign-shi-secrets-brokerd.sh — Team-sign shi-secrets-brokerd with SH7MZH647S.
#
# spec: 7c2e9a14 vault-lock-per-platform rev 3, W1 (AC-W1-1).
#
# Required for AppleKeychainCustody (data protection Keychain):
#   - kSecAttrAccessibleWhenUnlockedThisDeviceOnly enforcement (BR-02)
#   - kSecUseDataProtectionKeychain support
#   - keychain-access-groups entitlement
#
# Usage:
#   ./scripts/sign-shi-secrets-brokerd.sh [--binary <path>]
#
# Default binary path: .build/release/shi-secrets-brokerd
# Override: SHI_CODESIGN_IDENTITY env var (same as codesign-admin-key-ceremony.sh)
#
# Prerequisites:
#   - Apple Distribution: OBYW.ONE (SH7MZH647S) cert in your login keychain.
#   - codesign(1) available (Xcode command line tools).

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

ENTITLEMENTS="$REPO_ROOT/Sources/ShiSecretsBrokerd/ShikkiSecretsBrokerd.entitlements"

if [[ ! -f "$ENTITLEMENTS" ]]; then
    echo "✘ entitlements not found at: $ENTITLEMENTS" >&2
    exit 1
fi

echo "→ Signing: $BINARY_PATH"
echo "  Identity: $IDENTITY"
echo "  Entitlements: $ENTITLEMENTS"

# ── Sign ─────────────────────────────────────────────────────────────────────
codesign \
    --sign "$IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    --timestamp \
    --options runtime \
    --force \
    "$BINARY_PATH"

# ── Verify ───────────────────────────────────────────────────────────────────
echo "→ Verifying signature..."
codesign --verify --verbose=2 "$BINARY_PATH"

TEAM=$(codesign -d --entitlements :- "$BINARY_PATH" 2>/dev/null \
    | plutil -extract "keychain-access-groups" raw - 2>/dev/null \
    || echo "(not present)")

echo "→ Team: $(codesign -d --verbose=2 "$BINARY_PATH" 2>&1 | grep TeamIdentifier | awk '{print $2}')"
echo "→ keychain-access-groups: $TEAM"

if [[ "$(codesign -d --verbose=2 "$BINARY_PATH" 2>&1 | grep TeamIdentifier | awk -F= '{print $NF}')" != "SH7MZH647S" ]]; then
    echo "✘ TeamIdentifier mismatch — expected SH7MZH647S" >&2
    exit 1
fi

echo "✓ shi-secrets-brokerd signed with SH7MZH647S"
echo ""
echo "Next: test data protection Keychain availability:"
echo "  .build/release/shi-secrets-brokerd --dry-run --socket /tmp/test.sock &"
echo "  shi secrets vault unlock --master-password <pw>"
echo "  shi secrets vault status    # should show 'custody: apple-keychain'"
echo "  # lock Mac screen, wait 2s, unlock"
echo "  shi secrets vault status    # should show 'custody: locked'"
