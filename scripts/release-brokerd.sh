#!/usr/bin/env bash
# release-brokerd.sh — build shi-secrets-brokerd as a RELEASE artifact:
# hardened runtime, secure timestamp, notarized, with no build paths baked in.
#
# W3 of spec c4e9a1f7 (enterprise safety hardening), BR-H-04 / test T-07.
#
# WHY THIS SCRIPT EXISTS. The red-team audit of 2026-11-07
# (~/.shikki/reports/redteam-binary-audit-2026-11-07.md, decision d3c44a4f)
# measured the INSTALLED broker and found:
#
#   · signed "Apple Distribution" but with NO hardened runtime, so any
#     same-user process can task_for_pid / DYLD_INSERT_LIBRARIES it and read
#     vault session material out of its memory — the single highest-impact
#     finding in the audit;
#   · built `-c debug`, with two embedded paths proving it:
#     /Users/jeoffrey/.shikki/cache/repos/shi-secrets/.build/arm64-apple-macosx/debug/...
#   · NOT stripped: ~15.5k symbols, ~13.9k of them Swift-mangled, naming
#     KeychainSecureStore, VaultwardenTokenCache, VaultCredentialStore,
#     BrokerWireDispatcher.dispatchSecretGet/Set/List/Delete, AuditSink —
#     "a reverser gets the full attack map for free".
#
# So the daemon that holds the vault session was the least hardened binary in
# the fleet. This script is the one place that produces a shippable one, and
# it VERIFIES what it produced rather than trusting the flags it passed:
# every claim below is read back off the artifact with codesign/nm/strings.
#
# Usage:
#   scripts/release-brokerd.sh [--skip-notarize] [--out <dir>]
#
# Env:
#   SHI_CODESIGN_IDENTITY  signing identity (default: the OBYW.ONE Apple
#                          Distribution identity, Team SH7MZH647S — the same
#                          team PeerCodeIdentity.swift binds callers to)
#   SHI_NOTARY_PROFILE     notarytool keychain profile name (default:
#                          shikki-notary). Credentials never land in argv.
#   SHI_SYMBOL_CEILING     max symbol count tolerated (default: 2000)
#
# Exit codes are distinct so CI can tell a build failure from a verification
# failure from a notarization rejection:
#   64 usage · 65 build failed · 66 codesign failed · 67 verification failed
#   68 notarization failed

set -euo pipefail

SKIP_NOTARIZE=0
OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-notarize) SKIP_NOTARIZE=1; shift ;;
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) sed -n '1,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/dist}"
IDENTITY="${SHI_CODESIGN_IDENTITY:-Apple Distribution: OBYW.ONE (SH7MZH647S)}"
NOTARY_PROFILE="${SHI_NOTARY_PROFILE:-shikki-notary}"
SYMBOL_CEILING="${SHI_SYMBOL_CEILING:-2000}"
PRODUCT="shi-secrets-brokerd"
ENTITLEMENTS="$REPO_ROOT/Sources/ShiSecretsBrokerd/ShikkiSecretsBrokerd.entitlements"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "release-brokerd.sh: macOS only (codesign/notarytool)" >&2
  exit 64
fi

echo "== 1/5 build (release, build paths mapped out)"
# -file-prefix-map rewrites the compile-time paths the audit found embedded.
# The map target is a literal "/shikki-secrets", not another real path: the
# point is that the artifact stops disclosing the operator's username and
# workspace layout, and a second absolute path would only move the leak.
#
# No `-Xswiftc -Xfrontend -disable-reflection-metadata`: the audit explicitly
# flags it as UNSAFE here because Codable and Mirror need reflection, and the
# broker's wire types are Codable. Swift type metadata survives any strip, and
# the aim is cost, not prevention.
cd "$REPO_ROOT"
if ! swift build \
      --force-resolved-versions \
      -c release \
      --product "$PRODUCT" \
      -Xswiftc -file-prefix-map -Xswiftc "$REPO_ROOT=/shikki-secrets" \
      -Xlinker -dead_strip; then
  echo "release-brokerd.sh: build failed" >&2
  exit 65
fi

BUILT="$(swift build -c release --product "$PRODUCT" --show-bin-path)/$PRODUCT"
if [[ ! -f "$BUILT" ]]; then
  echo "release-brokerd.sh: built artifact not found at $BUILT" >&2
  exit 65
fi

mkdir -p "$OUT_DIR"
ARTIFACT="$OUT_DIR/$PRODUCT"
cp "$BUILT" "$ARTIFACT"

echo "== 2/5 strip"
# -x strips local symbols, -S the debug map. The Swift-mangled public symbols
# the audit listed are exported and survive; what goes is the ~22k stab/debug
# entries `nm -a` was seeing. Measured, not assumed, in step 4.
strip -x -S "$ARTIFACT"

echo "== 3/5 codesign (hardened runtime + secure timestamp)"
if ! codesign \
      --sign "$IDENTITY" \
      --entitlements "$ENTITLEMENTS" \
      --options runtime \
      --timestamp \
      --force \
      "$ARTIFACT"; then
  echo "release-brokerd.sh: codesign failed with identity '$IDENTITY'" >&2
  exit 66
fi

echo "== 4/5 verify the artifact (every claim read back off the file)"
FAIL=0
fail() { echo "  FAIL $*" >&2; FAIL=1; }
pass() { echo "  ok   $*"; }

# 4a — the signature is valid and strict.
if codesign --verify --strict --verbose=2 "$ARTIFACT" >/dev/null 2>&1; then
  pass "signature verifies (--strict)"
else
  fail "signature does not verify (--strict)"
fi

CS_INFO="$(codesign -dvvv "$ARTIFACT" 2>&1 || true)"

# 4b — hardened runtime. This is the audit's top finding; it is the one check
# whose absence must never be tolerated, so it is not warn-only.
if printf '%s' "$CS_INFO" | grep -q 'flags=.*runtime'; then
  pass "hardened runtime present"
else
  fail "hardened runtime ABSENT (codesign flags: $(printf '%s' "$CS_INFO" | grep -o 'flags=[^ ]*' || echo none))"
fi

# 4c — the team the broker's own peer check binds callers to.
EXPECTED_TEAM="$(printf '%s' "$IDENTITY" | sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p')"
if [[ -n "$EXPECTED_TEAM" ]]; then
  if printf '%s' "$CS_INFO" | grep -q "TeamIdentifier=$EXPECTED_TEAM"; then
    pass "TeamIdentifier=$EXPECTED_TEAM"
  else
    fail "TeamIdentifier is not $EXPECTED_TEAM ($(printf '%s' "$CS_INFO" | grep -o 'TeamIdentifier=[^ ]*' || echo absent))"
  fi
fi

# 4d — get-task-allow absent. With it present, hardened runtime buys nothing:
# the debugger can still attach.
ENTS="$(codesign -d --entitlements - --xml "$ARTIFACT" 2>/dev/null || true)"
if printf '%s' "$ENTS" | grep -q 'get-task-allow'; then
  fail "get-task-allow is PRESENT — hardened runtime is defeated"
else
  pass "get-task-allow absent"
fi

# 4e — no build paths. The exact defect the audit measured, by its own two
# markers.
if strings -a "$ARTIFACT" | grep -q '/\.build/.*/debug/'; then
  fail "a debug build path is embedded ($(strings -a "$ARTIFACT" | grep -m1 '/\.build/.*/debug/'))"
else
  pass "no debug build path embedded"
fi
USER_PATHS="$(strings -a "$ARTIFACT" | grep -c '^/Users/' || true)"
if [[ "${USER_PATHS:-0}" -gt 0 ]]; then
  fail "$USER_PATHS absolute /Users/ path string(s) embedded — -file-prefix-map did not cover them"
else
  pass "no /Users/ path strings"
fi

# 4f — no DWARF in the shipped binary, and no dSYM beside it.
if otool -l "$ARTIFACT" 2>/dev/null | grep -q '__DWARF'; then
  fail "__DWARF segment present in the shipped binary"
else
  pass "no __DWARF segment"
fi
if [[ -d "$ARTIFACT.dSYM" ]]; then
  fail "$ARTIFACT.dSYM sits beside the artifact — do not ship it"
else
  pass "no dSYM beside the artifact"
fi

# 4g — symbol ceiling. A count, not a pattern: the audit's point was the
# NUMBER of names a reverser gets, and a ceiling is the only check that
# notices a regression in it.
SYMBOLS="$(nm -a "$ARTIFACT" 2>/dev/null | wc -l | tr -d ' ')"
if [[ "${SYMBOLS:-0}" -gt "$SYMBOL_CEILING" ]]; then
  fail "$SYMBOLS symbol entries exceed the ceiling of $SYMBOL_CEILING (was ~38000 unstripped on 2026-11-07)"
else
  pass "$SYMBOLS symbol entries (ceiling $SYMBOL_CEILING)"
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "release-brokerd.sh: artifact verification FAILED — not shipping $ARTIFACT" >&2
  exit 67
fi

if [[ "$SKIP_NOTARIZE" -eq 1 ]]; then
  echo "== 5/5 notarize SKIPPED (--skip-notarize)"
  echo "release-brokerd.sh: verified but NOT notarized: $ARTIFACT"
  exit 0
fi

echo "== 5/5 notarize + staple"
ZIP="$OUT_DIR/$PRODUCT.zip"
ditto -c -k --keepParent "$ARTIFACT" "$ZIP"
if ! xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait --timeout 900; then
  echo "release-brokerd.sh: notarization failed (profile '$NOTARY_PROFILE')" >&2
  exit 68
fi
# A bare Mach-O cannot carry a stapled ticket; the zip can, and Gatekeeper
# falls back to the online check for the binary. Stapling the zip is the
# honest half, and `spctl --assess` is read back rather than assumed.
if ! xcrun stapler staple "$ZIP"; then
  echo "release-brokerd.sh: stapling the archive failed" >&2
  exit 68
fi
spctl --assess --type open --context context:primary-signature -v "$ZIP" || true

echo "release-brokerd.sh: shipped $ARTIFACT (+ $ZIP, notarized)"
