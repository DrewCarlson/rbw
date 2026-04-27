#!/bin/sh
# Code-sign bwx + bwx-agent on macOS. Picks the strongest signing
# identity available in the login keychain:
#
#   1. `$IDENTITY`                           (explicit override)
#   2. "Developer ID Application: …"         (paid cert, distributable)
#   3. "Apple Development: …"                (free, Xcode auto-provisioned)
#   4. ad-hoc (`-`)                          (no cert; cargo-install users)
#
# Tier 2 signs with hardened runtime + the
# `com.apple.security.cs.allow-unsigned-executable-memory` entitlement
# (Rust's allocator needs it; notarization auto-grants it). Touch ID
# enforcement lives in the agent's `require_presence` call rather than
# in a Keychain item ACL — bare CLI binaries cannot carry the
# `keychain-access-groups` restricted entitlement (it requires a
# provisioning profile, which a Mach-O CLI can't embed), and AMFI
# kills any Developer-ID build that asks for it.
#
# Usage:
#   ./scripts/sign-macos.sh                  # sign ~/.cargo/bin/bwx{,-agent}
#   ./scripts/sign-macos.sh /path/to/dir     # sign binaries in a different dir
#   IDENTITY="Developer ID Application: …" ./scripts/sign-macos.sh
set -eu

BIN_DIR="${1:-$HOME/.cargo/bin}"

pick_identity() {
  if [ -n "${IDENTITY:-}" ]; then
    printf "%s" "$IDENTITY"
    return
  fi
  ids="$(security find-identity -v -p codesigning 2>/dev/null || true)"
  # Developer ID Application is the only identity that pairs with
  # hardened runtime + notarization. Apple Development certs sign but
  # don't notarize, so they fall through to the plain path.
  pick="$(printf "%s" "$ids" | grep 'Developer ID Application' | head -1 \
           | sed -nE 's/.*"(.+)".*/\1/p')"
  if [ -n "$pick" ]; then printf "%s" "$pick"; return; fi
  pick="$(printf "%s" "$ids" | grep 'Apple Development' | head -1 \
           | sed -nE 's/.*"(.+)".*/\1/p')"
  if [ -n "$pick" ]; then printf "%s" "$pick"; return; fi
  printf "%s" "-"
}

# Extract the 10-char Apple Team ID from a Developer-ID identity
# string like `Developer ID Application: Some Name (TEAMID0123)`.
# Honors $TEAM_ID env override. Returns empty string on miss.
pick_team_id() {
  if [ -n "${TEAM_ID:-}" ]; then
    printf "%s" "$TEAM_ID"
    return
  fi
  printf "%s" "$1" | sed -nE 's/.*\(([0-9A-Z]{10})\).*/\1/p'
}

IDENTITY_STR="$(pick_identity)"
case "$IDENTITY_STR" in
  "Developer ID Application"*) USE_ENTITLEMENTS=1 ;;
  *)                           USE_ENTITLEMENTS=0 ;;
esac

if [ "$USE_ENTITLEMENTS" -eq 0 ]; then
  if [ "$IDENTITY_STR" = "-" ]; then
    echo "signing mode: ad-hoc"
  else
    echo "signing mode: $IDENTITY_STR (plain, no hardened runtime)"
  fi
  for name in bwx bwx-agent; do
    bin="$BIN_DIR/$name"
    [ -x "$bin" ] || continue
    codesign --force --sign "$IDENTITY_STR" "$bin"
    echo "  signed: $bin"
  done
  exit 0
fi

echo "signing mode: $IDENTITY_STR"

# `HARDENED_RUNTIME=1` opts the binary into Apple's hardened runtime
# (`codesign --options runtime`), required for notarization. The
# `allow-unsigned-executable-memory` entitlement is added so AMFI
# doesn't kill the Rust binary on first run — Rust's allocator + a few
# crates touch executable pages in ways the strict default rejects.
#
# `application-identifier` + `keychain-access-groups` scope bwx into
# the data-protection keychain under `TEAMID.bwx`. Without them
# `SecItemAdd` returns errSecMissingEntitlement (-34018) because the
# DP keychain has no group to associate items with. The runtime side
# in `src/touchid/keychain.rs` queries its own entitlements and only
# uses the DP keychain when this pair is present, so unentitled
# install paths (cargo-install, ad-hoc, Apple Development) keep
# working against the legacy file keychain.
#
# Local dev (no env var) skips hardened runtime entirely.
ENTITLEMENTS="$(mktemp -t bwx-entitlements).plist"
trap "rm -f '$ENTITLEMENTS'" EXIT
if [ "${HARDENED_RUNTIME:-0}" = "1" ]; then
  TEAM_ID_RESOLVED="$(pick_team_id "$IDENTITY_STR")"
  if [ -z "$TEAM_ID_RESOLVED" ]; then
    echo "error: could not extract Team ID from identity '$IDENTITY_STR';" >&2
    echo "       set TEAM_ID=XXXXXXXXXX to override." >&2
    exit 1
  fi
  cat > "$ENTITLEMENTS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
  <true/>
  <key>com.apple.application-identifier</key>
  <string>${TEAM_ID_RESOLVED}.bwx</string>
  <key>keychain-access-groups</key>
  <array>
    <string>${TEAM_ID_RESOLVED}.bwx</string>
  </array>
</dict>
</plist>
EOF
  HR_FLAG="--options=runtime"
  ENT_FLAG="--entitlements $ENTITLEMENTS"
else
  HR_FLAG=""
  ENT_FLAG=""
fi

for name in bwx bwx-agent; do
  bin="$BIN_DIR/$name"
  [ -x "$bin" ] || continue
  # shellcheck disable=SC2086
  codesign --force $HR_FLAG --timestamp $ENT_FLAG \
           --sign "$IDENTITY_STR" "$bin"
  echo "  signed: $bin"
done

echo ""
if [ "${HARDENED_RUNTIME:-0}" = "1" ]; then
  echo "hardened runtime: on (notarization-ready)"
fi
echo "Touch ID is enforced via a presence check before the agent"
echo "releases the wrapper key; no Keychain ACL is attached."
if [ "${HARDENED_RUNTIME:-0}" = "1" ]; then
  echo "keychain scope: data-protection (group ${TEAM_ID_RESOLVED}.bwx)"
fi
