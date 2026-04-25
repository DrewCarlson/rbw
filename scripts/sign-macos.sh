#!/bin/sh
# Code-sign bwx + bwx-agent on macOS. Picks the strongest signing
# identity available in the login keychain:
#
#   1. `$IDENTITY`                           (explicit override)
#   2. "Developer ID Application: …"         (paid cert, distributable)
#   3. "Apple Development: …"                (free, Xcode auto-provisioned)
#   4. ad-hoc (`-`)                          (no cert; cargo-install users)
#
# Tiers 2 and 3 also sign an entitlements plist declaring a
# `keychain-access-groups` entry scoped to the signing identity's team
# ID. That unlocks the biometric-ACL Keychain path at runtime. Tier 4
# falls through to the plain-Keychain path; Touch ID enforcement lives
# in the agent's `require_presence` call rather than in the item ACL.
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
  # Developer ID Application is the only CLI-tool-friendly identity
  # that can carry a `keychain-access-groups` entitlement without a
  # provisioning profile. Apple Development certs *can* sign, but the
  # entitlement would only work inside a `.app` bundle with an
  # embedded profile, so we sign those plain (no entitlement) —
  # identical in effect to ad-hoc for bwx's purposes.
  pick="$(printf "%s" "$ids" | grep 'Developer ID Application' | head -1 \
           | sed -nE 's/.*"(.+)".*/\1/p')"
  if [ -n "$pick" ]; then printf "%s" "$pick"; return; fi
  pick="$(printf "%s" "$ids" | grep 'Apple Development' | head -1 \
           | sed -nE 's/.*"(.+)".*/\1/p')"
  if [ -n "$pick" ]; then printf "%s" "$pick"; return; fi
  printf "%s" "-"
}

extract_team_id() {
  # "Apple Development: Name (ABCD123456)" -> ABCD123456
  printf "%s" "$1" | sed -nE 's/.*\(([A-Z0-9]{10})\).*/\1/p'
}

IDENTITY_STR="$(pick_identity)"
# Only Developer ID Application signatures get the
# keychain-access-groups entitlement. Apple Development + ad-hoc go
# through the plain-Keychain path (Touch ID prompt enforced by bwx-
# agent's own LAContext call rather than by the item ACL).
case "$IDENTITY_STR" in
  "Developer ID Application"*) USE_ENTITLEMENTS=1 ;;
  *)                           USE_ENTITLEMENTS=0 ;;
esac

if [ "$USE_ENTITLEMENTS" -eq 0 ]; then
  if [ "$IDENTITY_STR" = "-" ]; then
    echo "signing mode: ad-hoc (plain Keychain path)"
  else
    echo "signing mode: $IDENTITY_STR (plain Keychain path)"
    echo "  (Developer ID Application is required for biometric-ACL"
    echo "   Keychain items on command-line tools; Apple Development"
    echo "   works for code-signing but not for"
    echo "   keychain-access-groups without a provisioning profile.)"
  fi
  for name in bwx bwx-agent; do
    bin="$BIN_DIR/$name"
    [ -x "$bin" ] || continue
    codesign --force --sign "$IDENTITY_STR" "$bin"
    echo "  signed: $bin"
  done
  exit 0
fi

TEAM_ID="$(extract_team_id "$IDENTITY_STR")"
if [ -z "$TEAM_ID" ]; then
  echo "error: couldn't extract team id from identity: $IDENTITY_STR" >&2
  exit 1
fi

echo "signing mode: $IDENTITY_STR (biometric-ACL Keychain path)"
ENTITLEMENTS="$(mktemp -t bwx-entitlements).plist"
trap "rm -f '$ENTITLEMENTS'" EXIT
cat > "$ENTITLEMENTS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>keychain-access-groups</key>
  <array>
    <string>${TEAM_ID}.bwx</string>
  </array>
</dict>
</plist>
EOF

for name in bwx bwx-agent; do
  bin="$BIN_DIR/$name"
  [ -x "$bin" ] || continue
  # Note: no `--options runtime` — Rust binaries can trip AMFI's
  # hardened runtime executable-memory checks. We still get the
  # keychain-access-groups entitlement honored without it.
  codesign --force --entitlements "$ENTITLEMENTS" \
           --sign "$IDENTITY_STR" "$bin"
  echo "  signed: $bin"
done

echo ""
echo "access group: ${TEAM_ID}.bwx"
echo "bwx touchid enroll will use a biometric-ACL Keychain item."
