#!/bin/sh
# Install bwx + bwx-agent from the current working tree, then — on macOS
# — code-sign the resulting binaries so `bwx touchid enroll` can access
# the Keychain. Extra arguments are forwarded to `cargo install`.
#
# Usage:
#   ./scripts/install.sh                       # release build, default bindir
#   ./scripts/install.sh --root /some/prefix   # any cargo-install flag
#   IDENTITY="Developer ID Application: …" ./scripts/install.sh
#
# Run this instead of raw `cargo install` whenever you want the Touch ID
# feature to actually work on macOS.
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"

cargo install --path . --locked --force "$@"

if [ "$(uname -s)" = "Darwin" ]; then
  # Respect `--root` so we sign binaries in whichever prefix cargo just
  # installed to; otherwise default to ~/.cargo/bin.
  bin_dir="$HOME/.cargo/bin"
  prev=""
  for arg in "$@"; do
    if [ "$prev" = "--root" ]; then
      bin_dir="$arg/bin"
    fi
    prev="$arg"
  done

  "$DIR/scripts/sign-macos.sh" "$bin_dir"
fi
