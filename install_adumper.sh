#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/usr/local/bin/adumper"
if [[ ! -x "$SCRIPT_DIR/adumper" ]]; then
  echo "adumper wrapper not found or not executable." >&2
  exit 1
fi

if command -v sudo >/dev/null 2>&1; then
  echo "Linking adumper to $TARGET (may prompt for password)..."
  sudo ln -sf "$SCRIPT_DIR/adumper" "$TARGET"
else
  ln -sf "$SCRIPT_DIR/adumper" "$TARGET"
fi
echo "adumper linked at $TARGET"
