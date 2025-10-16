#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/usr/local/bin/adumper-cloud"
if [[ ! -x "$SCRIPT_DIR/adumper-cloud" ]]; then
  echo "adumper-cloud wrapper not found or not executable." >&2
  exit 1
fi

if command -v sudo >/dev/null 2>&1; then
  echo "Linking adumper-cloud to $TARGET (may prompt for password)..."
  sudo ln -sf "$SCRIPT_DIR/adumper-cloud" "$TARGET"
else
  ln -sf "$SCRIPT_DIR/adumper-cloud" "$TARGET"
fi
echo "adumper-cloud linked at $TARGET"
