#!/bin/bash
# Regenerate scripts/requirements.lock from scripts/requirements.txt (core deps only).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LOCK_VENV="$ROOT/.lock-venv"
rm -rf "$LOCK_VENV"
python3 -m venv "$LOCK_VENV"
# shellcheck disable=SC1091
source "$LOCK_VENV/bin/activate"

pip install -q --upgrade pip setuptools wheel
pip install -q --prefer-binary -r scripts/requirements.txt
pip freeze > scripts/requirements.lock
rm -rf "$LOCK_VENV"

echo "Updated scripts/requirements.lock ($(wc -l < scripts/requirements.lock) packages)"
