#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${RUN_AFTER_BUILD:-1}" == 0 ]]; then
    exec "$root/start.dh" --build-only
fi
export CTI_HOST_PORT="${CTI_HOST_PORT:-${HOST_PORT:-5001}}"
exec "$root/start.dh" --build
