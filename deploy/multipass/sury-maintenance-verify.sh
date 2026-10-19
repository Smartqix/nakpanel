#!/usr/bin/env bash
# Explicit disposable rehearsal only; no implicit source/profile/provider changes.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 "${SCRIPT_DIR}/sury-maintenance-drill.py" "$@"
