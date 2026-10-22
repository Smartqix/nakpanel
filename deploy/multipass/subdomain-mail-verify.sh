#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd -P)/subdomain-mail-verify.py" "$@"
