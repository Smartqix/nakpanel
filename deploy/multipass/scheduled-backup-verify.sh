#!/usr/bin/env bash
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo 'Scheduled-backup qualification requires a disposable GitHub-hosted runner.' >&2
  exit 1
fi
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/scheduled-backup-verify.py" "$@"
