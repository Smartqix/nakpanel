#!/usr/bin/env bash
set -euo pipefail

# Read-only acceptance after a completed import. Credentials stay in private files.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${NAKPANEL_MAIL_VERIFY_SOURCE_CREDENTIAL_FILE:?source credential file required}"
: "${NAKPANEL_MAIL_VERIFY_TARGET_CREDENTIAL_FILE:?target credential file required}"
TEMP="$(mktemp -d)"
trap 'rm -r "$TEMP"' EXIT
probe="${NAKPANEL_MAIL_VERIFY_PROBE:-$TEMP/probe}"
if [[ -z "${NAKPANEL_MAIL_VERIFY_PROBE:-}" ]]; then
  (cd "$ROOT" && go build -o "$probe" ./deploy/multipass/mailimportprobe)
fi
[[ -x "$probe" ]] || { echo 'Mail verification probe is not executable.' >&2; exit 1; }
NAKPANEL_MAIL_VERIFY_CREDENTIAL_FILE="$NAKPANEL_MAIL_VERIFY_SOURCE_CREDENTIAL_FILE" "$probe" snapshot > "$TEMP/source.json"
NAKPANEL_MAIL_VERIFY_CREDENTIAL_FILE="$NAKPANEL_MAIL_VERIFY_TARGET_CREDENTIAL_FILE" "$probe" snapshot > "$TEMP/target.json"
if ! cmp -s "$TEMP/source.json" "$TEMP/target.json"; then
  echo 'Mail verification failed: folder, message multiplicity, body hash, date or flags differ.' >&2
  exit 1
fi
echo 'Verified: source and destination message content, multiplicity, folders, dates and flags match.'
if [[ -n "${NAKPANEL_MAIL_VERIFY_FOLDER:-}" ]]; then
  echo 'Verification was restricted to the explicitly selected folder.'
fi
