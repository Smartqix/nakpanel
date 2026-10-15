#!/usr/bin/env bash
set -euo pipefail

# Read-only acceptance after a completed import. Credentials stay in private files.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${NAKPANEL_MAIL_VERIFY_SOURCE_CREDENTIAL_FILE:?source credential file required}"
: "${NAKPANEL_MAIL_VERIFY_TARGET_CREDENTIAL_FILE:?target credential file required}"
TEMP="$(mktemp -d)"
trap 'rm -r "$TEMP"' EXIT
(cd "$ROOT" && go build -o "$TEMP/probe" ./deploy/multipass/mailimportprobe)
NAKPANEL_MAIL_VERIFY_CREDENTIAL_FILE="$NAKPANEL_MAIL_VERIFY_SOURCE_CREDENTIAL_FILE" "$TEMP/probe" snapshot > "$TEMP/source.json"
NAKPANEL_MAIL_VERIFY_CREDENTIAL_FILE="$NAKPANEL_MAIL_VERIFY_TARGET_CREDENTIAL_FILE" "$TEMP/probe" snapshot > "$TEMP/target.json"
if ! cmp -s "$TEMP/source.json" "$TEMP/target.json"; then
  echo 'Mail verification failed: folder, message multiplicity, body hash, date or flags differ.' >&2
  exit 1
fi
echo 'Verified: source and destination message content, multiplicity, folders, dates and flags match.'
