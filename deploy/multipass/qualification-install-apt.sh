#!/usr/bin/env bash
# Skip optional translated package descriptions during the owned hosted install.
# APT_CONFIG is inherited by installer subprocesses, without changing system
# configuration, package sources, signatures, hashes or package error handling.
set -euo pipefail
umask 077
apt_config="$(mktemp "${TMPDIR:-/tmp}/nakpanel-qualification-apt.XXXXXXXX")"
trap 'rm -f "${apt_config}"' EXIT
printf '%s\n' 'Acquire::Languages "none";' >"${apt_config}"
APT_CONFIG="${apt_config}" "$@"
