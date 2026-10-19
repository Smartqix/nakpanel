#!/usr/bin/env bash
# Shared private guest paths. Sources are frozen host inputs; release identity
# is additionally bound to the exact selected manifest and out-of-band key.

configure_qualification_guest_paths() {
  # CI and soak source common.sh before init_qualification_run creates the
  # token. Do not turn that deferred signed source into a legacy /tmp default.
  if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" && -z "${NAKPANEL_RUN_TOKEN:-}" ]]; then return 0; fi
  if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" && -n "${NAKPANEL_RUN_TOKEN:-}" ]]; then
    [[ "${NAKPANEL_RUN_TOKEN}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{5,63}$ ]] || { echo 'unsafe qualification token' >&2; return 1; }
    NAKPANEL_GUEST_QUALIFICATION_ROOT="/var/lib/nakpanel-qualification/${NAKPANEL_RUN_TOKEN}"
    local expected="${NAKPANEL_GUEST_QUALIFICATION_ROOT}/source"
    [[ -z "${NAKPANEL_REMOTE_SRC:-}" || "${NAKPANEL_REMOTE_SRC}" == "${expected}" ]] || { echo 'signed qualification source must use the token-bound private guest path' >&2; return 1; }
    NAKPANEL_REMOTE_SRC="${expected}"
    NAKPANEL_GUEST_RELEASE_DIR="${NAKPANEL_GUEST_QUALIFICATION_ROOT}/release"
    NAKPANEL_GUEST_RELEASE_PUBLIC_KEY="${NAKPANEL_GUEST_QUALIFICATION_ROOT}/public.pem"
    export NAKPANEL_GUEST_QUALIFICATION_ROOT NAKPANEL_GUEST_RELEASE_DIR NAKPANEL_GUEST_RELEASE_PUBLIC_KEY
  else
    unset NAKPANEL_GUEST_QUALIFICATION_ROOT NAKPANEL_GUEST_RELEASE_DIR NAKPANEL_GUEST_RELEASE_PUBLIC_KEY
    NAKPANEL_REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
  fi
  export NAKPANEL_REMOTE_SRC
}

qualification_release_identity() {
  : "${NAKPANEL_RELEASE_BUNDLE:?signed release required}"
  : "${NAKPANEL_RELEASE_PUBLIC_KEY:?release trust anchor required}"
  : "${NAKPANEL_RELEASE_VERSION:?exact release version required}"
  python3 - "${NAKPANEL_RELEASE_BUNDLE}/manifest.json" "${NAKPANEL_RELEASE_PUBLIC_KEY}" <<'PY'
import hashlib,pathlib,sys
for path in map(pathlib.Path,sys.argv[1:]):
    if path.is_symlink() or not path.is_file():raise SystemExit('selected host identity must be regular files')
    print(hashlib.sha256(path.read_bytes()).hexdigest())
PY
}

qualification_release_operation() {
  local operation="$1" archive="${2:-}" key="${3:-}" archive_sha="${4:-}" archive_size="${5:-}" identity manifest_sha key_sha
  configure_qualification_guest_paths || return 1
  identity="$(qualification_release_identity)" || return 1
  manifest_sha="${identity%%$'\n'*}"; key_sha="${identity#*$'\n'}"
  local args=("${operation}" --token "${NAKPANEL_RUN_TOKEN}" --version "${NAKPANEL_RELEASE_VERSION}" --architecture "${NAKPANEL_MULTIPASS_ARCH}" --manifest-sha "${manifest_sha}" --key-sha "${key_sha}")
  [[ "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" != 1 ]] || args+=(--allow-development)
  [[ "${operation}" != stage ]] || args+=(--archive "${archive}" --archive-sha "${archive_sha}" --archive-size "${archive_size}" --public-key "${key}")
  multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo python3 "${NAKPANEL_REMOTE_SRC}/deploy/multipass/qualification_artifacts.py" "${args[@]}"
}

stage_qualification_release() (
  set -euo pipefail
  assert_current_vm_identity
  configure_qualification_guest_paths
  local helper_dir root_dir staging guest_archive guest_key archive_identity archive_sha archive_size
  helper_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  root_dir="$(cd "${helper_dir}/../.." && pwd -P)"
  local verify_args=(--bundle "${NAKPANEL_RELEASE_BUNDLE}" --public-key "${NAKPANEL_RELEASE_PUBLIC_KEY}" --version "${NAKPANEL_RELEASE_VERSION}" --architecture "${NAKPANEL_MULTIPASS_ARCH}")
  [[ "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" != 1 ]] || verify_args+=(--allow-development)
  python3 "${root_dir}/deploy/release/verify.py" "${verify_args[@]}"
  umask 077
  staging="$(mktemp -d)"
  trap 'rm -f "${staging}/release.tar"; rmdir "${staging}"' EXIT
  COPYFILE_DISABLE=1 tar -C "${NAKPANEL_RELEASE_BUNDLE}" -cf "${staging}/release.tar" .
  archive_identity="$(qualification_archive_identity "${staging}/release.tar")"
  read -r archive_sha archive_size <<<"${archive_identity}"
  guest_archive="/tmp/nakpanel-release-${NAKPANEL_RUN_TOKEN}.tar"
  guest_key="/tmp/nakpanel-key-${NAKPANEL_RUN_TOKEN}.pem"
  multipass transfer "${staging}/release.tar" "${NAKPANEL_MULTIPASS_VM}:${guest_archive}"
  multipass transfer "${NAKPANEL_RELEASE_PUBLIC_KEY}" "${NAKPANEL_MULTIPASS_VM}:${guest_key}"
  qualification_release_operation stage "${guest_archive}" "${guest_key}" "${archive_sha}" "${archive_size}"
  multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- rm -f "${guest_archive}" "${guest_key}"
)

qualification_archive_identity() {
  python3 - "$1" <<'PY'
import hashlib,pathlib,sys
path=pathlib.Path(sys.argv[1]);sha=hashlib.sha256()
with path.open('rb') as source:
 for block in iter(lambda:source.read(1024*1024),b''):sha.update(block)
print(sha.hexdigest(),path.stat().st_size)
PY
}

assert_qualification_installed_release() (
  [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]] || return 0
  export NAKPANEL_MULTIPASS_VM="${1:-${NAKPANEL_MULTIPASS_VM}}"
  assert_current_vm_identity
  qualification_release_operation installed
)

stage_qualification_public_probe() {
  local vm="$1" name="$2" helper_dir expected
  helper_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  case "$name" in roundcube-dr-canary.php|webhook_sink.py) ;; *) return 1;; esac
  expected="$(python3 - "${helper_dir}/${name}" <<'PYHASH'
import hashlib,pathlib,sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PYHASH
)" || return 1
  multipass_exec_short "${vm}" -- sudo python3 "${NAKPANEL_REMOTE_SRC}/deploy/multipass/qualification_artifacts.py" probe --token "${NAKPANEL_RUN_TOKEN}" --name "${name}" --sha "${expected}"
}

run_qualification_roundcube_canary() {
  local vm="$1" mode="$2" mailbox="$3" probe
  if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
    probe="$(stage_qualification_public_probe "${vm}" roundcube-dr-canary.php)" || return 1
  else
    probe="${NAKPANEL_REMOTE_SRC}/deploy/multipass/roundcube-dr-canary.php"
  fi
  multipass_exec_short "${vm}" -- sudo bash -se -- "${NAKPANEL_REMOTE_SRC}" "${probe}" "${mode}" "${mailbox}" <<'ROUNDCUBE_RUNTIME'
set -euo pipefail
source "$1/deploy/install/platform.sh"
nakpanel_require_platform || exit 1
exec sudo -u www-data "/usr/bin/php${NAKPANEL_INTERNAL_PHP_VERSION}" "$2" "$3" "$4"
ROUNDCUBE_RUNTIME
}
