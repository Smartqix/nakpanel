#!/usr/bin/env bash

if (( BASH_VERSINFO[0] < 5 )); then
  builtin printf '%s\n' 'Qualification requires GNU Bash 5 or newer.' \
    'Install GNU Bash 5+ and invoke the qualification entry point using its explicit executable path.' >&2
  builtin exit 1
fi

NAKPANEL_MULTIPASS_VM="${NAKPANEL_MULTIPASS_VM:-nakpanel-lab}"
NAKPANEL_MULTIPASS_IMAGE="${NAKPANEL_MULTIPASS_IMAGE:-26.04}"
NAKPANEL_REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-}"

NAKPANEL_LEGACY_PHASE_VMS=(
  nakpanel-phase1
  nakpanel-phase2
  nakpanel-phase3
  nakpanel-phase4
  nakpanel-phase4-tls
  nakpanel-phase5-ui
  nakpanel-phase6
  nakpanel-phase6-recovery
  nakpanel-phase7
  nakpanel-phase8
  nakpanel-phase9
  nakpanel-phase10
  nakpanel-phase11
  nakpanel-phase12
  nakpanel-phase13
  nakpanel-phase14
  nakpanel-phase15
  nakpanel-phase16
  nakpanel-phase17
  nakpanel-phase18
  nakpanel-phase19
  nakpanel-phase20
  nakpanel-phase21
  nakpanel-phase22
  nakpanel-phase23
  nakpanel-phase24
  nakpanel-phase25
  nakpanel-phase26
  nakpanel-phase27
  nakpanel-phase28
  nakpanel-phase29
  nakpanel-phase30
  nakpanel-phase31
  nakpanel-phase32
  nakpanel-phase33
  nakpanel-phase34
)

# Qualification fixtures cover every PHP version advertised by the selected
# installer profile. Sury is the default full-PHP Resolute contract.
NAKPANEL_QUALIFICATION_PHP_PROVIDER="${NAKPANEL_QUALIFICATION_PHP_PROVIDER:-sury}"
case "${NAKPANEL_MULTIPASS_IMAGE}:${NAKPANEL_QUALIFICATION_PHP_PROVIDER}" in
  26.04:sury)
    NAKPANEL_FIXTURE_PHP=8.4; NAKPANEL_BASELINE_PHP=8.3; NAKPANEL_PHP_VERSIONS=8.5,8.4,8.3
    NAKPANEL_QUALIFICATION_PROFILE=ubuntu-26.04-sury ;;
  26.04:native)
    NAKPANEL_FIXTURE_PHP=8.5; NAKPANEL_BASELINE_PHP=8.5; NAKPANEL_PHP_VERSIONS=8.5
    NAKPANEL_QUALIFICATION_PROFILE=ubuntu-26.04-native ;;
  *) NAKPANEL_FIXTURE_PHP=unsupported; NAKPANEL_BASELINE_PHP=unsupported; NAKPANEL_PHP_VERSIONS=unsupported; NAKPANEL_QUALIFICATION_PROFILE=unsupported ;;
esac
export NAKPANEL_FIXTURE_PHP NAKPANEL_BASELINE_PHP NAKPANEL_PHP_VERSIONS NAKPANEL_QUALIFICATION_PHP_PROVIDER NAKPANEL_QUALIFICATION_PROFILE

require_multipass() {
  if ! command -v multipass >/dev/null 2>&1; then
    echo "multipass is required" >&2
    exit 1
  fi
}

# Multipass 1.16 on macOS can leave its client process spinning after a short
# remote command has already exited. Buffer output until the client exits so
# downstream grep cannot close the pipe early, and retry only watchdog hangs.
multipass_exec_short() (
  umask 077
  local budget="${NAKPANEL_MULTIPASS_SHORT_TIMEOUT:-30}"
  local attempt pid waited output_dir exit_status
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/nakpanel-mp.XXXXXX")" || return 1
  trap 'rm -f "${output_dir}/stdin" "${output_dir}/stdout" "${output_dir}/stderr"; rmdir "${output_dir}"' EXIT
  # Bash disconnects asynchronous commands from the caller's stdin. Capture
  # redirected scripts/data once, then reopen the private buffer for every
  # watchdog attempt. Interactive callers must never block on a terminal read.
  if [[ -t 0 ]]; then
    : >"${output_dir}/stdin"
  else
    cat >"${output_dir}/stdin" || return 1
  fi
  for attempt in 1 2 3; do
    multipass exec "$@" <"${output_dir}/stdin" >"${output_dir}/stdout" 2>"${output_dir}/stderr" &
    pid=$!
    waited=0
    while kill -0 "${pid}" 2>/dev/null && [[ "${waited}" -lt "${budget}" ]]; do
      sleep 1
      waited=$((waited + 1))
    done
    if kill -0 "${pid}" 2>/dev/null; then
      kill -9 "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
      cat "${output_dir}/stdout" || true
      cat "${output_dir}/stderr" >&2 || true
      echo "multipass exec watchdog fired (attempt ${attempt})" >&2
      continue
    fi
    if wait "${pid}"; then
      exit_status=0
    else
      exit_status=$?
    fi
    cat "${output_dir}/stdout" || true
    cat "${output_dir}/stderr" >&2 || true
    return "${exit_status}"
  done
  echo "multipass exec kept hanging after three attempts" >&2
  return 124
)

require_nakpanel_vm_name() {
  local name="$1"
  if [[ ! "${name}" == nakpanel-* ]]; then
    echo "refusing to delete non-Nakpanel Multipass VM: ${name}" >&2
    echo "choose a VM name beginning with nakpanel- or run manual cleanup yourself" >&2
    exit 1
  fi
}

# A qualification run that selected a signed release must never silently
# switch to a working-tree build because its staged guest copy disappeared.
# Runs without a release retain the legacy source-development workflow.
assert_qualification_bundle_staged() {
  [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]] || return 0
  qualification_release_operation check || { echo 'expected signed release artifacts are missing, unsafe or differ from the selected host release; refusing source-build fallback' >&2; return 1; }
}

# A launch may create ownership only after confirming the actual guest identity.
# Existing guests require both records; a name prefix alone is never ownership.
NAKPANEL_OWNERSHIP_DIR="${NAKPANEL_OWNERSHIP_DIR:-${HOME}/.local/state/nakpanel/multipass}"
multipass_host_arch() {
  case "$(uname -m)" in
    arm64|aarch64) echo arm64 ;;
    x86_64|amd64) echo amd64 ;;
    *) echo unknown ;;
  esac
}
NAKPANEL_MULTIPASS_ARCH="${NAKPANEL_MULTIPASS_ARCH:-$(multipass_host_arch)}"

validate_run_identity() {
  [[ "${NAKPANEL_QUALIFICATION_PROFILE}" != unsupported ]] || { echo "unsupported qualification release/PHP provider" >&2; return 1; }
  [[ "${1:-}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{5,63}$ ]] || { echo "explicit safe NAKPANEL_RUN_TOKEN is required" >&2; return 1; }
  [[ "${NAKPANEL_MULTIPASS_IMAGE}" == 26.04 ]] || return 1
  [[ "${NAKPANEL_MULTIPASS_ARCH}" == arm64 || "${NAKPANEL_MULTIPASS_ARCH}" == amd64 ]] || return 1
}

assert_distinct_vm_names() {
  [[ "$1" != "$2" ]] || { echo "source and DR VM names must differ" >&2; return 1; }
}

assert_disposable_name() {
  require_nakpanel_vm_name "$1" || return 1
  [[ "$1" =~ ^nakpanel-[A-Za-z0-9-]+$ ]] || return 1
  case "$1" in nakpanel-lab|*soak*) echo "protected VM name: $1" >&2; return 1;; esac
}

init_qualification_run() {
  export NAKPANEL_RUN_TOKEN="${NAKPANEL_RUN_TOKEN:-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 4)}"
  validate_run_identity "${NAKPANEL_RUN_TOKEN}" || return 1
  if [[ "${NAKPANEL_MULTIPASS_VM}" == nakpanel-lab ]]; then
    export NAKPANEL_MULTIPASS_VM="nakpanel-${NAKPANEL_MULTIPASS_IMAGE//./-}-${NAKPANEL_MULTIPASS_ARCH}-${NAKPANEL_RUN_TOKEN}"
  fi
  export NAKPANEL_MULTIPASS_SOURCE_VM="${NAKPANEL_MULTIPASS_VM}"
  export NAKPANEL_MULTIPASS_DR_VM="${NAKPANEL_MULTIPASS_DR_VM:-${NAKPANEL_MULTIPASS_VM}-dr}"
  export NAKPANEL_MULTIPASS_VM NAKPANEL_MULTIPASS_ARCH NAKPANEL_MULTIPASS_IMAGE NAKPANEL_OWNERSHIP_DIR
  configure_qualification_guest_paths || return 1
  assert_disposable_name "${NAKPANEL_MULTIPASS_VM}" || return 1
  assert_disposable_name "${NAKPANEL_MULTIPASS_DR_VM}" || return 1
  assert_distinct_vm_names "${NAKPANEL_MULTIPASS_VM}" "${NAKPANEL_MULTIPASS_DR_VM}"
}

probe_vm_identity() {
  # The marker is root-owned and cannot be replaced via the unprivileged user.
  multipass_exec_short "$1" -- sudo bash -c '
set -euo pipefail
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo "guest identity requires Ubuntu" >&2; exit 1; }
printf "%s\n" "$VERSION_ID"
dpkg --print-architecture
marker=/etc/nakpanel-qualification-owner
if [[ -f "$marker" && ! -L "$marker" && "$(stat -c %u:%a "$marker")" == 0:600 ]]; then cat "$marker"; else printf "\n"; fi
' nakpanel-identity-probe
}

assert_vm_identity() {
  local name="$1" version="$2" arch="$3" token="$4" manifest identity expected
  validate_run_identity "${token}" || return 1
  assert_disposable_name "${name}" || return 1
  manifest="${NAKPANEL_OWNERSHIP_DIR}/${token}/${name}"
  [[ -f "${manifest}" && ! -L "${manifest}" ]] || { echo "VM has no host ownership record: ${name}" >&2; return 1; }
  expected="$(printf '%s\t%s\t%s' "${version}" "${arch}" "${token}")"
  [[ "$(cat "${manifest}")" == "${expected}" ]] || { echo "VM host ownership mismatch: ${name}" >&2; return 1; }
  # Multipass may report cloud-init done just before a reboot resets SSH.
  # Retry only failed read transports; a completed mismatched probe fails now.
  local probe_attempt probe_version probe_ok=0
  for probe_attempt in 1 2 3; do
    if identity="$(probe_vm_identity "${name}")"; then
      # The macOS client occasionally reports SSH reset with a successful
      # exit and no protocol body. A real probe always starts version+arch.
      probe_version="${identity%%$'\n'*}"
      if [[ "${probe_version}" =~ ^[0-9]+\.[0-9]+$ && "${identity}" == *$'\n'* ]]; then probe_ok=1; break; fi
    fi
    [[ "${probe_attempt}" == 3 ]] || sleep 2
  done
  [[ "${probe_ok}" == 1 ]] || return 1
  expected="$(printf '%s\n%s\n%s' "${version}" "${arch}" "${token}")"
  [[ "${identity}" == "${expected}" ]] || { echo "VM guest identity/ownership mismatch: ${name}" >&2; return 1; }
}

assert_current_vm_identity() {
  assert_distinct_vm_names "${NAKPANEL_MULTIPASS_SOURCE_VM:-${NAKPANEL_MULTIPASS_VM}}" "${NAKPANEL_MULTIPASS_DR_VM:-${NAKPANEL_MULTIPASS_VM}-dr}" || return 1
  assert_vm_identity "${NAKPANEL_MULTIPASS_VM}" "${NAKPANEL_MULTIPASS_IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN:-}"
}

wait_for_cloud_init() {
  local name="${1:-${NAKPANEL_MULTIPASS_VM}}"
  local cloud_init_done=0
  for _ in $(seq 1 90); do
    if multipass_exec_short "${name}" -- cloud-init status 2>/dev/null | grep -q 'status: done'; then
      cloud_init_done=1
      break
    fi
    sleep 2
  done

  if [[ "${cloud_init_done}" != "1" ]]; then
    multipass_exec_short "${name}" -- cloud-init status --long || true
    echo "cloud-init did not finish in time" >&2
    exit 1
  fi
}

# The expected guest release remains NAKPANEL_MULTIPASS_IMAGE. An optional
# independently verified local cloud image only changes the launch transport.
# HTTPS images can be downloaded by the operator and supplied as local files;
# this helper never fetches a mutable remote URL or weakens guest validation.
resolve_multipass_launch_image() {
  local source="${NAKPANEL_MULTIPASS_IMAGE_SOURCE:-}" digest="${NAKPANEL_MULTIPASS_IMAGE_SHA256:-}"
  if [[ -z "${source}" && -z "${digest}" ]]; then
    printf '%s\n' "${NAKPANEL_MULTIPASS_IMAGE}"
    return 0
  fi
  python3 - "${source}" "${digest}" <<'IMAGE'
import hashlib, pathlib, re, sys
source, expected = sys.argv[1:]
if not source or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
    raise SystemExit("pinned image requires an absolute local source and exact SHA256")
path = pathlib.Path(source)
if not path.is_absolute() or path.is_symlink() or not path.is_file():
    raise SystemExit("pinned image must be an absolute regular file, never a symlink")
sha = hashlib.sha256()
with path.open("rb") as image:
    for block in iter(lambda: image.read(1024 * 1024), b""):
        sha.update(block)
if sha.hexdigest() != expected.lower():
    raise SystemExit("pinned image SHA256 mismatch; refusing launch")
print(path.resolve().as_uri())
IMAGE
}

record_vm_launch_image() {
  # Keep image evidence separate from the exact ownership TSV contract.
  python3 - "$1" "$2" "${NAKPANEL_MULTIPASS_IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_MULTIPASS_IMAGE_SHA256:-}" <<'IMAGE'
import json, os, sys
path, source, release, architecture, digest = sys.argv[1:]
record = dict(source=source, sha256=digest.lower() if source.startswith("file://") else None,
              expected_release=release, expected_architecture=architecture,
              verification="local-sha256" if source.startswith("file://") else "multipass-alias")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as output:
    json.dump(record, output, indent=2)
    output.write("\n")
IMAGE
}

ensure_vm() {
  local cpus="${1:-2}"
  local memory="${2:-3G}"
  local disk="${3:-16G}"
  # Dedicated hosted qualification may lower guest allocation without changing
  # any product gate. DR keeps its own bounded allocation, defaults unchanged.
  if [[ "${NAKPANEL_MULTIPASS_VM}" == "${NAKPANEL_MULTIPASS_DR_VM:-}" ]]; then
    cpus="${NAKPANEL_QUALIFICATION_DR_CPUS:-${cpus}}"
    memory="${NAKPANEL_QUALIFICATION_DR_MEMORY:-${memory}}"
    disk="${NAKPANEL_QUALIFICATION_DR_DISK:-${disk}}"
  else
    cpus="${NAKPANEL_QUALIFICATION_VM_CPUS:-${cpus}}"
    memory="${NAKPANEL_QUALIFICATION_VM_MEMORY:-${memory}}"
    disk="${NAKPANEL_QUALIFICATION_VM_DISK:-${disk}}"
  fi
  [[ "${cpus}" =~ ^[1-9][0-9]*$ && "${memory}" =~ ^[1-9][0-9]*[MG]$ && "${disk}" =~ ^[1-9][0-9]*[MG]$ ]] || { echo "invalid qualification guest resource budget" >&2; return 1; }
  require_multipass
  validate_run_identity "${NAKPANEL_RUN_TOKEN:-}" || return 1
  assert_disposable_name "${NAKPANEL_MULTIPASS_VM}" || return 1
  assert_distinct_vm_names "${NAKPANEL_MULTIPASS_SOURCE_VM:-${NAKPANEL_MULTIPASS_VM}}" "${NAKPANEL_MULTIPASS_DR_VM:-${NAKPANEL_MULTIPASS_VM}-dr}" || return 1
  if multipass info "${NAKPANEL_MULTIPASS_VM}" >/dev/null 2>&1; then
    assert_current_vm_identity || return 1
  else
    local identity expected manifest launch_image
    launch_image="$(resolve_multipass_launch_image)" || return 1
    manifest="${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}/${NAKPANEL_MULTIPASS_VM}"
    [[ ! -e "${manifest}" && ! -L "${manifest}" && ! -e "${manifest}.image.json" && ! -L "${manifest}.image.json" ]] || { echo "stale ownership or image evidence; use a new run token" >&2; return 1; }
    multipass launch "${launch_image}" --name "${NAKPANEL_MULTIPASS_VM}" --cpus "${cpus}" --memory "${memory}" --disk "${disk}" || return 1
    wait_for_cloud_init "${NAKPANEL_MULTIPASS_VM}"
    identity="$(probe_vm_identity "${NAKPANEL_MULTIPASS_VM}")" || return 1
    expected="$(printf '%s\n%s' "${NAKPANEL_MULTIPASS_IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}")"
    [[ "${identity}" == "${expected}" ]] || { echo "launched guest identity mismatch" >&2; return 1; }
    multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -c 'set -e; test ! -e /etc/nakpanel-qualification-owner; umask 077; printf "%s\n" "$1" > /etc/nakpanel-qualification-owner' _ "${NAKPANEL_RUN_TOKEN}" || return 1
    (umask 077; mkdir -p "${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}"; printf '%s\t%s\t%s\n' "${NAKPANEL_MULTIPASS_IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}" > "${manifest}") || return 1
    record_vm_launch_image "${manifest}.image.json" "${launch_image}" || return 1
    assert_current_vm_identity || return 1
  fi
  wait_for_cloud_init "${NAKPANEL_MULTIPASS_VM}"
}

ensure_lab_quota() {
  assert_current_vm_identity || return 1
  require_nakpanel_vm_name "${NAKPANEL_MULTIPASS_VM}"
  multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -se <<'QUOTA'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
packages=(quota)
if apt-cache show "linux-modules-extra-$(uname -r)" >/dev/null 2>&1; then packages+=("linux-modules-extra-$(uname -r)"); fi
apt-get install -y "${packages[@]}"
modprobe quota_v2 >/dev/null 2>&1 || true
target="$(findmnt -n -o TARGET --target /home)"
test -n "${target}"
if ! findmnt -n -o OPTIONS --target /home | tr ',' '\n' | grep -qx usrquota; then
 mount -o remount,usrquota,grpquota "${target}"
fi
state="$(quotaon -p "${target}" 2>/dev/null || true)"
if ! grep -Eq 'user quota .* is on' <<<"${state}"; then
 quotacheck -ugm "${target}" || quotacheck -cugm "${target}"
 quotaon -uv "${target}" || true
fi
state="$(quotaon -p "${target}" 2>/dev/null || true)"
grep -Eq 'user quota .* is on' <<<"${state}"
QUOTA
}

sync_repo() (
  assert_current_vm_identity || return 1
  local root_dir="$1"
  local remote_src="${2:-${NAKPANEL_REMOTE_SRC}}"
  local signed_source=0
  if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
    configure_qualification_guest_paths || return 1
    [[ "${remote_src}" == "${NAKPANEL_REMOTE_SRC}" ]] || { echo 'signed source destination differs from private run path' >&2; return 1; }
    signed_source=1
  elif [[ ! "${remote_src}" =~ ^/tmp/nakpanel-[A-Za-z0-9._-]+$ ]]; then
    echo "refusing unsafe Multipass sync destination: ${remote_src}" >&2
    echo "NAKPANEL_REMOTE_SRC must be a direct child of /tmp named nakpanel-*" >&2
    return 1
  fi
  local tmpdir remote_archive
  tmpdir="$(mktemp -d)"
  remote_archive="/tmp/nakpanel-source-$$.tar"
  trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
  # Include working-tree edits and nonignored new sources, but never local
  # secrets, build caches, sockets or this task's private test artifacts.
  git -C "${root_dir}" ls-files -z --cached --others --exclude-standard |
    COPYFILE_DISABLE=1 tar -C "${root_dir}" --null -T - -cf "${tmpdir}/source.tar"
  local archive_identity source_sha source_size
  archive_identity="$(qualification_archive_identity "${tmpdir}/source.tar")" || return 1
  read -r source_sha source_size <<<"${archive_identity}"
  multipass transfer "${tmpdir}/source.tar" "${NAKPANEL_MULTIPASS_VM}:${remote_archive}"
  if [[ "${signed_source}" == 1 ]]; then
    # Feed the trusted host program directly through stdin. No guest-writable
    # temporary executable can race a privileged source-staging operation.
    multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo python3 - source --token "${NAKPANEL_RUN_TOKEN}" --archive "${remote_archive}" --archive-sha "${source_sha}" --archive-size "${source_size}" < "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/qualification_artifacts.py"
  else
    multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- bash -c '
set -euo pipefail
sudo rm -rf "$1"
sudo install -d -m 0755 -o ubuntu -g ubuntu "$1"
tar --no-same-owner -xf "$2" -C "$1"
' _ "${remote_src}" "${remote_archive}"
  fi
  wait_for_repo_sync "${remote_src}"
  multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- rm -f "${remote_archive}"
)

# Multipass 1.16 on macOS can return from a recursive transfer while the daemon
# is still materializing the final files. Require the build inputs to exist and
# the remote file count to be stable before a verifier enters the source tree.
wait_for_repo_sync() {
  local remote_src="$1"
  local previous_count="" stable_checks=0 file_count=""
  for _ in $(seq 1 60); do
    file_count="$(multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -c \
      'test -f "$1/go.mod" && test -f "$1/sqlc.yaml" && test -f "$1/cmd/panel/main.go" && test -f "$1/internal/control/http/server.go" && test -f "$1/migrations/migrations_test.go" && find "$1" -type f | wc -l' \
      _ "${remote_src}" 2>/dev/null || true)"
    file_count="${file_count//[[:space:]]/}"
    if [[ "${file_count}" =~ ^[0-9]+$ && "${file_count}" -gt 0 ]]; then
      if [[ "${file_count}" == "${previous_count}" ]]; then
        stable_checks=$((stable_checks + 1))
      else
        stable_checks=0
      fi
      if [[ "${stable_checks}" -ge 2 ]]; then
        return 0
      fi
      previous_count="${file_count}"
    fi
    sleep 1
  done
  echo "Multipass repository sync did not stabilize at ${remote_src}" >&2
  return 1
}

vm_ip() {
  local ip=""
  for _ in $(seq 1 60); do
    ip="$(multipass info "${NAKPANEL_MULTIPASS_VM}" 2>/dev/null | awk '/IPv4/{print $2; exit}' || true)"
    if [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf '%s\n' "${ip}"; return; fi
    sleep 2
  done
  echo "Multipass IPv4 did not become available for ${NAKPANEL_MULTIPASS_VM}" >&2
  return 1
}

csrf_token() {
  local cookie_file="$1"
  local session_token
  session_token="$(awk '$6 == "nakpanel_session" { value = $7 } END { print value }' "${cookie_file}")"
  if [[ -z "${session_token}" ]]; then
    echo "nakpanel_session is missing from ${cookie_file}" >&2
    return 1
  fi
  if command -v shasum >/dev/null 2>&1; then
    printf 'nakpanel-csrf-v1:%s' "${session_token}" | shasum -a 256 | awk '{print $1}'
  else
    printf 'nakpanel-csrf-v1:%s' "${session_token}" | sha256sum | awk '{print $1}'
  fi
}

destroy_owned_vm() {
  local name="$1" token="$2" manifest version arch recorded_token
  require_multipass
  validate_run_identity "${token}" || return 1
  assert_disposable_name "${name}" || return 1
  assert_distinct_vm_names "${NAKPANEL_MULTIPASS_SOURCE_VM:-${NAKPANEL_MULTIPASS_VM}}" "${NAKPANEL_MULTIPASS_DR_VM:-${NAKPANEL_MULTIPASS_VM}-dr}" || return 1
  manifest="${NAKPANEL_OWNERSHIP_DIR}/${token}/${name}"
  if ! multipass info "${name}" >/dev/null 2>&1; then return 0; fi
  [[ -f "${manifest}" ]] || { echo "refusing deletion of unowned VM: ${name}" >&2; return 1; }
  IFS=$'\t' read -r version arch recorded_token < "${manifest}"
  assert_vm_identity "${name}" "${version}" "${arch}" "${token}" || return 1
  multipass delete --purge "${name}" || return 1
  rm -f "${manifest}"
}

destroy_vm() {
  destroy_owned_vm "$1" "${NAKPANEL_RUN_TOKEN:-}"
}

# Deliberate maintenance only, never called by ordinary qualification. Every
# candidate must still have both ownership records for this run.
destroy_legacy_phase_vms() {
  [[ "${NAKPANEL_LEGACY_MAINTENANCE:-0}" == 1 ]] || { echo "legacy cleanup requires explicit maintenance mode" >&2; return 1; }
  local name
  for name in "${NAKPANEL_LEGACY_PHASE_VMS[@]}"; do
    destroy_owned_vm "${name}" "${NAKPANEL_RUN_TOKEN:-}" || return 1
  done
}

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/qualification-artifacts.sh"
configure_qualification_guest_paths
