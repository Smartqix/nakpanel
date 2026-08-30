#!/usr/bin/env bash

NAKPANEL_MULTIPASS_VM="${NAKPANEL_MULTIPASS_VM:-nakpanel-lab}"
NAKPANEL_MULTIPASS_IMAGE="${NAKPANEL_MULTIPASS_IMAGE:-24.04}"
NAKPANEL_REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"

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
)

require_multipass() {
  if ! command -v multipass >/dev/null 2>&1; then
    echo "multipass is required" >&2
    exit 1
  fi
}

# Multipass 1.16 on macOS can leave its client process spinning after a short
# remote command has already exited. Buffer output until the client exits so
# downstream grep cannot close the pipe early, and retry only watchdog hangs.
multipass_exec_short() {
  local budget="${NAKPANEL_MULTIPASS_SHORT_TIMEOUT:-30}"
  local attempt pid waited output_dir exit_status
  for attempt in 1 2 3; do
    output_dir="$(mktemp -d "${TMPDIR:-/tmp}/nakpanel-mp.XXXXXX")"
    multipass exec "$@" >"${output_dir}/stdout" 2>"${output_dir}/stderr" &
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
      rm -rf "${output_dir}"
      echo "multipass exec watchdog fired (attempt ${attempt}): $*" >&2
      continue
    fi
    if wait "${pid}"; then
      exit_status=0
    else
      exit_status=$?
    fi
    cat "${output_dir}/stdout" || true
    cat "${output_dir}/stderr" >&2 || true
    rm -rf "${output_dir}"
    return "${exit_status}"
  done
  echo "multipass exec kept hanging: $*" >&2
  return 124
}

require_nakpanel_vm_name() {
  local name="$1"
  if [[ ! "${name}" == nakpanel-* ]]; then
    echo "refusing to delete non-Nakpanel Multipass VM: ${name}" >&2
    echo "choose a VM name beginning with nakpanel- or run manual cleanup yourself" >&2
    exit 1
  fi
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

ensure_vm() {
  local cpus="${1:-2}"
  local memory="${2:-3G}"
  local disk="${3:-16G}"
  require_multipass
  if ! multipass info "${NAKPANEL_MULTIPASS_VM}" >/dev/null 2>&1; then
    multipass launch "${NAKPANEL_MULTIPASS_IMAGE}" --name "${NAKPANEL_MULTIPASS_VM}" --cpus "${cpus}" --memory "${memory}" --disk "${disk}"
  fi
  wait_for_cloud_init "${NAKPANEL_MULTIPASS_VM}"
}

sync_repo() {
  local root_dir="$1"
  local remote_src="${2:-${NAKPANEL_REMOTE_SRC}}"
  if [[ ! "${remote_src}" =~ ^/tmp/nakpanel-[A-Za-z0-9._-]+$ ]]; then
    echo "refusing unsafe Multipass sync destination: ${remote_src}" >&2
    echo "NAKPANEL_REMOTE_SRC must be a direct child of /tmp named nakpanel-*" >&2
    return 1
  fi
  multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo rm -rf "${remote_src}"
  multipass transfer -r "${root_dir}" "${NAKPANEL_MULTIPASS_VM}:${remote_src}"
  wait_for_repo_sync "${remote_src}"
}

# Multipass 1.16 on macOS can return from a recursive transfer while the daemon
# is still materializing the final files. Require the build inputs to exist and
# the remote file count to be stable before a verifier enters the source tree.
wait_for_repo_sync() {
  local remote_src="$1"
  local previous_count="" stable_checks=0 file_count=""
  for _ in $(seq 1 60); do
    file_count="$(multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- bash -c \
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
  multipass info "${NAKPANEL_MULTIPASS_VM}" | awk '/IPv4/{print $2; exit}'
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

destroy_vm() {
  local name="$1"
  require_multipass
  if multipass info "${name}" >/dev/null 2>&1; then
    multipass delete --purge "${name}"
  fi
}

destroy_legacy_phase_vms() {
  local name
  for name in "${NAKPANEL_LEGACY_PHASE_VMS[@]}"; do
    if [[ "${name}" == "${NAKPANEL_MULTIPASS_VM}" ]]; then
      continue
    fi
    destroy_vm "${name}"
  done
}
