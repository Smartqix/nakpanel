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
)

require_multipass() {
  if ! command -v multipass >/dev/null 2>&1; then
    echo "multipass is required" >&2
    exit 1
  fi
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
    if multipass exec "${name}" -- cloud-init status 2>/dev/null | grep -q 'status: done'; then
      cloud_init_done=1
      break
    fi
    sleep 2
  done

  if [[ "${cloud_init_done}" != "1" ]]; then
    multipass exec "${name}" -- cloud-init status --long || true
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
  multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo rm -rf "${remote_src}"
  multipass transfer -r "${root_dir}" "${NAKPANEL_MULTIPASS_VM}:${remote_src}"
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
