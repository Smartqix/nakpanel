#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

echo "Preparing single Nakpanel deployment VM: ${VM_NAME} (${IMAGE}); default is nakpanel-lab"
require_nakpanel_vm_name "${NAKPANEL_MULTIPASS_VM}"
destroy_legacy_phase_vms
destroy_vm "${NAKPANEL_MULTIPASS_VM}"
ensure_vm 2 3G 16G

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase10-verify.sh"

VM_IP="$(vm_ip)"
if [[ -z "${VM_IP}" ]]; then
  echo "could not determine ${VM_NAME} IPv4 address" >&2
  exit 1
fi

echo "Single-VM deployment verification passed for ${VM_NAME} (${VM_IP})."
