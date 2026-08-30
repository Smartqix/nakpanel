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
# A crashed Phase 29 disaster-recovery leg must not leak its second VM.
destroy_vm "${NAKPANEL_MULTIPASS_VM}-dr"
ensure_vm 2 3G 16G

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
# Phase 28 preserves the server-security, Tools & Settings, hosting toolkit,
# and domain workspace chain while verifying operational OCI deployments.
"${ROOT_DIR}/deploy/multipass/phase28-verify.sh"
# Run the adversarial boundary suite against the same fully provisioned VM.
NAKPANEL_SKIP_PRIOR_PHASES=1 "${ROOT_DIR}/deploy/multipass/security-verify.sh"
# Phase 29 runs last: its upgrade, reboot, and disaster-recovery legs mutate
# the VM the earlier suites already validated.
NAKPANEL_SKIP_PRIOR_PHASES=1 "${ROOT_DIR}/deploy/multipass/phase29-verify.sh"
# Phase 30 is the final gate. It installs the current worktree over the
# synthetic Phase 29 upgrade version, then proves Classic WordPress and native
# managed PHP on the same server without rebuilding the VM.
NAKPANEL_SKIP_PRIOR_PHASES=1 "${ROOT_DIR}/deploy/multipass/phase30-verify.sh"

VM_IP="$(vm_ip)"
if [[ -z "${VM_IP}" ]]; then
  echo "could not determine ${VM_NAME} IPv4 address" >&2
  exit 1
fi

echo "Single-VM deployment verification passed for ${VM_NAME} (${VM_IP})."
