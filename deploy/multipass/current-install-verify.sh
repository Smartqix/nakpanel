#!/usr/bin/env bash
# Bootstrap the current stack, not historical UI/token contracts.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
require_nakpanel_vm_name "${VM_NAME}"
ensure_vm 4 6G 48G
sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${NAKPANEL_REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
cd "$1"
if ! id nakpanel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi
chown -R nakpanel:nakpanel "$1"
timeout 45m deploy/install/install.sh --yes --allow-downgrade --force
systemctl is-active --quiet nakpanel nakpanel-agent nginx postgresql mariadb named stalwart-mail
/usr/local/bin/panelctl version
nginx -t
named-checkconf
sshd -t
REMOTE
VM_IP="$(vm_ip)"
test -n "${VM_IP}"
curl -skf --connect-timeout 5 --max-time 30 "https://${VM_IP}:7443/healthz" >/dev/null
echo "Current installation verified on ${VM_NAME} (${VM_IP})."
