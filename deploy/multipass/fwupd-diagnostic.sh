#!/usr/bin/env bash
# Bounded reproduction without installing Nakpanel or touching persistent hosts.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || exit 1
: "${RUNNER_TEMP:?}" "${RESOLUTE_SERIAL:?}" "${RESOLUTE_SHA256:?}"
[[ "${RESOLUTE_SERIAL}" =~ ^20[0-9]{6}(\.[0-9]+)?$ && "${RESOLUTE_SHA256}" =~ ^[a-f0-9]{64}$ ]] || exit 1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
evidence="${RUNNER_TEMP}/fwupd-diagnostic"
mkdir -p "${evidence}"
base="https://cloud-images.ubuntu.com/releases/resolute/release-${RESOLUTE_SERIAL}"
for name in SHA256SUMS SHA256SUMS.gpg; do
  curl --fail --location --retry 3 --proto '=https' --proto-redir '=https' "${base}/${name}" -o "${evidence}/${name}"
done
gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg "${evidence}/SHA256SUMS.gpg" "${evidence}/SHA256SUMS"
python3 - "${evidence}/SHA256SUMS" "${RESOLUTE_SHA256}" <<'PY'
from pathlib import Path
import sys
rows=[row.split()[0] for row in Path(sys.argv[1]).read_text().splitlines() if row.split()[-1].lstrip('*')=='ubuntu-26.04-server-cloudimg-amd64.img']
assert rows==[sys.argv[2]], 'image pin differs from signed Ubuntu sums'
PY
export NAKPANEL_MULTIPASS_IMAGE_SOURCE="${RUNNER_TEMP}/fwupd-resolute.img"
export NAKPANEL_MULTIPASS_IMAGE_SHA256="${RESOLUTE_SHA256}"
curl --fail --location --retry 3 --proto '=https' --proto-redir '=https' "${base}/ubuntu-26.04-server-cloudimg-amd64.img" -o "${NAKPANEL_MULTIPASS_IMAGE_SOURCE}"
export NAKPANEL_RUN_TOKEN="fwupd-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
export NAKPANEL_MULTIPASS_IMAGE=26.04 NAKPANEL_MULTIPASS_ARCH=amd64
export NAKPANEL_OWNERSHIP_DIR="${RUNNER_TEMP}/fwupd-owned"
source "${SCRIPT_DIR}/common.sh"
init_qualification_run
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -f "${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}/${NAKPANEL_MULTIPASS_VM}" ]]; then
    destroy_owned_vm "${NAKPANEL_MULTIPASS_VM}" "${NAKPANEL_RUN_TOKEN}" >"${evidence}/cleanup.log" 2>&1 || status=1
  fi
  exit "${status}"
}
trap cleanup EXIT
ensure_vm 2 2G 12G
assert_current_vm_identity
multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo timeout --kill-after=5s 600s bash -se <<'GUEST' | tee "${evidence}/fwupd.log"
set -euo pipefail
cat /etc/os-release
systemd-detect-virt
if ! dpkg-query -W -f='${Status}' fwupd 2>/dev/null | grep -qx 'install ok installed'; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y fwupd
fi
dpkg-query -W -f='${Package} ${Version} ${Status}\n' fwupd libfwupd3
systemctl cat fwupd-refresh.service
systemctl show fwupd-refresh.service -p User -p DynamicUser -p ExecStart -p StandardError -p Result -p ExecMainStatus
# Upstream discards stderr. Change only its destination so authentication or
# network errors survive; keep ExecStart, user, sandbox and success codes intact.
mkdir -p /run/systemd/system/fwupd-refresh.service.d
printf '[Service]\nStandardError=journal\n' >/run/systemd/system/fwupd-refresh.service.d/diagnostic.conf
systemctl daemon-reload
set +e
systemctl start fwupd-refresh.service
service_status=$?
systemctl status fwupd-refresh.service --no-pager -l
journalctl -b -u fwupd-refresh.service -u fwupd.service --no-pager -n 100
timeout 90 /usr/bin/fwupdmgr refresh
root_status=$?
printf 'DIAGNOSTIC_SERVICE_EXIT=%s\nDIAGNOSTIC_ROOT_EXIT=%s\n' "$service_status" "$root_status"
GUEST
