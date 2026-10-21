#!/usr/bin/env bash
# Package-only reproduction on one disposable guest; never product acceptance.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || {
  echo 'PHP diagnostic requires a disposable Actions runner' >&2; exit 1;
}
: "${RUNNER_TEMP:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
evidence="${RUNNER_TEMP}/php-maintenance-diagnostic"
mkdir "${evidence}"
base=https://cloud-images.ubuntu.com/releases/resolute/release-20260927
pin=8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2
for name in SHA256SUMS SHA256SUMS.gpg; do
  curl --fail --location --retry 3 --proto '=https' --proto-redir '=https' "${base}/${name}" -o "${evidence}/${name}"
done
gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg "${evidence}/SHA256SUMS.gpg" "${evidence}/SHA256SUMS"
python3 - "${evidence}/SHA256SUMS" "${pin}" <<'PY'
from pathlib import Path
import sys
rows=[r.split()[0] for r in Path(sys.argv[1]).read_text().splitlines() if r.split()[-1].lstrip('*')=='ubuntu-26.04-server-cloudimg-amd64.img']
assert rows==[sys.argv[2]], 'image pin differs from signed Ubuntu sums'
PY
export NAKPANEL_MULTIPASS_IMAGE_SOURCE="${RUNNER_TEMP}/php-diagnostic-resolute.img"
export NAKPANEL_MULTIPASS_IMAGE_SHA256="${pin}"
curl --fail --location --retry 3 --proto '=https' --proto-redir '=https' "${base}/ubuntu-26.04-server-cloudimg-amd64.img" -o "${NAKPANEL_MULTIPASS_IMAGE_SOURCE}"
export NAKPANEL_RUN_TOKEN="php-diag-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
export NAKPANEL_MULTIPASS_IMAGE=26.04 NAKPANEL_MULTIPASS_ARCH=amd64
export NAKPANEL_OWNERSHIP_DIR="${RUNNER_TEMP}/php-diagnostic-owned"
source "${SCRIPT_DIR}/common.sh"
init_qualification_run
cleanup() {
  local status=$? cleanup_status=0 owned=false
  trap - EXIT
  if [[ -f "${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}/${NAKPANEL_MULTIPASS_VM}" ]]; then
    owned=true
    destroy_owned_vm "${NAKPANEL_MULTIPASS_VM}" "${NAKPANEL_RUN_TOKEN}" >"${evidence}/cleanup.log" 2>&1 || cleanup_status=$?
  fi
  printf '{"ownership_record_present":%s,"exit_code":%s}\n' "${owned}" "${cleanup_status}" >"${evidence}/cleanup.json"
  (( cleanup_status == 0 )) || status=1
  exit "${status}"
}
trap cleanup EXIT
ensure_vm 2 3G 12G
assert_current_vm_identity
archive="${evidence}/source.tar"
tar -C "${ROOT_DIR}" -cf "${archive}" deploy/multipass/php-maintenance-diagnostic.py deploy/multipass/sury-maintenance-drill.py deploy/install/platform.sh deploy/install/sury.sh deploy/install/sury_verify.py deploy/install/sury-php-archive-keyring.gpg
read -r sha size <<<"$(qualification_archive_identity "${archive}")"
remote_archive="/tmp/nakpanel-php-diagnostic-${NAKPANEL_RUN_TOKEN}.tar"
multipass transfer "${archive}" "${NAKPANEL_MULTIPASS_VM}:${remote_archive}"
multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo python3 - source --token "${NAKPANEL_RUN_TOKEN}" --archive "${remote_archive}" --archive-sha "${sha}" --archive-size "${size}" <"${SCRIPT_DIR}/qualification_artifacts.py"
multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo timeout --kill-after=5s 1200s bash -se -- "${NAKPANEL_RUN_TOKEN}" <<'GUEST' | tee "${evidence}/packages.log"
set -euo pipefail
[[ "$(cat /etc/nakpanel-qualification-owner)" == "$1" ]]
[[ "$(systemd-detect-virt --vm)" == kvm ]]
src="/var/lib/nakpanel-qualification/$1/source"
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 libfcgi-bin
bash "${src}/deploy/install/sury.sh" prepare ubuntu-26.04-sury
apt-get update
source "${src}/deploy/install/platform.sh"
nakpanel_load_platform
mapfile -t packages < <(nakpanel_php_packages)
apt-get install -y --no-install-recommends "${packages[@]}" php8.5-pgsql
python3 "${src}/deploy/multipass/php-maintenance-diagnostic.py" "$1"
GUEST
