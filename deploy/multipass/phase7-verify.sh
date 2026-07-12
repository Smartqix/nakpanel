#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase6-verify.sh"

VM_IP="$(multipass info "${VM_NAME}" | awk '/IPv4/{print $2; exit}')"
if [[ -z "${VM_IP}" ]]; then
  echo "could not determine ${VM_NAME} IPv4 address" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "${needle}" "${file}"; then
    echo "${file} is missing expected text: ${needle}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

post_admin() {
  local label="$1"
  local endpoint="$2"
  shift 2
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" \
    "https://${VM_IP}:7443/${endpoint}")"
  if [[ "${status}" != "303" ]]; then
    echo "${label} returned HTTP ${status}" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
}

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/restores"'

csrf_status="$(curl -sk -o "${tmpdir}/csrf.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -H 'Origin: https://attacker.test' \
  -d 'domain=phase5-ui.test' \
  "https://${VM_IP}:7443/backups")"
if [[ "${csrf_status}" != "403" ]]; then
  echo "cross-site POST with Origin: https://attacker.test returned HTTP ${csrf_status}, want 403" >&2
  cat "${tmpdir}/csrf.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo install -o npui -g npui -m 0644 /dev/stdin /home/npui/public_html/index.php <<'PHP'
phase7 restored file
PHP
sudo mariadb np_phase5 <<'SQL'
DROP TABLE IF EXISTS phase7_restore_probe;
CREATE TABLE phase7_restore_probe (
  id INT PRIMARY KEY,
  value VARCHAR(64) NOT NULL
);
INSERT INTO phase7_restore_probe (id, value) VALUES (1, 'restored');
SQL
REMOTE

post_admin phase7-backup backups -d 'domain=phase5-ui.test'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM backups WHERE target_name = 'phase5-ui.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, target_name, status, archive_path, last_error FROM backups ORDER BY id DESC LIMIT 10" >&2
sudo -u postgres psql -d nakpanel -c "SELECT id, kind, state, args, errors FROM river_job WHERE kind IN ('create_backup', 'restore_backup') ORDER BY id DESC LIMIT 20" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
echo "phase7 backup did not become active" >&2
exit 1
REMOTE

backup_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM backups WHERE target_name = 'phase5-ui.test' AND status = 'active' ORDER BY id DESC LIMIT 1" | tr -d '[:space:]')"
if [[ -z "${backup_id}" ]]; then
  echo "could not find active phase7 backup id" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo install -o npui -g npui -m 0644 /dev/stdin /home/npui/public_html/index.php <<'PHP'
phase7 mutated file
PHP
sudo mariadb np_phase5 -e "UPDATE phase7_restore_probe SET value = 'mutated' WHERE id = 1;"
grep -Fxq 'phase7 mutated file' /home/npui/public_html/index.php
sudo mariadb -NBe "SELECT value FROM np_phase5.phase7_restore_probe WHERE id = 1" | grep -qx 'mutated'
REMOTE

post_admin phase7-restore restores -d "backup_id=${backup_id}"

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM restore_runs WHERE target_name = 'phase5-ui.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, backup_id, target_name, status, restored_at, last_error FROM restore_runs ORDER BY id DESC LIMIT 10" >&2
sudo -u postgres psql -d nakpanel -c "SELECT id, kind, state, args, errors FROM river_job WHERE kind = 'restore_backup' ORDER BY id DESC LIMIT 20" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
echo "restore_runs did not become active" >&2
exit 1
REMOTE

multipass exec "${VM_NAME}" -- bash -se "${VM_IP}" <<'REMOTE'
set -euo pipefail
vm_ip="$1"
grep -Fxq 'phase7 restored file' /home/npui/public_html/index.php
sudo mariadb -NBe "SELECT value FROM np_phase5.phase7_restore_probe WHERE id = 1" | grep -qx 'restored'

zone_path="/etc/bind/nakpanel/zones/db.phase5-ui.test"
include_path="/etc/bind/nakpanel/zones.d/phase5-ui.test.conf"
aggregate_path="/etc/bind/nakpanel/named.conf"
test -f "${zone_path}"
test -f "${include_path}"
test -f "${aggregate_path}"
grep -Fq "zone \"phase5-ui.test\"" "${include_path}"
grep -Fq "file \"${zone_path}\"" "${include_path}"
grep -Fq "include \"${include_path}\";" "${aggregate_path}"
named-checkzone phase5-ui.test "${zone_path}"
named-checkconf "${aggregate_path}"
grep -Fq "@ IN A ${vm_ip}" "${zone_path}"
sudo systemctl is-active --quiet named.service
sudo systemctl is-active --quiet nakpanel-agent.service
sudo systemctl is-active --quiet nakpanel.service
REMOTE

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/?legacy=1" > "${tmpdir}/phase7-dashboard.html"
assert_contains "${tmpdir}/phase7-dashboard.html" 'phase5-ui.test'

echo "phase7 verification passed for restore, DNS validation includes, CSRF origin rejection, and integrated Phase 6 flow on https://${VM_IP}:7443"
