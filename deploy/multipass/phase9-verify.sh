#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase8-verify.sh"

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
    "$@" \
    "https://${VM_IP}:7443/${endpoint}")"
  if [[ "${status}" != "303" ]]; then
    echo "${label} returned HTTP ${status}" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
}

post_expect_400() {
  local label="$1"
  local endpoint="$2"
  local needle="$3"
  shift 3
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
    "$@" \
    "https://${VM_IP}:7443/${endpoint}")"
  if [[ "${status}" != "400" ]]; then
    echo "${label} returned HTTP ${status}, want 400" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
  assert_contains "${tmpdir}/${label}.out" "${needle}"
}

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'
assert_contains "${tmpdir}/admin-dashboard.html" 'Plans & subscriptions'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/plans"'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/subscriptions"'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/settings/oversell"'
assert_contains "${tmpdir}/admin-dashboard.html" '/assets/app.js'
assert_contains "${tmpdir}/admin-dashboard.html" 'np-layout'
assert_contains "${tmpdir}/admin-dashboard.html" 'data-np-view="subscriptions"'
assert_contains "${tmpdir}/admin-dashboard.html" 'create-site-modal'

curl -sk --fail "https://${VM_IP}:7443/assets/app.js" > "${tmpdir}/app.js"
assert_contains "${tmpdir}/app.js" 'X-Nakpanel-SPA'

phase9_state="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "
SELECT
  (SELECT COUNT(*) FROM plans WHERE name IN ('Starter', 'Business', 'Pro', 'Legacy Unlimited')),
  (SELECT COUNT(*) FROM subscriptions WHERE status = 'active'),
  (SELECT COUNT(*) FROM sites WHERE subscription_id IS NOT NULL),
  (SELECT COUNT(*) FROM databases WHERE subscription_id IS NOT NULL),
  (SELECT COUNT(*) FROM backups WHERE subscription_id IS NOT NULL)
")"
IFS='|' read -r seeded_plans active_subscriptions linked_sites linked_databases linked_backups <<<"${phase9_state}"
if [[ "${seeded_plans}" != "4" || "${active_subscriptions}" -lt 2 ]]; then
  echo "phase9 seed/backfill check failed: ${phase9_state}" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE args::text LIKE '%phase9-client.test%'
   OR args::text LIKE '%phase9-over.test%'
   OR args::text LIKE '%np_phase9%';
DELETE FROM backups WHERE target_name IN ('phase9-client.test', 'phase9-over.test');
DELETE FROM databases WHERE db_name LIKE 'np_phase9%';
DELETE FROM sites WHERE domain IN ('phase9-client.test', 'phase9-over.test');
DELETE FROM subscriptions WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase9-client@nakpanel.test');
DELETE FROM subscriptions WHERE customer_user_id IN (SELECT id FROM users WHERE email = 'phase9-client@nakpanel.test');
DELETE FROM customers WHERE email = 'phase9-client@nakpanel.test';
DELETE FROM users WHERE email = 'phase9-client@nakpanel.test';
DELETE FROM plans WHERE name IN ('Phase9 Tiny', 'Phase9 Huge');
INSERT INTO users (email, password_hash, role)
VALUES ('phase9-client@nakpanel.test', '$argon2id$v=19$m=65536,t=3,p=1$CtuDwkxvRQbtZgjhC3Jkog$JAqH/qKCmBZdQmLhykEgWmDnYOlHZxAG5vzSf4FViyQ', 'client');
SQL
sudo rm -f /etc/nginx/sites-enabled/phase9-client.test.conf /etc/nginx/sites-available/phase9-client.test.conf
sudo rm -f /etc/php/8.3/fpm/pool.d/nakpanel-npq9a-phase9-client-test.conf
sudo userdel -r npq9a >/dev/null 2>&1 || true
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

phase9_user_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM users WHERE email = 'phase9-client@nakpanel.test'" | tr -d '[:space:]')"
client_user_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM users WHERE email = 'client@nakpanel.test'" | tr -d '[:space:]')"
starter_plan_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM plans WHERE name = 'Starter'" | tr -d '[:space:]')"
if [[ -z "${phase9_user_id}" || -z "${client_user_id}" || -z "${starter_plan_id}" ]]; then
  echo "could not resolve phase9/client/starter ids" >&2
  exit 1
fi

post_expect_400 phase9-unsubscribed sites 'no active subscription' \
  -d "owner_user_id=${phase9_user_id}" \
  -d 'username=npq9a' \
  -d 'domain=phase9-client.test' \
  -d 'php_version=8.3'

post_admin phase9-plan plans \
  -d 'name=Phase9 Tiny' \
  -d 'description=Phase 9 finite test plan' \
  -d 'disk_mb=2' \
  -d 'max_sites=1' \
  -d 'max_databases=1' \
  -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' \
  -d 'backup_retention_days=7' \
  -d 'php_allowlist=8.3,8.2' \
  -d 'php_max_children=2' \
  -d 'php_memory_mb=64' \
  -d 'site_disk_quota_mb=1' \
  -d 'max_backups=1' \
  -d 'backup_storage_mb=128' \
  -d 'allow_dns=true' \
  -d 'is_active=true'
tiny_plan_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM plans WHERE name = 'Phase9 Tiny'" | tr -d '[:space:]')"
if [[ -z "${tiny_plan_id}" ]]; then
  echo "could not resolve Phase9 Tiny plan id" >&2
  exit 1
fi

post_admin phase9-subscription subscriptions \
  -d "customer_user_id=${phase9_user_id}" \
  -d "plan_id=${tiny_plan_id}"

post_admin phase9-client-subscription subscriptions \
  -d "customer_user_id=${client_user_id}" \
  -d "plan_id=${starter_plan_id}"

post_admin phase9-site sites \
  -d "owner_user_id=${phase9_user_id}" \
  -d 'username=npq9a' \
  -d 'domain=phase9-client.test' \
  -d 'php_version=8.3'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM sites WHERE domain = 'phase9-client.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    break
  fi
  sleep 1
done
if ! sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM sites WHERE domain = 'phase9-client.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
  sudo -u postgres psql -d nakpanel -c "SELECT id, domain, status, last_error FROM sites ORDER BY id DESC LIMIT 10" >&2
  sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
  echo "phase9 site did not become active" >&2
  exit 1
fi
pool="/etc/php/8.3/fpm/pool.d/nakpanel-npq9a-phase9-client-test.conf"
test -f "${pool}"
grep -Fq 'pm.max_children = 2' "${pool}"
grep -Fq 'php_admin_value[memory_limit] = 64M' "${pool}"
quota_target="$(findmnt -n -o TARGET --target /home/npq9a)"
sudo quota -u npq9a | tee /tmp/nakpanel-phase9-quota.txt
grep -Eq '(^|[[:space:]])1024([[:space:]]|$)' /tmp/nakpanel-phase9-quota.txt
if sudo -u npq9a dd if=/dev/zero of=/home/npq9a/public_html/too-big.bin bs=1M count=3 status=none; then
  echo "over-quota write succeeded for npq9a" >&2
  exit 1
fi
sudo rm -f /home/npq9a/public_html/too-big.bin
REMOTE

owner_check="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT owner_user_id = ${phase9_user_id}, subscription_id IS NOT NULL FROM sites WHERE domain = 'phase9-client.test'" | tr -d '[:space:]')"
if [[ "${owner_check}" != "t|t" ]]; then
  echo "site owner/subscription check failed: ${owner_check}" >&2
  exit 1
fi

post_admin phase9-db databases \
  -d "owner_user_id=${phase9_user_id}" \
  -d 'engine=mariadb' \
  -d 'db_name=np_phase9' \
  -d 'db_user=np_phase9_user'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM databases WHERE db_name = 'np_phase9' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, db_name, status, last_error FROM databases ORDER BY id DESC LIMIT 10" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
echo "phase9 database did not become active" >&2
exit 1
REMOTE

post_admin phase9-backup backups \
  -d "owner_user_id=${phase9_user_id}" \
  -d 'domain=phase9-client.test'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM backups WHERE target_name = 'phase9-client.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, target_name, status, archive_path, last_error FROM backups ORDER BY id DESC LIMIT 10" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
echo "phase9 backup did not become active" >&2
exit 1
REMOTE

post_expect_400 phase9-site-over sites 'quota exceeded' \
  -d "owner_user_id=${phase9_user_id}" \
  -d 'username=npq9b' \
  -d 'domain=phase9-over.test' \
  -d 'php_version=8.3'
post_expect_400 phase9-db-over databases 'quota exceeded' \
  -d "owner_user_id=${phase9_user_id}" \
  -d 'engine=mariadb' \
  -d 'db_name=np_phase9_over' \
  -d 'db_user=np_phase9_over_user'
post_expect_400 phase9-backup-over backups 'quota exceeded' \
  -d "owner_user_id=${phase9_user_id}" \
  -d 'domain=phase9-client.test'

post_admin phase9-huge-plan plans \
  -d 'name=Phase9 Huge' \
  -d 'description=Phase 9 oversell plan' \
  -d 'disk_mb=999999' \
  -d 'max_sites=-1' \
  -d 'max_databases=-1' \
  -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' \
  -d 'backup_retention_days=30' \
  -d 'php_allowlist=8.3,8.2' \
  -d 'php_max_children=-1' \
  -d 'php_memory_mb=-1' \
  -d 'site_disk_quota_mb=-1' \
  -d 'max_backups=-1' \
  -d 'backup_storage_mb=-1' \
  -d 'allow_ssh=true' \
  -d 'allow_dns=true' \
  -d 'is_active=true'
huge_plan_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM plans WHERE name = 'Phase9 Huge'" | tr -d '[:space:]')"
post_admin phase9-warn-settings settings/oversell \
  -d 'oversell_policy=warn' \
  -d 'server_disk_capacity_mb=1'
post_admin phase9-warn-subscription subscriptions \
  -d "customer_user_id=${phase9_user_id}" \
  -d "plan_id=${huge_plan_id}"

post_admin phase9-reset-subscription subscriptions \
  -d "customer_user_id=${phase9_user_id}" \
  -d "plan_id=${tiny_plan_id}"
post_admin phase9-cap-settings settings/oversell \
  -d 'oversell_policy=cap' \
  -d 'server_disk_capacity_mb=200000'
post_expect_400 phase9-cap-block subscriptions 'oversell cap exceeded' \
  -d "customer_user_id=${phase9_user_id}" \
  -d "plan_id=${huge_plan_id}"

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
if ! id nppeer9 >/dev/null 2>&1; then
  sudo useradd -M -G nakpanel nppeer9
fi
if sudo -u nppeer9 python3 - <<'PY'
import json
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect('/run/nakpanel/agent.sock')
except OSError:
    sys.exit(0)
try:
    sock.sendall(b'{"op":"ping","id":"01JPHASE900000000000000001","data":{}}\n')
    data = sock.recv(4096).decode('utf-8', 'replace')
except OSError:
    sys.exit(0)
sock.close()
try:
    response = json.loads(data)
except Exception:
    sys.exit(0)
sys.exit(1 if response.get("ok") is True else 0)
PY
then
  :
else
  echo "non-panel peer successfully used agent socket" >&2
  exit 1
fi
sudo systemctl is-active --quiet nakpanel-agent.service
sudo systemctl is-active --quiet nakpanel.service
REMOTE

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/" > "${tmpdir}/phase9-dashboard.html"
assert_contains "${tmpdir}/phase9-dashboard.html" 'Plans & subscriptions'
assert_contains "${tmpdir}/phase9-dashboard.html" 'Phase9 Tiny'
assert_contains "${tmpdir}/phase9-dashboard.html" 'phase9-client.test'

echo "phase9 verification passed for plans, subscriptions, entitlement gate, oversell policy, resource ownership, PHP/disk limits, and agent peer credential rejection on https://${VM_IP}:7443"
