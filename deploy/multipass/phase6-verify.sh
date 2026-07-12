#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase5-ui-verify.sh"

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

assert_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq -- "${needle}" "${file}"; then
    echo "${file} contains unexpected text: ${needle}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y bind9
sudo systemctl enable --now named.service
sudo install -d -m 0755 /usr/share/roundcube
if [[ ! -f /usr/share/roundcube/index.php ]]; then
  echo '<?php echo "nakpanel roundcube placeholder";' | sudo tee /usr/share/roundcube/index.php >/dev/null
fi
sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE kind IN ('create_backup', 'configure_webmail', 'configure_dns_zone', 'reconcile_system')
  AND (
    args->>'domain' IN ('phase5-ui.test', 'webmail.phase5-ui.test')
    OR args::text LIKE '%phase5-ui.test%'
  );
DELETE FROM restore_runs WHERE target_name = 'phase5-ui.test';
DELETE FROM backups WHERE target_name = 'phase5-ui.test';
DELETE FROM webmail_hosts WHERE hostname = 'webmail.phase5-ui.test';
DELETE FROM dns_zones WHERE domain = 'phase5-ui.test';
DELETE FROM reconciliation_runs;
DELETE FROM adminer_tokens;
SQL
sudo rm -f /etc/nginx/sites-enabled/webmail.phase5-ui.test.conf /etc/nginx/sites-available/webmail.phase5-ui.test.conf
sudo rm -f /etc/bind/nakpanel/zones/db.phase5-ui.test
sudo rm -rf /var/lib/nakpanel/backups
sudo systemctl reload bind9
sudo systemctl restart nakpanel-agent.service
sudo systemctl restart nakpanel.service
sudo systemctl is-active --quiet nakpanel-agent.service
sudo systemctl is-active --quiet nakpanel.service
REMOTE

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'
assert_contains "${tmpdir}/admin-dashboard.html" 'Operations'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/backups"'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/webmail"'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/dns"'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/reconcile"'
assert_contains "${tmpdir}/admin-dashboard.html" 'href="/db"'

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/db" > "${tmpdir}/adminer.html"
assert_contains "${tmpdir}/adminer.html" 'Adminer SSO'
assert_contains "${tmpdir}/adminer.html" 'Token'
assert_contains "${tmpdir}/adminer.html" 'Expires'

post_phase6_action() {
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
    echo "Phase 6 ${label} returned HTTP ${status}" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
}

post_phase6_action webmail webmail -d 'domain=phase5-ui.test'
post_phase6_action dns dns -d 'domain=phase5-ui.test' -d "address=${VM_IP}"
post_phase6_action backup backups -d 'domain=phase5-ui.test'
post_phase6_action reconcile reconcile -X POST

multipass exec "${VM_NAME}" -- bash -se "${VM_IP}" <<'REMOTE'
set -euo pipefail
vm_ip="$1"

wait_for_row() {
  local sql="$1"
  local label="$2"
  for _ in $(seq 1 90); do
    if sudo -u postgres psql -d nakpanel -tAc "${sql}" | grep -qx 'active'; then
      return 0
    fi
    sleep 1
  done
  sudo -u postgres psql -d nakpanel -c "SELECT id, kind, state, args, errors FROM river_job WHERE kind IN ('create_backup', 'configure_webmail', 'configure_dns_zone', 'reconcile_system') ORDER BY id DESC LIMIT 20" >&2
  sudo -u postgres psql -d nakpanel -c "SELECT id, target_name, status, archive_path, last_error FROM backups ORDER BY id DESC LIMIT 10" >&2
  sudo -u postgres psql -d nakpanel -c "SELECT id, hostname, status, config_path, last_error FROM webmail_hosts ORDER BY id DESC LIMIT 10" >&2
  sudo -u postgres psql -d nakpanel -c "SELECT id, domain, address, status, zone_path, last_error FROM dns_zones ORDER BY id DESC LIMIT 10" >&2
  sudo -u postgres psql -d nakpanel -c "SELECT id, status, sites_total, sites_ok, last_error FROM reconciliation_runs ORDER BY id DESC LIMIT 10" >&2
  sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
  echo "${label} did not become active" >&2
  exit 1
}

wait_for_row "SELECT status FROM webmail_hosts WHERE hostname = 'webmail.phase5-ui.test' ORDER BY id DESC LIMIT 1" "webmail"
wait_for_row "SELECT status FROM dns_zones WHERE domain = 'phase5-ui.test' ORDER BY id DESC LIMIT 1" "dns"
wait_for_row "SELECT status FROM backups WHERE target_name = 'phase5-ui.test' ORDER BY id DESC LIMIT 1" "backup"
wait_for_row "SELECT status FROM reconciliation_runs ORDER BY id DESC LIMIT 1" "reconciliation"

webmail_config="$(sudo -u postgres psql -d nakpanel -tAc "SELECT config_path FROM webmail_hosts WHERE hostname = 'webmail.phase5-ui.test' ORDER BY id DESC LIMIT 1" | tr -d '[:space:]')"
test -f "${webmail_config}"
grep -Fq 'server_name webmail.phase5-ui.test;' "${webmail_config}"
grep -Fq 'root /usr/share/roundcube;' "${webmail_config}"

zone_path="$(sudo -u postgres psql -d nakpanel -tAc "SELECT zone_path FROM dns_zones WHERE domain = 'phase5-ui.test' ORDER BY id DESC LIMIT 1" | tr -d '[:space:]')"
test -f "${zone_path}"
grep -Fq '$ORIGIN phase5-ui.test.' "${zone_path}"
grep -Fq "@ IN A ${vm_ip}" "${zone_path}"
grep -Fq "webmail IN A ${vm_ip}" "${zone_path}"

archive_path="$(sudo -u postgres psql -d nakpanel -tAc "SELECT archive_path FROM backups WHERE target_name = 'phase5-ui.test' ORDER BY id DESC LIMIT 1" | tr -d '[:space:]')"
sudo test -f "${archive_path}"
sudo tar -tzf "${archive_path}" | grep -Fx 'manifest.json'
sudo tar -tzf "${archive_path}" | grep -Fx 'files/index.php'
sudo tar -tzf "${archive_path}" | grep -Fx 'databases/np_phase5.sql'

sudo ss -ltnp | tee /tmp/nakpanel-phase6-ss.txt
grep -Eq 'LISTEN.+:7443\b.+nakpanel-panel' /tmp/nakpanel-phase6-ss.txt
if grep -Eq 'LISTEN.+:(80|443)\b.+nakpanel-panel' /tmp/nakpanel-phase6-ss.txt; then
  echo "nakpanel panel unexpectedly listens on :80 or :443" >&2
  exit 1
fi
REMOTE

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/?legacy=1" > "${tmpdir}/phase6-dashboard.html"
assert_contains "${tmpdir}/phase6-dashboard.html" 'phase5-ui.test'
assert_contains "${tmpdir}/phase6-dashboard.html" 'webmail.phase5-ui.test'
assert_contains "${tmpdir}/phase6-dashboard.html" 'db.phase5-ui.test'
assert_contains "${tmpdir}/phase6-dashboard.html" 'active'

plain_http_status="$(curl -s -o "${tmpdir}/plain-http.out" -w '%{http_code}' "http://${VM_IP}:7443/login" || true)"
if [[ "${plain_http_status}" == "200" ]] && grep -Fq 'nakpanel login' "${tmpdir}/plain-http.out"; then
  echo "plain HTTP exposed the panel login on :7443" >&2
  cat "${tmpdir}/plain-http.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- sudo systemctl stop nginx
curl -sk --fail "https://${VM_IP}:7443/login" > "${tmpdir}/nginx-stopped-login.html"
assert_contains "${tmpdir}/nginx-stopped-login.html" 'nakpanel login'

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_contains "${tmpdir}/client-dashboard.html" 'Client dashboard'
assert_not_contains "${tmpdir}/client-dashboard.html" 'Operations'
assert_not_contains "${tmpdir}/client-dashboard.html" 'action="/backups"'

echo "Phase 6 verification passed for backup, webmail, DNS, Adminer SSO, reconciliation, and direct :7443 recovery on https://${VM_IP}:7443"
