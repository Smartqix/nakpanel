#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase10-verify.sh"

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

assert_contains() {
  local file="$1" needle="$2"
  if ! grep -Fq -- "${needle}" "${file}"; then
    echo "${file} is missing expected text: ${needle}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

post_admin() {
  local label="$1" endpoint="$2"
  shift 2
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" "$@" "https://${VM_IP}:7443/${endpoint}")"
  if [[ "${status}" != "303" ]]; then
    echo "${label} returned HTTP ${status}" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
}

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/dashboard.html"
for marker in 'np-routed-layout' 'Customers' 'Service Plans' 'data-np-search-input' 'name="nakpanel-csrf"'; do
  assert_contains "${tmpdir}/dashboard.html" "${marker}"
done
if ! grep -Eq 'Websites &amp; Domains|>Domains<' "${tmpdir}/dashboard.html"; then
  echo "administrator dashboard is missing the domains navigation item" >&2
  cat "${tmpdir}/dashboard.html" >&2
  exit 1
fi

for route in sites databases backups dns certificates activity customers subscriptions subscriptions/new service-plans tools-settings; do
  curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/${route}" > "${tmpdir}/route-${route//\//-}.html"
  assert_contains "${tmpdir}/route-${route//\//-}.html" 'np-routed-layout'
done
assert_contains "${tmpdir}/route-subscriptions-new.html" 'data-np-onboarding'
assert_contains "${tmpdir}/route-tools-settings.html" 'Overselling policy'

# The shared deployment VM can run this verifier repeatedly while debugging a
# later phase, so remove only Phase 11's own fixtures before recreating them.
multipass exec "${VM_NAME}" -- sudo -u postgres psql -v ON_ERROR_STOP=1 -d nakpanel <<'SQL'
DELETE FROM audit_events
WHERE (target_type = 'site' AND target_id IN (SELECT id FROM sites WHERE domain = 'phase11-client.test'))
   OR (target_type = 'subscription' AND target_id IN (SELECT id FROM subscriptions WHERE name = 'Phase11 Client Workspace'))
   OR (target_type = 'plan' AND target_id IN (SELECT id FROM plans WHERE name = 'Phase11 Self Service'));
DELETE FROM river_job WHERE args::text LIKE '%phase11%' OR args::text LIKE '%np11client%';
DELETE FROM restore_runs WHERE backup_id IN (SELECT id FROM backups WHERE site_id IN (SELECT id FROM sites WHERE domain = 'phase11-client.test'));
DELETE FROM backups WHERE site_id IN (SELECT id FROM sites WHERE domain = 'phase11-client.test');
DELETE FROM sites WHERE domain = 'phase11-client.test';
DELETE FROM subscriptions WHERE name = 'Phase11 Client Workspace';
DELETE FROM plans WHERE name = 'Phase11 Self Service';
SQL
multipass exec "${VM_NAME}" -- bash -c '
  sudo rm -f /etc/nginx/sites-enabled/phase11-client.test.conf /etc/nginx/sites-available/phase11-client.test.conf
  sudo rm -f /etc/php/8.3/fpm/pool.d/nakpanel-np11client-phase11-client-test.conf /etc/php/8.3/fpm/pool.d/nakpanel-np11client-phase11-client-test.conf.suspended
  sudo systemctl reload nginx php8.3-fpm >/dev/null 2>&1 || true
  id -u np11client >/dev/null 2>&1 && sudo userdel -r np11client >/dev/null 2>&1 || true
'

post_admin phase11-plan plans \
  -d 'name=Phase11 Self Service' -d 'description=Phase 11 client ownership verification' \
  -d 'disk_mb=128' -d 'max_sites=2' -d 'max_databases=2' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=7' -d 'php_allowlist=8.3' \
  -d 'php_max_children=2' -d 'php_memory_mb=128' -d 'site_disk_quota_mb=64' \
  -d 'max_backups=2' -d 'backup_storage_mb=128' -d 'allow_dns=true' -d 'is_active=true'

customer_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM customers WHERE email='phase10-customer@nakpanel.test'" | tr -d '[:space:]')"
plan_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM plans WHERE name='Phase11 Self Service'" | tr -d '[:space:]')"
post_admin phase11-subscription subscriptions \
  -d 'customer_mode=existing' -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" \
  -d 'subscription_name=Phase11 Client Workspace'
subscription_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND plan_id=${plan_id} ORDER BY id DESC LIMIT 1" | tr -d '[:space:]')"

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=phase10-customer@nakpanel.test' -d 'password=NakpanelPhase10!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_contains "${tmpdir}/client-dashboard.html" 'All subscriptions'
assert_contains "${tmpdir}/client-dashboard.html" 'Phase11 Client Workspace'
if grep -Fq 'Tools &amp; Settings' "${tmpdir}/client-dashboard.html"; then
  echo "client workspace exposed administrator navigation" >&2
  exit 1
fi

client_create_status="$(curl -sk -o "${tmpdir}/client-create.out" -w '%{http_code}' -b "${tmpdir}/client.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/client.cookies")" \
  -d "subscription_id=${subscription_id}" -d 'username=np11client' -d 'domain=phase11-client.test' -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${client_create_status}" != "303" ]]; then
  echo "client site creation returned HTTP ${client_create_status}" >&2
  cat "${tmpdir}/client-create.out" >&2
  exit 1
fi

site_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM sites WHERE domain='phase11-client.test' AND customer_id=${customer_id} AND subscription_id=${subscription_id}" | tr -d '[:space:]')"
curl -sk --fail -b "${tmpdir}/client.cookies" "https://${VM_IP}:7443/sites/${site_id}" > "${tmpdir}/client-site.html"
assert_contains "${tmpdir}/client-site.html" 'phase11-client.test'

foreign_site_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM sites WHERE customer_id<>${customer_id} ORDER BY id LIMIT 1" | tr -d '[:space:]')"
if [[ -n "${foreign_site_id}" ]]; then
  foreign_status="$(curl -sk -o /dev/null -w '%{http_code}' -b "${tmpdir}/client.cookies" "https://${VM_IP}:7443/sites/${foreign_site_id}")"
  [[ "${foreign_status}" == "404" ]] || { echo "cross-customer site lookup returned ${foreign_status}, want 404" >&2; exit 1; }
fi

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/support/customers/${customer_id}/sites" > "${tmpdir}/support.html"
assert_contains "${tmpdir}/support.html" 'Support view'
assert_contains "${tmpdir}/support.html" 'phase11-client.test'

curl -sk --fail -b "${tmpdir}/client.cookies" "https://${VM_IP}:7443/search?q=phase11-client" > "${tmpdir}/search.json"
assert_contains "${tmpdir}/search.json" 'phase11-client.test'

csrf_status="$(curl -sk -o /dev/null -w '%{http_code}' -b "${tmpdir}/admin.cookies" -H "Origin: https://${VM_IP}:7443" -d 'oversell_policy=warn' -d 'server_disk_capacity_mb=200000' "https://${VM_IP}:7443/settings/oversell")"
[[ "${csrf_status}" == "403" ]] || { echo "browser-like POST without CSRF returned ${csrf_status}, want 403" >&2; exit 1; }

audit_count="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT COUNT(*) FROM audit_events WHERE action IN ('site.queued','plan.saved','subscription.saved')")"
if [[ "${audit_count}" -lt 3 ]]; then
  echo "Phase 11 audit events were not recorded: ${audit_count}" >&2
  exit 1
fi

echo "Phase 11 routed workspace verification passed for ${VM_NAME} (${VM_IP})."
