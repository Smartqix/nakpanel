#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase9-verify.sh"

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

post_expect_400() {
  local label="$1"
  local endpoint="$2"
  local needle="$3"
  shift 3
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
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
  -d 'legacy=1' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Customers'
assert_contains "${tmpdir}/admin-dashboard.html" 'Add Subscription'
assert_contains "${tmpdir}/admin-dashboard.html" 'name="subscription_id"'
assert_contains "${tmpdir}/admin-dashboard.html" 'Create Customer + Subscription'

phase10_state="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "
SELECT
  (SELECT COUNT(*) FROM customers),
  (SELECT COUNT(*) FROM subscriptions WHERE customer_id IS NOT NULL),
  (SELECT COUNT(*) FROM subscriptions WHERE status = 'active')
")"
IFS='|' read -r customers_count customer_subscriptions active_subscriptions <<<"${phase10_state}"
if [[ "${customers_count}" -lt 2 || "${customer_subscriptions}" -lt 2 || "${active_subscriptions}" -lt 2 ]]; then
  echo "phase10 migration/backfill check failed: ${phase10_state}" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE args::text LIKE '%phase10-one.test%'
   OR args::text LIKE '%phase10-two.test%'
   OR args::text LIKE '%phase10-over.test%'
   OR args::text LIKE '%phase11-client.test%'
   OR args::text LIKE '%np10%'
   OR args::text LIKE '%np11client%';
DELETE FROM restore_runs WHERE backup_id IN (
  SELECT id FROM backups WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase10-customer@nakpanel.test')
     OR target_name IN ('phase10-one.test', 'phase10-two.test', 'phase10-over.test')
);
DELETE FROM backups WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase10-customer@nakpanel.test')
   OR target_name IN ('phase10-one.test', 'phase10-two.test', 'phase10-over.test');
DELETE FROM databases WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase10-customer@nakpanel.test')
   OR db_name LIKE 'np10%'
   OR site_id IN (SELECT id FROM sites WHERE domain IN ('phase10-one.test', 'phase10-two.test', 'phase10-over.test'));
DELETE FROM sites WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase10-customer@nakpanel.test')
   OR domain IN ('phase10-one.test', 'phase10-two.test', 'phase10-over.test');
DELETE FROM subscriptions WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase10-customer@nakpanel.test');
DELETE FROM audit_events WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase10-customer@nakpanel.test')
   OR actor_user_id IN (SELECT id FROM users WHERE email = 'phase10-customer@nakpanel.test');
DELETE FROM customers WHERE email = 'phase10-customer@nakpanel.test';
DELETE FROM users WHERE email = 'phase10-customer@nakpanel.test';
DELETE FROM plans WHERE name IN ('Phase10 One', 'Phase10 Two');
SQL
REMOTE

post_admin phase10-settings settings/oversell \
  -d 'oversell_policy=warn' \
  -d 'server_disk_capacity_mb=200000'

for plan in One Two; do
  post_admin "phase10-plan-${plan}" plans \
    -d "name=Phase10 ${plan}" \
    -d "description=Phase 10 ${plan} subscription-scoped test plan" \
    -d 'disk_mb=64' \
    -d 'max_sites=1' \
    -d 'max_databases=1' \
    -d 'bandwidth_mb=-1' \
    -d 'max_mailboxes=0' \
    -d 'backup_retention_days=7' \
    -d 'php_allowlist=8.3' \
    -d 'php_max_children=2' \
    -d 'php_memory_mb=64' \
    -d 'site_disk_quota_mb=32' \
    -d 'max_backups=1' \
    -d 'backup_storage_mb=64' \
    -d 'allow_dns=true' \
    -d 'is_active=true'
done

plan_one_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM plans WHERE name = 'Phase10 One'" | tr -d '[:space:]')"
plan_two_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM plans WHERE name = 'Phase10 Two'" | tr -d '[:space:]')"
if [[ -z "${plan_one_id}" || -z "${plan_two_id}" ]]; then
  echo "could not resolve Phase10 plan ids" >&2
  exit 1
fi

post_admin phase10-new-customer-sub subscriptions \
  -d 'customer_mode=new' \
  -d 'customer_email=phase10-customer@nakpanel.test' \
  -d 'customer_name=Phase Ten Customer' \
  -d 'company=Phase Ten Co' \
  -d "plan_id=${plan_one_id}" \
  -d 'subscription_name=Phase10 One Sub'

customer_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM customers WHERE email = 'phase10-customer@nakpanel.test'" | tr -d '[:space:]')"
sub_one_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM subscriptions WHERE customer_id = ${customer_id} AND plan_id = ${plan_one_id}" | tr -d '[:space:]')"
if [[ -z "${customer_id}" || -z "${sub_one_id}" ]]; then
  echo "could not resolve phase10 customer/subscription one" >&2
  exit 1
fi

post_admin phase10-second-sub subscriptions \
  -d 'customer_mode=existing' \
  -d "customer_id=${customer_id}" \
  -d "plan_id=${plan_two_id}" \
  -d 'subscription_name=Phase10 Two Sub'
sub_two_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM subscriptions WHERE customer_id = ${customer_id} AND plan_id = ${plan_two_id}" | tr -d '[:space:]')"
if [[ -z "${sub_two_id}" || "${sub_two_id}" == "${sub_one_id}" ]]; then
  echo "could not resolve distinct second subscription" >&2
  exit 1
fi

post_admin phase10-enable-login customers/login \
  -d "customer_id=${customer_id}" \
  -d 'email=phase10-customer@nakpanel.test' \
  -d 'password=NakpanelPhase10!2026'

post_admin phase10-site-one sites \
  -d "subscription_id=${sub_one_id}" \
  -d 'username=np10one' \
  -d 'domain=phase10-one.test' \
  -d 'php_version=8.3'

post_expect_400 phase10-over-one sites 'quota exceeded' \
  -d "subscription_id=${sub_one_id}" \
  -d 'username=np10over' \
  -d 'domain=phase10-over.test' \
  -d 'php_version=8.3'

post_admin phase10-site-two sites \
  -d "subscription_id=${sub_two_id}" \
  -d 'username=np10two' \
  -d 'domain=phase10-two.test' \
  -d 'php_version=8.3'

owner_state="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "
SELECT
  (SELECT COUNT(*) FROM subscriptions WHERE customer_id = ${customer_id} AND status = 'active'),
  (SELECT COUNT(*) FROM sites WHERE customer_id = ${customer_id} AND subscription_id = ${sub_one_id}),
  (SELECT COUNT(*) FROM sites WHERE customer_id = ${customer_id} AND subscription_id = ${sub_two_id})
")"
IFS='|' read -r active_for_customer sites_one sites_two <<<"${owner_state}"
if [[ "${active_for_customer}" -lt 2 || "${sites_one}" != "1" || "${sites_two}" != "1" ]]; then
  echo "phase10 subscription ownership check failed: ${owner_state}" >&2
  exit 1
fi

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=phase10-customer@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelPhase10!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_contains "${tmpdir}/client-dashboard.html" 'Phase10 One'
assert_contains "${tmpdir}/client-dashboard.html" 'Phase10 Two'
if grep -Fq 'admin@nakpanel.test' "${tmpdir}/client-dashboard.html"; then
  echo "client dashboard leaked another customer" >&2
  exit 1
fi

echo "Phase 10 Multipass verification passed for ${VM_NAME} (${VM_IP})."
