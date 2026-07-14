#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase11-verify.sh"
fi

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

db_value() {
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}

post_as() {
  local actor="$1" label="$2" endpoint="$3"
  shift 3
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -b "${tmpdir}/${actor}.cookies" -c "${tmpdir}/${actor}.cookies" "$@" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/${actor}.cookies")" \
    "https://${VM_IP}:7443/${endpoint}")"
  if [[ "${status}" != "303" ]]; then
    echo "${label} returned HTTP ${status}, want 303" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
}

post_expect_400() {
  local actor="$1" label="$2" endpoint="$3" needle="$4"
  shift 4
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -b "${tmpdir}/${actor}.cookies" -c "${tmpdir}/${actor}.cookies" "$@" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/${actor}.cookies")" \
    "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "400" ]] || { echo "${label} returned ${status}, want 400" >&2; cat "${tmpdir}/${label}.out" >&2; exit 1; }
  assert_contains "${tmpdir}/${label}.out" "${needle}"
}

post_expect_404() {
  local actor="$1" label="$2" endpoint="$3"
  shift 3
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -b "${tmpdir}/${actor}.cookies" -c "${tmpdir}/${actor}.cookies" "$@" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/${actor}.cookies")" \
    "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "404" ]] || { echo "${label} returned ${status}, want 404" >&2; cat "${tmpdir}/${label}.out" >&2; exit 1; }
}

wait_for_value() {
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 90); do
    value="$(db_value "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  echo "${label}: got ${value}, want ${expected}" >&2
  exit 1
}

wait_for_http_status() {
  local label="$1" host="$2" expected="$3" status=""
  for _ in $(seq 1 30); do
    status="$(multipass exec "${VM_NAME}" -- curl -s -o /dev/null -w '%{http_code}' -H "Host: ${host}" http://127.0.0.1/)"
    [[ "${status}" == "${expected}" ]] && return 0
    sleep 1
  done
  echo "${label}: got HTTP ${status}, want ${expected}" >&2
  exit 1
}

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin.html"
for marker in 'Resellers' 'Domains' 'Service Plans' 'Tools &amp; Settings'; do
  assert_contains "${tmpdir}/admin.html" "${marker}"
done
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/resellers" > "${tmpdir}/resellers.html"
assert_contains "${tmpdir}/resellers.html" 'Provider accounts'
assert_contains "${tmpdir}/resellers.html" 'data-np-bulk-form'
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/service-plans" > "${tmpdir}/service-plans.html"
for marker in 'Hosting Plans' 'Add-on Plans' 'Reseller Plans' 'Create plan' 'np-plan-table'; do
  assert_contains "${tmpdir}/service-plans.html" "${marker}"
done
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/service-plans?type=addon" > "${tmpdir}/addon-plans.html"
assert_contains "${tmpdir}/addon-plans.html" '/addons/bulk-status'
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/service-plans?type=reseller" > "${tmpdir}/reseller-plans.html"
assert_contains "${tmpdir}/reseller-plans.html" '/reseller-plans/bulk-status'
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/service-plans/new" > "${tmpdir}/service-plan-new.html"
for marker in 'data-np-plan-editor' 'Resources' 'Permissions' 'PHP Settings' 'Logs &amp; Statistics' 'Overuse is not allowed' 'data-np-unlimited'; do
  assert_contains "${tmpdir}/service-plan-new.html" "${marker}"
done
service_plan_schema="$(db_value "SELECT (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='plans' AND column_name IN ('overuse_policy','max_subdomains','max_domain_aliases','max_ftp_accounts','validity_days')) || ':' || (SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('plan_service_presets','subscription_usage_current','site_traffic_cursors','notifications','notification_deliveries'))")"
[[ "${service_plan_schema}" == '5:5' ]] || { echo "service plan schema is incomplete: ${service_plan_schema}" >&2; exit 1; }
service_plan_name_indexes="$(db_value "SELECT COUNT(*) FROM pg_indexes WHERE indexname IN ('plans_provider_name_admin_idx','plans_provider_name_reseller_idx','addon_plans_provider_name_admin_idx','addon_plans_provider_name_reseller_idx','reseller_plans_name_ci_idx')")"
[[ "${service_plan_name_indexes}" == '5' ]] || { echo "provider-scoped plan name indexes are incomplete: ${service_plan_name_indexes}" >&2; exit 1; }

# Keep the phase verifier repeatable on the shared lab VM without disturbing
# fixtures owned by the earlier verification phases.
multipass exec "${VM_NAME}" -- sudo -u postgres psql -v ON_ERROR_STOP=1 -d nakpanel <<'SQL'
DELETE FROM audit_events
WHERE actor_user_id IN (SELECT id FROM users WHERE email = 'phase12-reseller@nakpanel.test')
   OR customer_id IN (SELECT id FROM customers WHERE email = 'phase12-customer@nakpanel.test')
   OR (target_type = 'site' AND target_id IN (SELECT id FROM sites WHERE domain = 'phase12-reseller.test'));
DELETE FROM river_job WHERE args::text LIKE '%phase12%' OR args::text LIKE '%np12site%';
DELETE FROM restore_runs
WHERE backup_id IN (SELECT id FROM backups WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase12-customer@nakpanel.test'))
   OR owner_user_id IN (SELECT id FROM users WHERE email = 'phase12-reseller@nakpanel.test');
DELETE FROM backups WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase12-customer@nakpanel.test');
DELETE FROM databases WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase12-customer@nakpanel.test');
DELETE FROM sites WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase12-customer@nakpanel.test');
DELETE FROM subscriptions WHERE customer_id IN (SELECT id FROM customers WHERE email = 'phase12-customer@nakpanel.test');
DELETE FROM customers WHERE email = 'phase12-customer@nakpanel.test';
DELETE FROM addon_plans WHERE reseller_id IN (SELECT id FROM reseller_accounts WHERE email = 'phase12-reseller@nakpanel.test');
DELETE FROM addon_plans WHERE reseller_id IS NULL AND name = 'Phase12 Foreign Addon';
DELETE FROM plans WHERE reseller_id IN (SELECT id FROM reseller_accounts WHERE email = 'phase12-reseller@nakpanel.test');
DELETE FROM reseller_subscriptions WHERE reseller_id IN (SELECT id FROM reseller_accounts WHERE email = 'phase12-reseller@nakpanel.test');
DELETE FROM reseller_accounts WHERE email = 'phase12-reseller@nakpanel.test';
DELETE FROM users WHERE email = 'phase12-reseller@nakpanel.test';
DELETE FROM reseller_plans WHERE name = 'Phase12 Agency';
SQL
multipass exec "${VM_NAME}" -- bash -c '
  sudo rm -f /etc/nginx/sites-enabled/phase12-reseller.test.conf /etc/nginx/sites-available/phase12-reseller.test.conf
  sudo rm -f /etc/php/8.3/fpm/pool.d/nakpanel-*-phase12-reseller-test.conf /etc/php/8.3/fpm/pool.d/nakpanel-*-phase12-reseller-test.conf.suspended
  sudo systemctl reload nginx php8.3-fpm >/dev/null 2>&1 || true
  id -u np12site >/dev/null 2>&1 && sudo userdel -r np12site >/dev/null 2>&1 || true
'

post_as admin phase12-reseller-plan reseller-plans \
  -d 'name=Phase12 Agency' -d 'description=Bounded Phase 12 provider allocation' \
  -d 'max_customers=2' -d 'max_subscriptions=2' -d 'disk_mb=200' \
  -d 'max_sites=4' -d 'max_databases=4' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'max_backups=4' -d 'backup_storage_mb=200' \
  -d 'allow_custom_plans=true' -d 'allow_dns=true' -d 'is_active=true'
reseller_plan_id="$(db_value "SELECT id FROM reseller_plans WHERE name='Phase12 Agency'")"

post_as admin phase12-reseller resellers \
  -d 'customer_name=Phase Twelve Provider' -d 'company=Phase Twelve Hosting' \
  -d 'customer_email=phase12-reseller@nakpanel.test' -d 'password=NakpanelPhase12!2026' \
  -d "reseller_plan_id=${reseller_plan_id}" -d 'notes=Multipass provider verification'
reseller_id="$(db_value "SELECT id FROM reseller_accounts WHERE email='phase12-reseller@nakpanel.test'")"

curl -sk --fail -c "${tmpdir}/reseller.cookies" -b "${tmpdir}/reseller.cookies" -L \
  -d 'email=phase12-reseller@nakpanel.test' -d 'password=NakpanelPhase12!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/reseller.html"
for marker in 'Customers' 'Domains' 'Service Plans' 'My Resources'; do
  assert_contains "${tmpdir}/reseller.html" "${marker}"
done
if grep -Fq 'Tools &amp; Settings' "${tmpdir}/reseller.html"; then
  echo "reseller workspace exposed global server settings" >&2
  exit 1
fi

post_as reseller phase12-hosting-plan plans \
  -d 'name=Phase12 Reseller Hosting' -d 'description=Provider-owned synchronized plan' \
  -d 'disk_mb=64' -d 'max_sites=1' -d 'max_databases=1' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=7' -d 'php_allowlist=8.3' \
  -d 'php_max_children=2' -d 'php_memory_mb=128' -d 'site_disk_quota_mb=64' \
  -d 'max_backups=1' -d 'backup_storage_mb=64' -d 'allow_dns=true' -d 'is_active=true'
plan_id="$(db_value "SELECT id FROM plans WHERE name='Phase12 Reseller Hosting' AND reseller_id=${reseller_id}")"

post_as reseller phase12-customer customers \
  -d 'customer_email=phase12-customer@nakpanel.test' -d 'customer_name=Phase Twelve Customer' \
  -d 'company=Provider Tenant'
customer_id="$(db_value "SELECT id FROM customers WHERE email='phase12-customer@nakpanel.test' AND reseller_id=${reseller_id}")"

for name in Synced Locked; do
  post_as reseller "phase12-sub-${name}" subscriptions \
    -d 'customer_mode=existing' -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" \
    -d "subscription_name=Phase12 ${name}"
done
synced_id="$(db_value "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='Phase12 Synced'")"
locked_id="$(db_value "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='Phase12 Locked'")"
post_as reseller phase12-lock "subscriptions/${locked_id}/mode" -d 'sync_mode=locked'

# A provider must retain management access to its own suspended subscription so
# it can reactivate it, while ownership checks remain provider-scoped.
post_as reseller phase12-subscription-suspend "subscriptions/${locked_id}/status" \
  -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d 'subscription_name=Phase12 Locked' \
  -d 'status=suspended' -d 'sync_mode=locked'
wait_for_value 'subscription suspension' "SELECT status FROM subscriptions WHERE id=${locked_id}" 'suspended'
post_as reseller phase12-subscription-reactivate "subscriptions/${locked_id}/status" \
  -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d 'subscription_name=Phase12 Locked' \
  -d 'status=active' -d 'sync_mode=locked'
wait_for_value 'subscription reactivation' "SELECT status FROM subscriptions WHERE id=${locked_id}" 'active'

post_expect_400 reseller phase12-over-allocation subscriptions 'reseller capacity exceeded' \
  -d 'customer_mode=existing' -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" \
  -d 'subscription_name=Phase12 Too Many'

post_as reseller phase12-plan-update plans \
  -d "plan_id=${plan_id}" -d 'name=Phase12 Reseller Hosting' -d 'description=Revised provider plan' \
  -d 'disk_mb=64' -d 'max_sites=2' -d 'max_databases=1' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=7' -d 'php_allowlist=8.3' \
  -d 'php_max_children=2' -d 'php_memory_mb=128' -d 'site_disk_quota_mb=64' \
  -d 'max_backups=1' -d 'backup_storage_mb=64' -d 'allow_dns=true' -d 'is_active=true'
wait_for_value 'synced snapshot revision' "SELECT e.max_sites||':'||s.sync_status FROM subscriptions s JOIN subscription_entitlements e ON e.subscription_id=s.id WHERE s.id=${synced_id}" '2:in_sync'
locked_state="$(db_value "SELECT e.max_sites||':'||s.sync_mode FROM subscriptions s JOIN subscription_entitlements e ON e.subscription_id=s.id WHERE s.id=${locked_id}")"
[[ "${locked_state}" == '1:locked' ]] || { echo "locked snapshot changed: ${locked_state}" >&2; exit 1; }

post_as reseller phase12-addon addons \
  -d 'name=Phase12 PHP Boost' -d 'description=Provider-owned synchronized add-on' \
  -d 'disk_mb=0' -d 'max_sites=0' -d 'max_databases=0' -d 'bandwidth_mb=0' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=0' -d 'php_allowlist=' \
  -d 'php_max_children=0' -d 'php_memory_mb=256' -d 'site_disk_quota_mb=0' \
  -d 'max_backups=0' -d 'backup_storage_mb=0' -d 'is_active=true'
addon_id="$(db_value "SELECT id FROM addon_plans WHERE name='Phase12 PHP Boost' AND reseller_id=${reseller_id}")"
post_as reseller phase12-addon-assign "subscriptions/${synced_id}/addons" -d "addon_id=${addon_id}"
wait_for_value 'initial add-on snapshot' "SELECT php_memory_mb FROM subscription_entitlements WHERE subscription_id=${synced_id}" '256'

post_as reseller phase12-addon-update addons \
  -d "addon_id=${addon_id}" -d 'name=Phase12 PHP Boost' -d 'description=Revised provider add-on' \
  -d 'disk_mb=0' -d 'max_sites=0' -d 'max_databases=0' -d 'bandwidth_mb=0' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=0' -d 'php_allowlist=' \
  -d 'php_max_children=0' -d 'php_memory_mb=384' -d 'site_disk_quota_mb=0' \
  -d 'max_backups=0' -d 'backup_storage_mb=0' -d 'is_active=true'
wait_for_value 'updated add-on snapshot' "SELECT e.php_memory_mb||':'||s.sync_status FROM subscriptions s JOIN subscription_entitlements e ON e.subscription_id=s.id WHERE s.id=${synced_id}" '384:in_sync'

post_as admin phase12-foreign-addon addons \
  -d 'name=Phase12 Foreign Addon' -d 'description=Administrator-owned isolation fixture' \
  -d 'disk_mb=0' -d 'max_sites=1' -d 'max_databases=0' -d 'bandwidth_mb=0' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=0' -d 'php_allowlist=' \
  -d 'php_max_children=0' -d 'php_memory_mb=0' -d 'site_disk_quota_mb=0' \
  -d 'max_backups=0' -d 'backup_storage_mb=0' -d 'is_active=true'
foreign_addon_id="$(db_value "SELECT id FROM addon_plans WHERE name='Phase12 Foreign Addon' AND reseller_id IS NULL")"
post_expect_400 reseller phase12-foreign-addon-rejected "subscriptions/${synced_id}/addons" 'belongs to another provider' \
  -d "addon_id=${foreign_addon_id}"
wait_for_value 'provider add-on assignment retained' "SELECT addon_plan_id FROM subscription_addons WHERE subscription_id=${synced_id}" "${addon_id}"

post_expect_400 reseller phase12-custom-over-allocation "subscriptions/${locked_id}/mode" 'reseller capacity exceeded' \
  -d 'sync_mode=custom' -d 'disk_mb=201' -d 'max_sites=1' -d 'max_databases=1' \
  -d 'bandwidth_mb=-1' -d 'max_mailboxes=0' -d 'backup_retention_days=7' \
  -d 'php_allowlist=8.3' -d 'php_max_children=2' -d 'php_memory_mb=128' \
  -d 'site_disk_quota_mb=64' -d 'max_backups=1' -d 'backup_storage_mb=64' -d 'allow_dns=true'

post_expect_400 admin phase12-reseller-plan-shrink reseller-plans 'reseller capacity exceeded' \
  -d "reseller_plan_id=${reseller_plan_id}" -d 'name=Phase12 Agency' -d 'description=Invalid downsizing attempt' \
  -d 'max_customers=2' -d 'max_subscriptions=2' -d 'disk_mb=200' \
  -d 'max_sites=2' -d 'max_databases=4' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'max_backups=4' -d 'backup_storage_mb=200' \
  -d 'allow_custom_plans=true' -d 'allow_dns=true' -d 'is_active=true'
wait_for_value 'reseller plan rollback' "SELECT max_sites FROM reseller_plans WHERE id=${reseller_plan_id}" '4'

post_as admin phase12-admin-plan-edit plans \
  -d "plan_id=${plan_id}" -d 'name=Phase12 Reseller Hosting' -d 'description=Administrator support edit' \
  -d 'disk_mb=64' -d 'max_sites=2' -d 'max_databases=1' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=7' -d 'php_allowlist=8.3' \
  -d 'php_max_children=2' -d 'php_memory_mb=128' -d 'site_disk_quota_mb=64' \
  -d 'max_backups=1' -d 'backup_storage_mb=64' -d 'allow_dns=true' -d 'is_active=true'
wait_for_value 'admin plan edit preserves provider' "SELECT COALESCE(reseller_id,0) FROM plans WHERE id=${plan_id}" "${reseller_id}"

# Forged IDs must neither reassign provider objects nor overwrite globally
# unique resource names that already belong to another subscription.
foreign_subscription_id="$(db_value "SELECT subscription_id FROM sites WHERE domain='phase5-ui.test'")"
foreign_subscription_owner="$(db_value "SELECT customer_id FROM subscriptions WHERE id=${foreign_subscription_id}")"
post_expect_404 reseller phase12-foreign-subscription-update subscriptions \
  -d "subscription_id=${foreign_subscription_id}" -d 'customer_mode=existing' \
  -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d 'subscription_name=Forged provider update'
wait_for_value 'foreign subscription ownership retained' "SELECT customer_id FROM subscriptions WHERE id=${foreign_subscription_id}" "${foreign_subscription_owner}"

foreign_site_subscription="$(db_value "SELECT subscription_id FROM sites WHERE domain='phase5-ui.test'")"
post_expect_404 reseller phase12-foreign-site-conflict sites \
  -d "subscription_id=${synced_id}" -d 'username=np12forged' -d 'domain=phase5-ui.test' -d 'php_version=8.3'
wait_for_value 'foreign site ownership retained' "SELECT subscription_id FROM sites WHERE domain='phase5-ui.test'" "${foreign_site_subscription}"

foreign_database_subscription="$(db_value "SELECT subscription_id FROM databases WHERE db_name='np_phase5'")"
post_expect_404 reseller phase12-foreign-database-conflict databases \
  -d "subscription_id=${synced_id}" -d 'engine=mariadb' -d 'db_name=np_phase5' -d 'db_user=np12_forged'
wait_for_value 'foreign database ownership retained' "SELECT subscription_id FROM databases WHERE db_name='np_phase5'" "${foreign_database_subscription}"

integrity_guards="$(db_value "SELECT (SELECT COUNT(*) FROM pg_constraint WHERE conname IN ('sites_subscription_customer_fk','databases_subscription_customer_fk','backups_subscription_customer_fk') AND confupdtype='c') || ':' || (SELECT COUNT(*) FROM pg_indexes WHERE indexname='users_email_lower_idx')")"
[[ "${integrity_guards}" == '3:1' ]] || { echo "tenant integrity guards are incomplete: ${integrity_guards}" >&2; exit 1; }

post_as reseller phase12-site sites \
  -d "subscription_id=${synced_id}" -d 'username=np12site' -d 'domain=phase12-reseller.test' -d 'php_version=8.3'
site_id="$(db_value "SELECT id FROM sites WHERE domain='phase12-reseller.test'")"
wait_for_value 'site provisioning' "SELECT status FROM sites WHERE id=${site_id}" 'active'
site_username="$(db_value "SELECT username FROM sites WHERE id=${site_id}")"
site_home="$(db_value "SELECT '/home/'||username FROM sites WHERE id=${site_id}")"
site_pool="/etc/php/8.3/fpm/pool.d/nakpanel-${site_username}-phase12-reseller-test.conf"

post_as reseller phase12-suspend customers/status -d "customer_id=${customer_id}" -d 'status=suspended'
wait_for_value 'site suspension' "SELECT status FROM sites WHERE id=${site_id}" 'suspended'
wait_for_http_status 'suspended website' 'phase12-reseller.test' '503'
multipass exec "${VM_NAME}" -- test -f "${site_pool}.suspended"

post_as reseller phase12-activate customers/status -d "customer_id=${customer_id}" -d 'status=active'
wait_for_value 'site reactivation' "SELECT status FROM sites WHERE id=${site_id}" 'active'
wait_for_http_status 'reactivated website' 'phase12-reseller.test' '200'
multipass exec "${VM_NAME}" -- test -f "${site_pool}"

# Two opposing jobs may overlap in River. The worker must converge on the
# current database intent rather than letting a stale suspend win last.
post_as reseller phase12-rapid-suspend customers/status -d "customer_id=${customer_id}" -d 'status=suspended'
post_as reseller phase12-rapid-activate customers/status -d "customer_id=${customer_id}" -d 'status=active'
wait_for_value 'rapid lifecycle convergence' "SELECT status FROM sites WHERE id=${site_id}" 'active'
wait_for_http_status 'rapid lifecycle convergence' 'phase12-reseller.test' '200'

# The plan's block policy is enforced from measured disk usage. The per-site
# quota remains higher than the aggregate subscription limit so this verifies
# the subscription-level collector rather than only the kernel quota.
post_as reseller phase12-overuse-plan plans \
  -d "plan_id=${plan_id}" -d 'name=Phase12 Reseller Hosting' -d 'description=Measured overuse fixture' \
  -d 'disk_mb=1' -d 'max_sites=2' -d 'max_databases=1' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'backup_retention_days=7' -d 'php_allowlist=8.3' \
  -d 'default_php_version=8.3' -d 'hosting_enabled=true' -d 'overuse_policy=block' \
  -d 'disk_warning_percent=80' -d 'traffic_warning_percent=80' \
  -d 'php_max_children=2' -d 'php_memory_mb=128' -d 'site_disk_quota_mb=64' \
  -d 'max_backups=1' -d 'backup_storage_mb=64' -d 'max_subdomains=0' \
  -d 'max_domain_aliases=0' -d 'max_ftp_accounts=0' -d 'validity_days=-1' \
  -d 'allow_dns=true' -d 'allow_tls=true' -d 'allow_backups=true' -d 'is_active=true'
wait_for_value 'overuse plan snapshot' "SELECT disk_mb FROM subscription_entitlements WHERE subscription_id=${synced_id}" '1'
multipass exec "${VM_NAME}" -- sudo -u "${site_username}" dd if=/dev/zero of="${site_home}/overuse.bin" bs=1M count=2 status=none
multipass exec "${VM_NAME}" -- sudo systemctl restart nakpanel
wait_for_value 'usage collection completed' "SELECT is_complete::text FROM subscription_usage_current WHERE subscription_id=${synced_id}" 'true'
wait_for_value 'overuse subscription suspension' "SELECT status FROM subscriptions WHERE id=${synced_id}" 'suspended'
wait_for_http_status 'overuse website' 'phase12-reseller.test' '503'
overuse_alerts="$(db_value "SELECT COUNT(*) FROM notifications WHERE subscription_id=${synced_id} AND kind IN ('over_limit','suspended') AND resolved_at IS NULL")"
[[ "${overuse_alerts}" -ge 2 ]] || { echo "overuse notifications are incomplete: ${overuse_alerts}" >&2; exit 1; }

multipass exec "${VM_NAME}" -- sudo rm -f "${site_home}/overuse.bin"
multipass exec "${VM_NAME}" -- sudo systemctl restart nakpanel
wait_for_value 'usage returned below plan' "SELECT (is_complete AND disk_bytes<=1048576)::text FROM subscription_usage_current WHERE subscription_id=${synced_id}" 'true'
post_as reseller phase12-overuse-reactivate "subscriptions/${synced_id}/status" \
  -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d 'subscription_name=Phase12 Synced' \
  -d 'status=active' -d 'sync_mode=synced'
wait_for_value 'overuse manual reactivation' "SELECT status FROM subscriptions WHERE id=${synced_id}" 'active'
wait_for_http_status 'overuse website restored' 'phase12-reseller.test' '200'

foreign_customer_id="$(db_value "SELECT id FROM customers WHERE reseller_id IS NULL ORDER BY id LIMIT 1")"
foreign_status="$(curl -sk -o /dev/null -w '%{http_code}' -b "${tmpdir}/reseller.cookies" "https://${VM_IP}:7443/customers/${foreign_customer_id}")"
[[ "${foreign_status}" == '404' ]] || { echo "cross-provider customer lookup returned ${foreign_status}, want 404" >&2; exit 1; }

audit_count="$(db_value "SELECT COUNT(*) FROM audit_events WHERE (target_id=${site_id} AND action='hosting.state_converged') OR (target_id=${customer_id} AND action='customer.status_changed')")"
[[ "${audit_count}" -ge 4 ]] || { echo "lifecycle audit trail is incomplete: ${audit_count}" >&2; exit 1; }

echo "Phase 12 service provider verification passed for ${VM_NAME} (${VM_IP})."
