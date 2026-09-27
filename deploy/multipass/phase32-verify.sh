#!/usr/bin/env bash
# Phase 32 WordPress Toolkit acceptance. This verifier exercises the public
# plan, site, and WordPress workflows; direct database writes are inspection
# only and never manufacture application state.
set -euo pipefail
trap 'status=$?; echo "phase32 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
PHASE32_COMPLETE=0

fail(){ echo "phase32: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${SCRIPT_DIR}/phase31-verify.sh"
fi

require_nakpanel_vm_name "${VM_NAME}"
for tool in curl python3; do
  command -v "${tool}" >/dev/null 2>&1 || fail "host prerequisite ${tool} is not installed"
done

tmpdir="$(mktemp -d)"
cleanup_phase32(){
  local status=$?
  if [[ "${PHASE32_COMPLETE}" != "1" && "${status}" -eq 0 ]]; then
    status=1
  fi
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup_phase32 EXIT

wait_for(){
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 180); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "${label}: got ${value:-empty}, want ${expected}"
}

post_as(){
  local label="$1" endpoint="$2"
  shift 2
  local status
  status="$(curl --connect-timeout 5 --max-time 30 -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "303" ]] || {
    echo "${label} returned HTTP ${status}, want 303" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  }
}

post_expect(){
  local expected="$1" label="$2" endpoint="$3"
  shift 3
  local status
  status="$(curl --connect-timeout 5 --max-time 30 -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "${expected}" ]] || {
    echo "${label} returned HTTP ${status}, want ${expected}" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  }
}

echo "phase32: install the current WordPress Toolkit build"
sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
src="$1"
cd "${src}"
timeout 45m deploy/install/install.sh --yes --allow-downgrade --force
systemctl is-active --quiet nakpanel.service
systemctl is-active --quiet nakpanel-agent.service
command -v wp >/dev/null
wp --allow-root --info | grep -Fq 'WP-CLI version'
REMOTE

VM_IP="$(vm_ip)"
[[ -n "${VM_IP}" ]] || fail "could not determine ${VM_NAME} IPv4 address"
for _ in $(seq 1 180); do
  curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null && break
  sleep 2
done
curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null || fail "current panel is not healthy"

schema_contract="$(db "SELECT (SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('wordpress_instances','wordpress_operations')) || ':' || (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='wordpress_operations' AND column_name='maintenance_enabled')")"
[[ "${schema_contract}" == '2:1' ]] || fail "Phase 32 schema contract is incomplete: ${schema_contract}"

curl --connect-timeout 5 --max-time 30 -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/admin.html"
grep -q 'data-np-role="admin"' "${tmpdir}/admin.html" || fail "admin login failed"

run_id="$(date +%s)"
plan_name="Phase32 WordPress ${run_id}"
customer_email="phase32-${run_id}@nakpanel.test"
domain="phase32-${run_id}.test"
limit_domain="phase32-limit-${run_id}.test"
admin_password="WordPress-Phase32-${run_id}!"
reset_password="WordPress-Reset-${run_id}!"
client_password="WordPress-Client-${run_id}!"

echo "phase32: create a ready plan with explicit WordPress entitlement"
post_as phase32-plan plans \
  -d 'plan_id=0' -d "name=${plan_name}" -d 'description=WordPress Toolkit acceptance plan' \
  -d 'lifecycle_status=active' -d 'change_reason=Phase 32 acceptance' \
  -d 'disk_mb=-1' -d 'bandwidth_mb=-1' -d 'max_sites=2' -d 'max_databases=2' \
  -d 'max_mailboxes=0' -d 'max_backups=4' -d 'backup_storage_mb=4096' \
  -d 'site_disk_quota_mb=-1' -d 'php_allowlist=8.4' -d 'php_versions=8.4' \
  -d 'default_php_version=8.4' -d 'php_max_children=4' -d 'php_memory_mb=256' \
  -d 'hosting_enabled=true' -d 'allow_tls=true' -d 'allow_backups=true' \
  -d 'allow_php_settings=true' -d 'allow_logs=true' -d 'php_opcache_enabled=true' \
  -d 'php_log_errors=true' -d 'allow_wordpress_toolkit=true' -d 'max_wordpress_sites=1' \
  -d 'overuse_policy=block' -d 'validity_days=-1'
plan_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND name='${plan_name}'")"
[[ "${plan_id}" =~ ^[0-9]+$ ]] || fail "WordPress plan was not created"
[[ "$(db "SELECT (hosting_policy->'permissions'->>'wordpress_toolkit')||':'||(hosting_policy->'resources'->>'max_wordpress_sites') FROM plans WHERE id=${plan_id}")" == 'true:1' ]] || fail "WordPress plan entitlement was not persisted"

post_as phase32-customer customers -d "customer_email=${customer_email}" -d "customer_name=Phase 32 ${run_id}" -d 'company=Nakpanel Acceptance'
customer_id="$(db "SELECT id FROM customers WHERE email='${customer_email}'")"
post_as phase32-customer-login customers/login -d "customer_id=${customer_id}" -d "email=${customer_email}" -d "password=${client_password}"
post_as phase32-subscription subscriptions -d 'customer_mode=existing' -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d "subscription_name=WordPress ${run_id}"
subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='WordPress ${run_id}'")"
wait_for 'WordPress entitlement synchronization' "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" 'in_sync'

post_as phase32-site sites -d "subscription_id=${subscription_id}" -d "domain=${domain}"
site_id="$(db "SELECT id FROM sites WHERE domain='${domain}'")"
wait_for 'WordPress site provisioning' "SELECT status FROM sites WHERE id=${site_id}" 'active'
username="$(db "SELECT account.username FROM subscription_system_accounts account WHERE account.subscription_id=${subscription_id}")"
document_root="$(db "SELECT document_root FROM sites WHERE id=${site_id}")"

echo "phase32: prove failed discovery placeholders do not consume or bypass quota"
post_as phase32-limit-site sites -d "subscription_id=${subscription_id}" -d "domain=${limit_domain}"
limit_site_id="$(db "SELECT id FROM sites WHERE domain='${limit_domain}'")"
wait_for 'limit-test site provisioning' "SELECT status FROM sites WHERE id=${limit_site_id}" 'active'
post_as phase32-empty-discovery "sites/${limit_site_id}/wordpress/operations" -d 'action=discover'
wait_for 'empty WordPress discovery failure' "SELECT status FROM wordpress_operations WHERE instance_id=(SELECT id FROM wordpress_instances WHERE site_id=${limit_site_id}) AND kind='discover' ORDER BY id DESC LIMIT 1" 'failed'
[[ "$(db "SELECT observed_state||':'||convergence_status FROM wordpress_instances WHERE site_id=${limit_site_id}")" == 'failed:failed' ]] || fail "failed discovery placeholder did not retain a recoverable state"

echo "phase32: install WordPress through the Toolkit"
post_as phase32-install "sites/${site_id}/wordpress/install" \
  -d 'site_title=Phase 32 WordPress' -d 'admin_user=siteadmin' \
  -d "admin_email=${customer_email}" -d "admin_password=${admin_password}" -d 'version=7.1'
wait_for 'WordPress installation operation' "SELECT status FROM wordpress_operations WHERE instance_id=(SELECT id FROM wordpress_instances WHERE site_id=${site_id}) AND kind='install' ORDER BY id DESC LIMIT 1" 'succeeded'
instance_id="$(db "SELECT id FROM wordpress_instances WHERE site_id=${site_id}")"
wait_for 'WordPress observed state' "SELECT observed_state||':'||convergence_status||':'||installed_version FROM wordpress_instances WHERE id=${instance_id}" 'healthy:in_sync:7.1'
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp core verify-checksums --path="${document_root}" --no-color
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%a' "${document_root}/wp-config.php" | tr -d '\r')" == '600' ]] || fail "wp-config.php is not mode 0600"
if multipass_exec_short "${VM_NAME}" -- sudo -u nobody cat "${document_root}/wp-config.php" >/dev/null 2>&1; then
  fail "an unrelated local account can read wp-config.php"
fi

curl --connect-timeout 5 --max-time 30 -skf -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/sites/${site_id}/wordpress" -o "${tmpdir}/wordpress.html"
for marker in 'WordPress Toolkit' 'Phase 32 WordPress' 'WordPress 7.1' 'Security' 'Plugins' 'Themes' 'Updates' 'Activity'; do
  grep -Fq "${marker}" "${tmpdir}/wordpress.html" || fail "WordPress workspace is missing ${marker}"
done
[[ "$(cat "${tmpdir}/wordpress.html")" != *"${admin_password}"* ]] || fail "WordPress workspace exposes the installation password"

echo "phase32: reset the administrator password without exposing it"
password_hash_before="$(multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp user get siteadmin --field=user_pass --path="${document_root}" --no-color | tr -d '\r\n')"
post_as phase32-password-reset "sites/${site_id}/wordpress/operations" -d 'action=password_reset' -d "admin_password=${reset_password}"
password_operation="$(db "SELECT id FROM wordpress_operations WHERE instance_id=${instance_id} AND kind='password_reset' ORDER BY id DESC LIMIT 1")"
wait_for 'WordPress password reset' "SELECT status FROM wordpress_operations WHERE id=${password_operation}" 'succeeded'
password_hash_after="$(multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp user get siteadmin --field=user_pass --path="${document_root}" --no-color | tr -d '\r\n')"
[[ -n "${password_hash_before}" && -n "${password_hash_after}" && "${password_hash_before}" != "${password_hash_after}" ]] || fail "WordPress administrator password hash did not change"

echo "phase32: prove backup-gated updates"
post_as phase32-update "sites/${site_id}/wordpress/operations" -d 'action=update' -d 'target_type=all' -d 'confirm=update'
update_operation="$(db "SELECT id FROM wordpress_operations WHERE instance_id=${instance_id} AND kind='update' ORDER BY id DESC LIMIT 1")"
[[ "$(db "SELECT status||':'||(backup_id IS NOT NULL)::text FROM wordpress_operations WHERE id=${update_operation}")" == 'waiting_backup:true' ]] || fail "update did not enter waiting_backup with a recovery point"
wait_for 'WordPress update operation' "SELECT status FROM wordpress_operations WHERE id=${update_operation}" 'succeeded'
[[ "$(db "SELECT backup.status FROM backups backup JOIN wordpress_operations operation ON operation.backup_id=backup.id WHERE operation.id=${update_operation}")" == 'active' ]] || fail "WordPress update backup did not complete"

echo "phase32: prove explicit maintenance state"
post_as phase32-maintenance-on "sites/${site_id}/wordpress/operations" -d 'action=maintenance' -d 'maintenance=true'
wait_for 'maintenance activation' "SELECT maintenance_mode::text FROM wordpress_instances WHERE id=${instance_id}" 'true'
maintenance_status="$(curl --connect-timeout 5 --max-time 30 -s -o /dev/null -w '%{http_code}' -H "Host: ${domain}" "http://${VM_IP}/")"
[[ "${maintenance_status}" == '503' ]] || fail "maintenance site returned HTTP ${maintenance_status}, want 503"
post_as phase32-maintenance-off "sites/${site_id}/wordpress/operations" -d 'action=maintenance' -d 'maintenance=false'
wait_for 'maintenance deactivation' "SELECT maintenance_mode::text FROM wordpress_instances WHERE id=${instance_id}" 'false'
curl --connect-timeout 5 --max-time 30 -sf -H "Host: ${domain}" "http://${VM_IP}/" >/dev/null || fail "WordPress site did not recover after maintenance"

echo "phase32: prove count limits and secret-free jobs"
post_expect 400 phase32-limit-install "sites/${limit_site_id}/wordpress/install" \
	-H 'X-Nakpanel-SPA: true' -H 'Accept: application/json' \
  -d 'site_title=Over Limit' -d 'admin_user=siteadmin' -d "admin_email=${customer_email}" \
  -d "admin_password=${admin_password}" -d 'version=7.1'
grep -Fqi 'WordPress site limit' "${tmpdir}/phase32-limit-install.out" || fail "WordPress limit rejection is unclear"

echo "phase32: prove customer ownership and cross-tenant concealment"
curl --connect-timeout 5 --max-time 30 -sk --fail -c "${tmpdir}/client.cookies" -L \
  -d "email=${customer_email}" -d "password=${client_password}" \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/client.html"
grep -q 'data-np-role="client"' "${tmpdir}/client.html" || fail "Phase 32 customer login failed"
own_status="$(curl --connect-timeout 5 --max-time 30 -sk -o "${tmpdir}/client-own.html" -w '%{http_code}' -b "${tmpdir}/client.cookies" "https://${VM_IP}:7443/sites/${site_id}/wordpress")"
[[ "${own_status}" == '200' ]] || fail "customer WordPress workspace returned HTTP ${own_status}"
other_site_id="$(db "SELECT id FROM sites WHERE customer_id<>${customer_id} ORDER BY id LIMIT 1")"
[[ "${other_site_id}" =~ ^[0-9]+$ ]] || fail "could not resolve a cross-tenant site from the prerequisite chain"
other_status="$(curl --connect-timeout 5 --max-time 30 -sk -o /dev/null -w '%{http_code}' -b "${tmpdir}/client.cookies" "https://${VM_IP}:7443/sites/${other_site_id}/wordpress")"
[[ "${other_status}" == '404' ]] || fail "cross-tenant WordPress lookup returned HTTP ${other_status}, want 404"

job_payloads="$(db "SELECT COALESCE(string_agg(args::text,'|'),'') FROM river_job WHERE kind='wordpress_operation'")"
for forbidden in database_password admin_password "${admin_password}"; do
  [[ "${job_payloads}" != *"${forbidden}"* ]] || fail "River WordPress arguments expose ${forbidden}"
done
[[ "$(db "SELECT COUNT(*) FROM service_secrets WHERE scope='wordpress.instance.${instance_id}' AND name='admin'")" == '0' ]] || fail "completed WordPress operation retained its retry-only administrator secret"
[[ "$(db "SELECT COUNT(*) FROM notifications WHERE kind='wordpress_operation_failed' AND subscription_id=${subscription_id}")" =~ ^[0-9]+$ ]] || fail "WordPress failure notification query is unavailable"
[[ "$(db "SELECT COUNT(*) FROM audit_events WHERE metadata::text ~* '(admin_password|database_password|${admin_password}|${reset_password})'")" == '0' ]] || fail "WordPress audit metadata exposes credentials"
service_logs="$(multipass_exec_short "${VM_NAME}" -- sudo journalctl -u nakpanel.service -u nakpanel-agent.service --no-pager --since '-30 minutes')"
for secret in "${admin_password}" "${reset_password}"; do
  [[ "${service_logs}" != *"${secret}"* ]] || fail "WordPress credential appears in service logs"
done

echo "phase32: detach tracking without deleting files and database"
database_id="$(db "SELECT database_id FROM wordpress_instances WHERE id=${instance_id}")"
post_as phase32-detach "sites/${site_id}/wordpress/detach" -d 'confirm=detach'
[[ "$(db "SELECT COUNT(*) FROM wordpress_instances WHERE id=${instance_id}")" == '0' ]] || fail "WordPress instance remains after detach"
[[ "$(db "SELECT COUNT(*) FROM wordpress_operations WHERE instance_id=${instance_id}")" == '0' ]] || fail "WordPress operation history remains after detach"
[[ "$(db "SELECT COUNT(*) FROM service_secrets WHERE scope='wordpress.instance.${instance_id}' AND name='admin'")" == '0' ]] || fail "WordPress Toolkit secret remains after detach"
[[ "$(db "SELECT status FROM databases WHERE id=${database_id}")" == 'active' ]] || fail "detach changed the WordPress database"
multipass_exec_short "${VM_NAME}" -- sudo test -f "${document_root}/wp-load.php" || fail "detach deleted WordPress files and database state"

echo "phase32: rediscover complete WordPress identity from hosted state"
post_as phase32-rediscover "sites/${site_id}/wordpress/operations" -d 'action=discover'
wait_for 'WordPress rediscovery operation' "SELECT status FROM wordpress_operations WHERE instance_id=(SELECT id FROM wordpress_instances WHERE site_id=${site_id}) AND kind='discover' ORDER BY id DESC LIMIT 1" 'succeeded'
rediscovered_instance_id="$(db "SELECT id FROM wordpress_instances WHERE site_id=${site_id}")"
wait_for 'WordPress rediscovery state' "SELECT observed_state||':'||convergence_status||':'||installed_version FROM wordpress_instances WHERE id=${rediscovered_instance_id}" 'healthy:in_sync:7.1'
rediscovered_identity="$(db "SELECT site_title||':'||admin_user||':'||admin_email FROM wordpress_instances WHERE id=${rediscovered_instance_id}")"
[[ "${rediscovered_identity}" == "Phase 32 WordPress:siteadmin:${customer_email}" ]] || fail "discovery did not restore WordPress identity: ${rediscovered_identity}"
post_as phase32-rediscover-detach "sites/${site_id}/wordpress/detach" -d 'confirm=detach'
[[ "$(db "SELECT COUNT(*) FROM wordpress_instances WHERE id=${rediscovered_instance_id}")" == '0' ]] || fail "rediscovered WordPress instance remains after final detach"

PHASE32_COMPLETE=1
echo "Phase 32 WordPress Toolkit verification passed for ${VM_NAME} (${VM_IP})."
