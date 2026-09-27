#!/usr/bin/env bash
# Phase 33 safe WordPress uninstall acceptance. Product routes create all
# WordPress intent; SQL and MariaDB access below is inspection-only.
set -euo pipefail
trap 'status=$?; echo "phase33 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
PHASE33_COMPLETE=0

fail(){ echo "phase33: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
maria(){ multipass_exec_short "${VM_NAME}" -- sudo mariadb --batch --skip-column-names -e "$1" | tr -d '\r'; }

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${SCRIPT_DIR}/phase32-verify.sh"
fi

require_nakpanel_vm_name "${VM_NAME}"
for tool in curl python3; do
  command -v "${tool}" >/dev/null 2>&1 || fail "host prerequisite ${tool} is not installed"
done

tmpdir="$(mktemp -d)"
cleanup_phase33(){
  local status=$?
  multipass_exec_short "${VM_NAME}" -- sudo systemctl start mariadb.service >/dev/null 2>&1 || true
  multipass_exec_short "${VM_NAME}" -- sudo systemctl start nakpanel.service >/dev/null 2>&1 || true
  if [[ "${PHASE33_COMPLETE}" != "1" && "${status}" -eq 0 ]]; then
    status=1
  fi
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup_phase33 EXIT

wait_for(){
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 180); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "${label}: got ${value:-empty}, want ${expected}"
}

wait_for_river_failure(){
  local operation_id="$1" value=""
  for _ in $(seq 1 180); do
    value="$(db "SELECT state FROM river_job WHERE kind='wordpress_operation' AND args->>'operation_id'='${operation_id}' ORDER BY id DESC LIMIT 1")"
    case "${value}" in
      retryable|cancelled|discarded) return 0 ;;
    esac
    sleep 1
  done
  fail "database-removal failure was not observed in River: ${value:-empty}"
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

post_json(){
  local label="$1" endpoint="$2"
  shift 2
  local status
  status="$(curl --connect-timeout 5 --max-time 30 -sk -o "${tmpdir}/${label}.json" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    -H 'X-Nakpanel-SPA: true' -H 'Accept: application/json' \
    "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "202" ]] || {
    echo "${label} returned HTTP ${status}, want 202" >&2
    cat "${tmpdir}/${label}.json" >&2
    exit 1
  }
}

echo "phase33: install the current safe-uninstall build"
sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
src="$1"
cd "${src}"
timeout 45m deploy/install/install.sh --yes --allow-downgrade --force
systemctl is-active --quiet nakpanel.service
systemctl is-active --quiet nakpanel-agent.service
systemctl is-active --quiet mariadb.service
REMOTE

VM_IP="$(vm_ip)"
[[ -n "${VM_IP}" ]] || fail "could not determine ${VM_NAME} IPv4 address"
for _ in $(seq 1 180); do
  curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null && break
  sleep 2
done
curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null || fail "current panel is not healthy"

schema_contract="$(db "SELECT (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='wordpress_instances' AND column_name='database_managed')||':'||(SELECT COUNT(*) FROM information_schema.columns WHERE table_name='backups' AND column_name='database_names')")"
[[ "${schema_contract}" == '1:1' ]] || fail "Phase 33 schema contract is incomplete: ${schema_contract}"

curl --connect-timeout 5 --max-time 30 -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/admin.html"
grep -q 'data-np-role="admin"' "${tmpdir}/admin.html" || fail "admin login failed"

run_id="$(date +%s)-$$"
plan_name="Phase33 Safe Removal ${run_id}"
customer_email="phase33-${run_id}@nakpanel.test"
managed_domain="phase33-${run_id}.test"
rollback_domain="phase33-rollback-${run_id}.test"
admin_password="WordPress-Phase33-${run_id}!"
start_epoch="$(date +%s)"

echo "phase33: create an entitled customer with two isolated Classic sites"
post_as phase33-plan plans \
  -d 'plan_id=0' -d "name=${plan_name}" -d 'description=Safe WordPress uninstall acceptance plan' \
  -d 'lifecycle_status=active' -d 'change_reason=Phase 33 acceptance' \
  -d 'disk_mb=-1' -d 'bandwidth_mb=-1' -d 'max_sites=2' -d 'max_databases=2' \
  -d 'max_mailboxes=0' -d 'max_backups=6' -d 'backup_storage_mb=6144' \
  -d 'site_disk_quota_mb=-1' -d 'php_allowlist=8.4' -d 'php_versions=8.4' \
  -d 'default_php_version=8.4' -d 'php_max_children=4' -d 'php_memory_mb=256' \
  -d 'hosting_enabled=true' -d 'allow_tls=true' -d 'allow_backups=true' \
  -d 'allow_php_settings=true' -d 'allow_logs=true' -d 'php_opcache_enabled=true' \
  -d 'php_log_errors=true' -d 'allow_wordpress_toolkit=true' -d 'max_wordpress_sites=2' \
  -d 'overuse_policy=block' -d 'validity_days=-1'
plan_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND name='${plan_name}'")"
post_as phase33-customer customers -d "customer_email=${customer_email}" -d "customer_name=Phase 33 ${run_id}" -d 'company=Nakpanel Acceptance'
customer_id="$(db "SELECT id FROM customers WHERE email='${customer_email}'")"
post_as phase33-subscription subscriptions -d 'customer_mode=existing' -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d "subscription_name=Safe Removal ${run_id}"
subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='Safe Removal ${run_id}'")"
wait_for 'Phase 33 entitlement synchronization' "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" 'in_sync'

post_as phase33-managed-site sites -d "subscription_id=${subscription_id}" -d "domain=${managed_domain}"
managed_site_id="$(db "SELECT id FROM sites WHERE domain='${managed_domain}'")"
wait_for 'managed site provisioning' "SELECT status FROM sites WHERE id=${managed_site_id}" 'active'
username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")"
managed_root="$(db "SELECT document_root FROM sites WHERE id=${managed_site_id}")"

echo "phase33: install content and request backup-gated managed removal"
post_as phase33-install "sites/${managed_site_id}/wordpress/install" \
  -d 'site_title=Phase 33 WordPress' -d 'admin_user=siteadmin' \
  -d "admin_email=${customer_email}" -d "admin_password=${admin_password}" -d 'version=7.1'
managed_instance_id="$(db "SELECT id FROM wordpress_instances WHERE site_id=${managed_site_id}")"
wait_for 'managed WordPress install' "SELECT status FROM wordpress_operations WHERE instance_id=${managed_instance_id} AND kind='install' ORDER BY id DESC LIMIT 1" 'succeeded'
wait_for 'managed WordPress health' "SELECT observed_state||':'||convergence_status FROM wordpress_instances WHERE id=${managed_instance_id}" 'healthy:in_sync'
managed_database_id="$(db "SELECT database_id FROM wordpress_instances WHERE id=${managed_instance_id}")"
managed_database="$(db "SELECT db_name FROM databases WHERE id=${managed_database_id}")"
managed_database_user="$(db "SELECT db_user FROM databases WHERE id=${managed_database_id}")"
wordpress_usage_before="$(db "SELECT COUNT(*) FROM wordpress_instances WHERE subscription_id=${subscription_id} AND observed_state<>'removed' AND NOT (installed_version='' AND observed_state='failed')")"

multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp post create --path="${managed_root}" --post_title='Phase 33 recovery post' --post_status=publish --porcelain >/dev/null
multipass_exec_short "${VM_NAME}" -- sudo bash -c "printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=' | base64 -d >/tmp/phase33-pixel.png"
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp media import /tmp/phase33-pixel.png --path="${managed_root}" --title='Phase 33 recovery media' --porcelain >/dev/null

site_contract_before="$(db "SELECT status||':'||tls_status||':'||subscription_id FROM sites WHERE id=${managed_site_id}")"
dns_contract_before="$(db "SELECT COUNT(*) FROM dns_zones WHERE site_id=${managed_site_id}")"
post_json phase33-managed-uninstall "sites/${managed_site_id}/wordpress/uninstall" \
  -d 'create_backup=on' -d 'delete_database=on' -d "confirm_domain=${managed_domain}"
grep -Fq '"status":"waiting_backup"' "${tmpdir}/phase33-managed-uninstall.json" || fail "uninstall did not enter waiting_backup"
managed_operation_id="$(db "SELECT id FROM wordpress_operations WHERE instance_id=${managed_instance_id} AND kind='uninstall' ORDER BY id DESC LIMIT 1")"
managed_backup_id="$(db "SELECT backup_id FROM wordpress_operations WHERE id=${managed_operation_id}")"
wait_for 'managed safety backup' "SELECT status FROM backups WHERE id=${managed_backup_id}" 'active'
backup_contract="$(db "SELECT (size_bytes>0)::text||':'||(checksum_sha256<>'')::text||':'||(database_names @> ARRAY['${managed_database}']::text[])::text FROM backups WHERE id=${managed_backup_id}")"
[[ "${backup_contract}" == 'true:true:true' ]] || fail "managed safety backup is incomplete: ${backup_contract}"
wait_for 'managed WordPress removal' "SELECT observed_state||':'||convergence_status FROM wordpress_instances WHERE id=${managed_instance_id}" 'removed:in_sync'

echo "phase33: verify WordPress removal and hosted-domain preservation"
if multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp core is-installed --path="${managed_root}" >/dev/null 2>&1; then
  fail "WordPress files remain after removal"
fi
[[ "$(maria "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${managed_database}'")" == '0' ]] || fail "managed WordPress database remains"
[[ "$(maria "SELECT COUNT(*) FROM mysql.user WHERE User='${managed_database_user}' AND Host='localhost'")" == '0' ]] || fail "managed WordPress database principal remains"
curl --connect-timeout 5 --max-time 30 -sf -H "Host: ${managed_domain}" "http://${VM_IP}/" -o "${tmpdir}/placeholder.html"
grep -Fqi 'Nakpanel' "${tmpdir}/placeholder.html" || fail "domain does not serve the Nakpanel placeholder"
[[ "$(db "SELECT status||':'||tls_status||':'||subscription_id FROM sites WHERE id=${managed_site_id}")" == "${site_contract_before}" ]] || fail "site/TLS/subscription intent changed during uninstall"
[[ "$(db "SELECT COUNT(*) FROM dns_zones WHERE site_id=${managed_site_id}")" == "${dns_contract_before}" ]] || fail "DNS intent changed during uninstall"
wordpress_usage_after="$(db "SELECT COUNT(*) FROM wordpress_instances WHERE subscription_id=${subscription_id} AND observed_state<>'removed' AND NOT (installed_version='' AND observed_state='failed')")"
[[ "$((wordpress_usage_before - wordpress_usage_after))" == '1' ]] || fail "WordPress allocation did not decrease exactly once after removal"
[[ "$(db "SELECT COUNT(*) FROM databases WHERE id=${managed_database_id}")" == '0' ]] || fail "managed database intent remains after removal"
quarantine="$(multipass_exec_short "${VM_NAME}" -- sudo find "$(dirname "${managed_root}")" -maxdepth 1 -name '.nakpanel-wordpress-removed-*' -print -quit | tr -d '\r')"
[[ -z "${quarantine}" ]] || fail "WordPress quarantine cleanup did not converge"

echo "phase33: reinstall through the preserved tombstone"
revision_before="$(db "SELECT desired_revision FROM wordpress_instances WHERE id=${managed_instance_id}")"
post_as phase33-reinstall "sites/${managed_site_id}/wordpress/install" \
  -d 'site_title=Phase 33 Reinstalled' -d 'admin_user=siteadmin' \
  -d "admin_email=${customer_email}" -d "admin_password=${admin_password}" -d 'version=7.1'
wait_for 'WordPress reinstall' "SELECT status FROM wordpress_operations WHERE instance_id=${managed_instance_id} AND kind='install' ORDER BY id DESC LIMIT 1" 'succeeded'
revision_after="$(db "SELECT desired_revision FROM wordpress_instances WHERE id=${managed_instance_id}")"
[[ "${revision_after}" -gt "${revision_before}" ]] || fail "desired_revision did not advance on reinstall"
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp core verify-checksums --path="${managed_root}" --no-color

echo "phase33: prove a discovered external database is preserved"
external_site_id="${managed_site_id}"
external_domain="${managed_domain}"
external_root="${managed_root}"
external_database_id="$(db "SELECT database_id FROM wordpress_instances WHERE id=${managed_instance_id}")"
external_database="$(db "SELECT db_name FROM databases WHERE id=${external_database_id}")"
external_database_user="$(db "SELECT db_user FROM databases WHERE id=${external_database_id}")"
post_as phase33-external-detach "sites/${external_site_id}/wordpress/detach" -d 'confirm=detach'
[[ "$(db "SELECT COUNT(*) FROM wordpress_instances WHERE site_id=${external_site_id}")" == '0' ]] || fail "detached WordPress tracking remains"
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp core is-installed --path="${external_root}" --no-color
post_as phase33-external-discover "sites/${external_site_id}/wordpress/operations" -d 'action=discover'
external_instance_id="$(db "SELECT id FROM wordpress_instances WHERE site_id=${external_site_id}")"
wait_for 'external WordPress discovery' "SELECT status FROM wordpress_operations WHERE instance_id=${external_instance_id} AND kind='discover' ORDER BY id DESC LIMIT 1" 'succeeded'
[[ "$(db "SELECT database_managed::text FROM wordpress_instances WHERE id=${external_instance_id}")" == 'false' ]] || fail "discovered database was incorrectly marked Toolkit-managed"
post_json phase33-external-uninstall "sites/${external_site_id}/wordpress/uninstall" \
  -d 'create_backup=on' -d "confirm_domain=${external_domain}"
external_operation_id="$(db "SELECT id FROM wordpress_operations WHERE instance_id=${external_instance_id} AND kind='uninstall' ORDER BY id DESC LIMIT 1")"
wait_for 'external WordPress removal' "SELECT observed_state||':'||convergence_status FROM wordpress_instances WHERE id=${external_instance_id}" 'removed:in_sync'
[[ "$(maria "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${external_database}'")" == '1' ]] || fail "discovered external database was deleted"
[[ "$(maria "SELECT COUNT(*) FROM mysql.user WHERE User='${external_database_user}' AND Host='localhost'")" == '1' ]] || fail "discovered external database principal was deleted"
echo "phase33: external database preserved"

echo "phase33: exercise deterministic database-removal failure rollback"
post_as phase33-rollback-site sites -d "subscription_id=${subscription_id}" -d "domain=${rollback_domain}"
rollback_site_id="$(db "SELECT id FROM sites WHERE domain='${rollback_domain}'")"
wait_for 'rollback site provisioning' "SELECT status FROM sites WHERE id=${rollback_site_id}" 'active'
rollback_root="$(db "SELECT document_root FROM sites WHERE id=${rollback_site_id}")"
post_as phase33-rollback-install "sites/${rollback_site_id}/wordpress/install" \
  -d 'site_title=Phase 33 Rollback' -d 'admin_user=siteadmin' \
  -d "admin_email=${customer_email}" -d "admin_password=${admin_password}" -d 'version=7.1'
rollback_instance_id="$(db "SELECT id FROM wordpress_instances WHERE site_id=${rollback_site_id}")"
wait_for 'rollback WordPress install' "SELECT status FROM wordpress_operations WHERE instance_id=${rollback_instance_id} AND kind='install' ORDER BY id DESC LIMIT 1" 'succeeded'
post_json phase33-rollback-uninstall "sites/${rollback_site_id}/wordpress/uninstall" \
  -d 'create_backup=on' -d 'delete_database=on' -d "confirm_domain=${rollback_domain}"
rollback_operation_id="$(db "SELECT id FROM wordpress_operations WHERE instance_id=${rollback_instance_id} AND kind='uninstall' ORDER BY id DESC LIMIT 1")"
rollback_backup_id="$(db "SELECT backup_id FROM wordpress_operations WHERE id=${rollback_operation_id}")"
wait_for 'rollback safety backup' "SELECT status FROM backups WHERE id=${rollback_backup_id}" 'active'
multipass_exec_short "${VM_NAME}" -- sudo systemctl stop nakpanel.service
multipass_exec_short "${VM_NAME}" -- sudo systemctl stop mariadb.service
multipass_exec_short "${VM_NAME}" -- sudo systemctl start nakpanel.service
wait_for_river_failure "${rollback_operation_id}"
multipass_exec_short "${VM_NAME}" -- sudo systemctl stop nakpanel.service
multipass_exec_short "${VM_NAME}" -- sudo systemctl start mariadb.service
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" wp core is-installed --path="${rollback_root}" --no-color
curl --connect-timeout 5 --max-time 30 -sf -H "Host: ${rollback_domain}" "http://${VM_IP}/" >/dev/null || fail "original site remains available check failed"
echo "phase33: database-removal failure proved the original site remains available"
multipass_exec_short "${VM_NAME}" -- sudo systemctl start nakpanel.service

echo "phase33: prove removal orchestration is secret-free"
river_payloads="$(db "SELECT COALESCE(string_agg(args::text,'|'),'') FROM river_job WHERE kind IN ('wordpress_operation','cleanup_wordpress_removal') AND created_at >= to_timestamp(${start_epoch})")"
audit_payloads="$(db "SELECT COALESCE(string_agg(metadata::text,'|'),'') FROM audit_events WHERE created_at >= to_timestamp(${start_epoch}) AND action LIKE 'wordpress.%'")"
service_logs="$(multipass_exec_short "${VM_NAME}" -- sudo journalctl -u nakpanel.service -u nakpanel-agent.service --no-pager --since "@${start_epoch}")"
workspace_status="$(curl --connect-timeout 5 --max-time 30 -sk -o "${tmpdir}/wordpress.html" -w '%{http_code}' -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${managed_site_id}/wordpress")"
[[ "${workspace_status}" == '200' ]] || fail "WordPress workspace returned HTTP ${workspace_status}"
combined_safe_output="${river_payloads}${audit_payloads}$(cat "${tmpdir}/wordpress.html")$(cat "${tmpdir}/phase33-managed-uninstall.json")"
control_plane_output="${river_payloads}${audit_payloads}${service_logs}$(cat "${tmpdir}/phase33-managed-uninstall.json")"
for forbidden in 'database_password' 'admin_password' 'archive_path'; do
  [[ "${control_plane_output}" != *"${forbidden}"* ]] || fail "WordPress removal control-plane output exposes ${forbidden}"
done
for forbidden in "${admin_password}" '/home/' '.nakpanel-wordpress-removed-' 'quarantine'; do
  [[ "${combined_safe_output}" != *"${forbidden}"* ]] || fail "WordPress removal output exposes ${forbidden}"
done
for forbidden in "${admin_password}" 'archive_path' '.nakpanel-wordpress-removed-' 'quarantine'; do
  [[ "${service_logs}" != *"${forbidden}"* ]] || fail "WordPress removal service logs expose ${forbidden}"
done
[[ "$(db "SELECT COUNT(*) FROM audit_events WHERE created_at >= to_timestamp(${start_epoch}) AND action='wordpress.uninstall.completed' AND metadata ? 'database_removed'")" -ge 2 ]] || fail "uninstall audit evidence is incomplete"

PHASE33_COMPLETE=1
echo "Phase 33 safe WordPress uninstall verification passed for ${VM_NAME} (${VM_IP})."
