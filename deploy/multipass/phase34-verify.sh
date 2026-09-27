#!/usr/bin/env bash
# Product-route acceptance for domain-scoped GoAccess reports on the shared lab.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
require_nakpanel_vm_name "${VM_NAME}"
if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != 1 ]]; then
  "${SCRIPT_DIR}/phase33-verify.sh"
fi
tmpdir="$(mktemp -d)"
cleanup(){ rm -rf "${tmpdir}"; }
trap cleanup EXIT
fail(){ echo "phase34: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){
  local query="$1" expected="$2" value=""
  for _ in $(seq 1 120); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "timed out waiting for ${expected}; observed ${value:-empty}"
}
post(){
  local endpoint="$1" status
  shift
  status="$(curl -sk --connect-timeout 5 --max-time 30 -o "${tmpdir}/post.out" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == 303 || "${status}" == 202 ]] || {
    cat "${tmpdir}/post.out" >&2
    fail "${endpoint} returned HTTP ${status}"
  }
}

echo 'phase34: install the current report implementation'
sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
cd "$1"
timeout 45m deploy/install/install.sh --yes --allow-downgrade --force
goaccess --version
systemctl is-active --quiet nakpanel.service
systemctl is-active --quiet nakpanel-agent.service
REMOTE
VM_IP="$(vm_ip)"
[[ -n "${VM_IP}" ]] || fail 'lab IP is unavailable'
curl -skf --connect-timeout 5 --max-time 30 "https://${VM_IP}:7443/healthz" >/dev/null
curl -skfL --connect-timeout 5 --max-time 30 -c "${tmpdir}/admin.cookies" \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/admin.html"
grep -q 'data-np-role="admin"' "${tmpdir}/admin.html" || fail 'admin login failed'
run_id="$(date +%s)-$$"
plan_name="Phase34 Statistics ${run_id}"
domain="phase34-${run_id}.test"
customer_email="phase34-${run_id}@nakpanel.test"
post plans -d 'plan_id=0' -d "name=${plan_name}" -d 'lifecycle_status=active' \
  -d 'change_reason=GoAccess acceptance' -d 'disk_mb=-1' -d 'bandwidth_mb=-1' \
  -d 'max_sites=1' -d 'max_databases=0' -d 'max_mailboxes=0' -d 'max_backups=0' \
  -d 'backup_storage_mb=0' -d 'site_disk_quota_mb=-1' -d 'php_allowlist=8.4' \
  -d 'php_versions=8.4' -d 'default_php_version=8.4' -d 'php_max_children=2' \
  -d 'php_memory_mb=256' -d 'hosting_enabled=true' -d 'allow_logs=true' \
  -d 'allow_web_statistics=true' -d 'logs_statistics_engine=goaccess' \
  -d 'logs_retention_days=14' -d 'logs_rotation_enabled=true' \
  -d 'overuse_policy=block' -d 'validity_days=-1'
plan_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND name='${plan_name}'")"
post customers -d "customer_email=${customer_email}" -d "customer_name=Statistics ${run_id}" \
  -d 'enable_login=true' -d 'password=NakpanelStatistics!2026'
customer_id="$(db "SELECT id FROM customers WHERE email='${customer_email}'")"
post subscriptions -d 'customer_mode=existing' -d "customer_id=${customer_id}" \
  -d "plan_id=${plan_id}" -d "subscription_name=Statistics ${run_id}"
subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='Statistics ${run_id}'")"
wait_for "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" in_sync
post sites -d "subscription_id=${subscription_id}" -d "domain=${domain}"
site_id="$(db "SELECT id FROM sites WHERE domain='${domain}'")"
wait_for "SELECT status FROM sites WHERE id=${site_id}" active

echo 'phase34: generate real nginx traffic and refresh through the domain'
for path in '/' '/missing-statistics-page?token=privacy-fixture'; do
  curl -s --connect-timeout 5 --max-time 15 -H "Host: ${domain}" \
    -H 'Referer: https://ref.example.test/path?key=referrer-fixture' \
    -A 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0' \
    "http://${VM_IP}${path}" >/dev/null
done
post "sites/${site_id}/statistics/refresh" -d 'refresh=true'
wait_for "SELECT (report_generation>0)::text FROM site_web_statistics WHERE site_id=${site_id}" true
status="$(curl -sk --connect-timeout 5 --max-time 30 -b "${tmpdir}/admin.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" -H 'Accept: application/json' \
  -H 'X-Nakpanel-SPA: true' -d 'refresh=true' -o /dev/null -w '%{http_code}' \
  "https://${VM_IP}:7443/sites/${site_id}/statistics/refresh")"
[[ "${status}" == 429 ]] || fail "repeated refresh was not rate-limited: ${status}"
status="$(curl -sk --connect-timeout 5 --max-time 30 -b "${tmpdir}/admin.cookies" \
  -d 'refresh=true' -o /dev/null -w '%{http_code}' "https://${VM_IP}:7443/sites/${site_id}/statistics/refresh")"
[[ "${status}" == 403 ]] || fail "refresh without CSRF was not rejected: ${status}"
curl -skf --connect-timeout 5 --max-time 30 -b "${tmpdir}/admin.cookies" \
  -D "${tmpdir}/report.headers" "https://${VM_IP}:7443/sites/${site_id}/statistics/report" -o "${tmpdir}/report.html"
grep -qi 'Content-Security-Policy:.*sandbox' "${tmpdir}/report.headers" || fail 'report is not sandboxed'
if grep -qi 'Content-Security-Policy:.*allow-same-origin' "${tmpdir}/report.headers"; then fail 'report has panel origin privileges'; fi
grep -qi 'GoAccess' "${tmpdir}/report.html" || fail 'detailed report is not GoAccess'
for secret in privacy-fixture referrer-fixture; do
  if grep -Fq "${secret}" "${tmpdir}/report.html"; then fail 'query-string secret leaked into report'; fi
done
curl -skf --connect-timeout 5 --max-time 30 -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/sites/${site_id}/statistics" -o "${tmpdir}/workspace.html"
grep -qi 'GoAccess' "${tmpdir}/workspace.html" || fail 'domain statistics workspace is missing'
curl -skf --connect-timeout 5 --max-time 30 -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/tools-settings/web-statistics" -o "${tmpdir}/settings.html"
grep -qi 'retention' "${tmpdir}/settings.html" || fail 'server statistics settings are missing'

echo 'phase34: verify owned reports and cross-customer denial'
curl -skfL --connect-timeout 5 --max-time 30 -c "${tmpdir}/owner.cookies" \
  -d "email=${customer_email}" -d 'password=NakpanelStatistics!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/owner.html"
curl -skf --connect-timeout 5 --max-time 30 -b "${tmpdir}/owner.cookies" \
  "https://${VM_IP}:7443/sites/${site_id}/statistics/report" >/dev/null
curl -skfL --connect-timeout 5 --max-time 30 -c "${tmpdir}/client.cookies" \
  -d 'email=client@nakpanel.test' -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/client.html"
for endpoint in "sites/${site_id}/statistics" "sites/${site_id}/statistics/report"; do
  status="$(curl -sk --connect-timeout 5 --max-time 30 -b "${tmpdir}/client.cookies" \
    -o /dev/null -w '%{http_code}' "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == 404 ]] || fail "cross-customer ${endpoint} returned ${status}"
done
status="$(curl -sk --connect-timeout 5 --max-time 30 -b "${tmpdir}/client.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/client.cookies")" -d 'enabled=true' \
  -o /dev/null -w '%{http_code}' "https://${VM_IP}:7443/tools-settings/web-statistics")"
[[ "${status}" == 403 ]] || fail "customer server settings write returned ${status}, want 403"
status="$(curl -sk --connect-timeout 5 --max-time 30 -o /dev/null -w '%{http_code}' \
  "https://${VM_IP}:7443/sites/${site_id}/statistics/report")"
[[ "${status}" == 303 || "${status}" == 302 || "${status}" == 401 ]] || fail 'anonymous report access was not denied'
echo "Phase 34 GoAccess verification passed for ${VM_NAME} (${VM_IP}), site ${site_id}."
