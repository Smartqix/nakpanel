#!/usr/bin/env bash
# Non-destructive V2 website journey against an already installed lab VM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
VM_IP="$(vm_ip)"
RUN_ID="${V2_RUN_ID:-$(date +%s)}"
PLAN_NAME="V2 Journey ${RUN_ID}"
SUB_NAME="V2 Journey ${RUN_ID}"
DOMAIN="v2-wp-${RUN_ID}.test"
CLIENT_DOMAIN="v2-client-${RUN_ID}.test"
TMP_DIR="$(mktemp -d)"

cleanup() {
  find "${TMP_DIR}" -type f -delete
  rmdir "${TMP_DIR}"
}
trap cleanup EXIT

fail() { echo "v2 journey: $*" >&2; exit 1; }
db() { multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }

wait_for() {
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 180); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    [[ "${value}" == failed* ]] && fail "${label}: ${value}"
    sleep 2
  done
  fail "${label}: got ${value:-empty}, want ${expected}"
}

post() {
  local cookie="$1" output="$2" endpoint="$3"
  shift 3
  curl --connect-timeout 5 --max-time 30 -sk -o "${output}" -w '%{http_code}' \
    -b "${cookie}" -c "${cookie}" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${cookie}")" \
    "$@" "https://${VM_IP}:7443/${endpoint}"
}

wp_cli() {
  multipass_exec_short "${VM_NAME}" -- sudo -u "${USERNAME}" bash -c \
    'cd "$1" || exit; shift; exec "$@"' _ "${DOCROOT}" wp "$@" --path="${DOCROOT}"
}

login() {
  local cookie="$1" email="$2" password="$3"
  local status
  status="$(curl --connect-timeout 5 --max-time 30 -sk -o /dev/null -w '%{http_code}' \
    -c "${cookie}" -d "email=${email}" -d "password=${password}" \
    "https://${VM_IP}:7443/login")"
  [[ "${status}" == 303 ]] || fail "${email} login returned ${status}"
}

create_wordpress() {
  local cookie="$1" domain="$2" label="$3"
  local status
  status="$(post "${cookie}" "${TMP_DIR}/${label}.json" websites \
    -H 'X-Nakpanel-SPA: true' -H 'Accept: application/json' \
    -d "subscription_id=${SUBSCRIPTION_ID}" -d "domain=${domain}" \
    -d 'website_type=wordpress' -d "site_title=V2 ${label}" \
    -d 'admin_user=siteadmin' -d "admin_email=v2-${RUN_ID}@nakpanel.test")"
  [[ "${status}" == 202 ]] || {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("error", "website creation failed"))' "${TMP_DIR}/${label}.json" >&2
    fail "${label} website creation returned ${status}"
  }
  python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r.get("admin_password") and r.get("site_id") and r.get("operation_id") and not r.get("partial"); print(r["site_id"])' "${TMP_DIR}/${label}.json"
}

require_multipass
[[ -n "${VM_IP}" ]] || fail "could not determine ${VM_NAME} IP"
curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null || fail "panel is unavailable"

login "${TMP_DIR}/admin.cookies" admin@nakpanel.test 'NakpanelAdmin!2026'
login "${TMP_DIR}/client.cookies" client@nakpanel.test 'NakpanelClient!2026'
CUSTOMER_ID="$(db "SELECT id FROM customers WHERE login_user_id=(SELECT id FROM users WHERE email='client@nakpanel.test')")"
[[ "${CUSTOMER_ID}" =~ ^[0-9]+$ ]] || fail "seeded test customer is missing"

echo "v2 journey: use isolated WordPress test plan and subscription"
PLAN_ID="$(db "SELECT id FROM plans WHERE name='${PLAN_NAME}'")"
if [[ -z "${PLAN_ID}" ]]; then
  status="$(post "${TMP_DIR}/admin.cookies" "${TMP_DIR}/plan.out" plans \
  -d 'plan_id=0' -d "name=${PLAN_NAME}" -d 'description=Disposable V2 hosting journey' \
  -d 'lifecycle_status=active' -d 'change_reason=V2 acceptance' \
  -d 'disk_mb=-1' -d 'bandwidth_mb=-1' -d 'max_sites=2' -d 'max_databases=2' \
  -d 'max_mailboxes=0' -d 'max_backups=4' -d 'backup_storage_mb=4096' \
  -d 'site_disk_quota_mb=-1' -d 'php_allowlist=8.4' -d 'php_versions=8.4' \
  -d 'default_php_version=8.4' -d 'php_max_children=4' -d 'php_memory_mb=256' \
  -d 'hosting_enabled=true' -d 'allow_tls=true' -d 'allow_backups=true' \
  -d 'allow_php_settings=true' -d 'allow_logs=true' -d 'php_opcache_enabled=true' \
  -d 'php_log_errors=true' -d 'allow_wordpress_toolkit=true' -d 'max_wordpress_sites=2' \
  -d 'overuse_policy=block' -d 'validity_days=-1')"
  [[ "${status}" == 303 ]] || fail "plan creation returned ${status}"
  PLAN_ID="$(db "SELECT id FROM plans WHERE name='${PLAN_NAME}'")"
fi
[[ "${PLAN_ID}" =~ ^[0-9]+$ ]] || fail "plan was not saved"

SUBSCRIPTION_ID="$(db "SELECT id FROM subscriptions WHERE customer_id=${CUSTOMER_ID} AND name='${SUB_NAME}'")"
if [[ -z "${SUBSCRIPTION_ID}" ]]; then
  status="$(post "${TMP_DIR}/admin.cookies" "${TMP_DIR}/subscription.out" subscriptions \
    -d 'customer_mode=existing' -d "customer_id=${CUSTOMER_ID}" \
    -d "plan_id=${PLAN_ID}" -d "subscription_name=${SUB_NAME}")"
  [[ "${status}" == 303 ]] || fail "subscription creation returned ${status}"
  SUBSCRIPTION_ID="$(db "SELECT id FROM subscriptions WHERE customer_id=${CUSTOMER_ID} AND name='${SUB_NAME}'")"
fi
[[ "${SUBSCRIPTION_ID}" =~ ^[0-9]+$ ]] || fail "subscription was not saved"
wait_for 'entitlement synchronization' "SELECT sync_status FROM subscriptions WHERE id=${SUBSCRIPTION_ID}" in_sync

echo "v2 journey: verify WordPress created from the V2 administrator flow"
SITE_ID="$(db "SELECT id FROM sites WHERE domain='${DOMAIN}' AND subscription_id=${SUBSCRIPTION_ID}")"
if [[ -z "${SITE_ID}" ]]; then
  SITE_ID="$(create_wordpress "${TMP_DIR}/admin.cookies" "${DOMAIN}" admin)"
fi
[[ "${SITE_ID}" =~ ^[0-9]+$ ]] || fail "administrator site is missing"
wait_for 'admin site provisioning' "SELECT status FROM sites WHERE id=${SITE_ID}" active
wait_for 'admin WordPress installation' "SELECT operation.status FROM wordpress_operations operation JOIN wordpress_instances instance ON instance.id=operation.instance_id WHERE instance.site_id=${SITE_ID} AND operation.kind='install' ORDER BY operation.id DESC LIMIT 1" succeeded
wait_for 'admin WordPress convergence' "SELECT observed_state||':'||convergence_status FROM wordpress_instances WHERE site_id=${SITE_ID}" healthy:in_sync

echo "v2 journey: verify WordPress created from the same flow as the customer"
CLIENT_SITE_ID="$(db "SELECT id FROM sites WHERE domain='${CLIENT_DOMAIN}' AND subscription_id=${SUBSCRIPTION_ID}")"
if [[ -z "${CLIENT_SITE_ID}" ]]; then
  CLIENT_SITE_ID="$(create_wordpress "${TMP_DIR}/client.cookies" "${CLIENT_DOMAIN}" client)"
fi
[[ "${CLIENT_SITE_ID}" =~ ^[0-9]+$ ]] || fail "customer site is missing"
wait_for 'client site provisioning' "SELECT status FROM sites WHERE id=${CLIENT_SITE_ID}" active
wait_for 'client WordPress installation' "SELECT operation.status FROM wordpress_operations operation JOIN wordpress_instances instance ON instance.id=operation.instance_id WHERE instance.site_id=${CLIENT_SITE_ID} AND operation.kind='install' ORDER BY operation.id DESC LIMIT 1" succeeded
wait_for 'client WordPress convergence' "SELECT observed_state||':'||convergence_status FROM wordpress_instances WHERE site_id=${CLIENT_SITE_ID}" healthy:in_sync

echo "v2 journey: verify account-owned WordPress and frontend"
USERNAME="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${SUBSCRIPTION_ID}")"
DOCROOT="$(db "SELECT document_root FROM sites WHERE id=${SITE_ID}")"
[[ -n "${USERNAME}" && -n "${DOCROOT}" ]] || fail "subscription account or document root missing"
wp_cli core verify-checksums --no-color
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%a' "${DOCROOT}/wp-config.php" | tr -d '\r')" == 600 ]] || fail "wp-config.php is not private"
[[ "$(wp_cli option get home | tr -d '\r')" == "http://${DOMAIN}" ]] || fail "WordPress points to HTTPS before a certificate is active"
curl --connect-timeout 5 --max-time 30 -sf --resolve "${DOMAIN}:80:${VM_IP}" "http://${DOMAIN}/" -o "${TMP_DIR}/admin-home.html" || fail "admin WordPress frontend is unavailable"
grep -Fq 'V2 admin' "${TMP_DIR}/admin-home.html" || fail "admin WordPress title is missing"
curl --connect-timeout 5 --max-time 30 -sf --resolve "${CLIENT_DOMAIN}:80:${VM_IP}" "http://${CLIENT_DOMAIN}/" -o "${TMP_DIR}/client-home.html" || fail "client WordPress frontend is unavailable"
grep -Fq 'V2 client' "${TMP_DIR}/client-home.html" || fail "client WordPress title is missing"
[[ "$(curl --connect-timeout 5 --max-time 30 -s -o /dev/null -w '%{http_code}' --resolve "${DOMAIN}:80:${VM_IP}" "http://${DOMAIN}/wp-admin/")" == 302 ]] || fail "WordPress administrator login is unavailable"

if [[ -f "${TMP_DIR}/admin.json" ]]; then
  ADMIN_PASSWORD="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["admin_password"])' "${TMP_DIR}/admin.json")"
else
  ADMIN_PASSWORD="$(openssl rand -hex 18)Aa!"
  status="$(post "${TMP_DIR}/admin.cookies" "${TMP_DIR}/password-reset.out" "sites/${SITE_ID}/wordpress/operations" \
    -d 'action=password_reset' -d "admin_password=${ADMIN_PASSWORD}")"
  [[ "${status}" == 303 ]] || fail "WordPress password reset returned ${status}"
  wait_for 'WordPress password reset' "SELECT status FROM wordpress_operations WHERE instance_id=(SELECT id FROM wordpress_instances WHERE site_id=${SITE_ID}) AND kind='password_reset' ORDER BY id DESC LIMIT 1" succeeded
fi
login_status="$(curl --connect-timeout 5 --max-time 30 -sSL --resolve "${DOMAIN}:80:${VM_IP}" \
  -b "${TMP_DIR}/wp.cookies" -c "${TMP_DIR}/wp.cookies" \
  -o "${TMP_DIR}/wp-admin.html" -w '%{http_code}' \
  --data-urlencode 'log=siteadmin' --data-urlencode "pwd=${ADMIN_PASSWORD}" \
  -d 'wp-submit=Log In' -d "redirect_to=http://${DOMAIN}/wp-admin/" \
  "http://${DOMAIN}/wp-login.php")"
ADMIN_PASSWORD=""
[[ "${login_status}" == 200 ]] || fail "WordPress administrator login returned ${login_status}"
grep -Fq 'wordpress_logged_in_' "${TMP_DIR}/wp.cookies" || fail "WordPress administrator session was not established"

echo "v2 journey: verify permalinks, media, plugin, and outbound HTTPS"
wp_cli rewrite structure '/%postname%/' --hard >/dev/null
page_slugs="$(wp_cli post list --post_type=page --post_status=publish --field=post_name)"
if ! grep -Fxq v2-clean <<<"${page_slugs}"; then
  wp_cli post create --post_type=page --post_status=publish \
    --post_title='V2 Clean Permalink' --post_name=v2-clean >/dev/null
fi
curl --connect-timeout 5 --max-time 30 -sf --resolve "${DOMAIN}:80:${VM_IP}" "http://${DOMAIN}/v2-clean/" -o "${TMP_DIR}/permalink.html" || fail "clean permalink did not render"
grep -Fq 'V2 Clean Permalink' "${TMP_DIR}/permalink.html" || fail "clean permalink title is missing"
multipass_exec_short "${VM_NAME}" -- sudo -u "${USERNAME}" bash -c \
  'cd "$2" || exit; printf %s iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII= | base64 -d >"$1"; wp media import "$1" --title="V2 media" --path="$2" --porcelain' \
  _ "${DOCROOT}/v2-media.png" "${DOCROOT}" >"${TMP_DIR}/media-id"
[[ "$(cat "${TMP_DIR}/media-id")" =~ ^[0-9]+$ ]] || fail "WordPress media import did not create an attachment"
wp_cli plugin activate hello >/dev/null
[[ "$(wp_cli plugin list --name=hello --field=status | tr -d '\r')" == active ]] || fail "WordPress plugin did not activate"
wp_cli eval '$r=wp_remote_get("https://api.wordpress.org/core/version-check/1.7/", ["timeout"=>20]); if (is_wp_error($r) || wp_remote_retrieve_response_code($r)!==200) { exit(1); }' >/dev/null

echo "v2 journey: verify site backup and restore"
wp_cli option update v2_restore_canary before >/dev/null
backup_output="$(multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel env \
  'NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  'NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock' \
  'NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json' \
  panelctl --actor v2-journey backup create "${DOMAIN}")"
BACKUP_ID="$(sed -nE 's/^Backup queued \(backup ([0-9]+)\)\.$/\1/p' <<<"${backup_output}")"
[[ "${BACKUP_ID}" =~ ^[0-9]+$ ]] || fail "backup could not be queued"
wait_for 'site backup' "SELECT status FROM backups WHERE id=${BACKUP_ID}" active
wp_cli option update v2_restore_canary after >/dev/null
multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel env \
  'NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  'NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock' \
  'NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json' \
  panelctl --actor v2-journey restore "${BACKUP_ID}" --yes >/dev/null
wait_for 'site restore' "SELECT status FROM restore_runs WHERE backup_id=${BACKUP_ID} ORDER BY id DESC LIMIT 1" active
[[ "$(wp_cli option get v2_restore_canary | tr -d '\r')" == before ]] || fail "restore did not recover WordPress database"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%a' "${DOCROOT}/wp-config.php" | tr -d '\r')" == 600 ]] || fail "restore exposed wp-config.php"

echo "v2 journey: verify customer ownership and plan limit"
[[ "$(curl --connect-timeout 5 --max-time 30 -sk -o /dev/null -w '%{http_code}' -b "${TMP_DIR}/client.cookies" "https://${VM_IP}:7443/sites/${SITE_ID}/wordpress")" == 200 ]] || fail "customer cannot see owned WordPress"
[[ "$(curl --connect-timeout 5 --max-time 30 -sk -o /dev/null -w '%{http_code}' -b "${TMP_DIR}/client.cookies" "https://${VM_IP}:7443/sites/58/wordpress")" == 404 ]] || fail "customer can see another subscription's WordPress"
limit_status="$(post "${TMP_DIR}/client.cookies" "${TMP_DIR}/limit.json" websites \
  -H 'X-Nakpanel-SPA: true' -H 'Accept: application/json' \
  -d "subscription_id=${SUBSCRIPTION_ID}" -d "domain=v2-limit-${RUN_ID}.test" -d 'website_type=wordpress' \
  -d 'site_title=Over limit' -d "admin_email=v2-${RUN_ID}@nakpanel.test")"
[[ "${limit_status}" == 400 ]] || fail "over-limit WordPress creation returned ${limit_status}, want 400"

echo "V2 JOURNEY PASS: VM=${VM_NAME} IP=${VM_IP} PLAN=${PLAN_ID} SUBSCRIPTION=${SUBSCRIPTION_ID} ADMIN_SITE=${SITE_ID} CLIENT_SITE=${CLIENT_SITE_ID} BACKUP=${BACKUP_ID} DOMAIN=${DOMAIN} CLIENT_DOMAIN=${CLIENT_DOMAIN}"
