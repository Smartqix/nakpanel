#!/usr/bin/env bash
# Phase 30 production PHP gate. This verifier uses panel-owned subscriptions,
# sites, databases, certificates, backups, Git repositories, and PHP
# application intent. The full fresh chain is intentionally host-driven; this
# script reuses the canonical nakpanel-lab VM and never destroys a VM.
set -euo pipefail
trap 'status=$?; echo "phase30 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
SECRET_DIR="/run/nakpanel/phase30-verifier"
DB_SECRET_FILE="${SECRET_DIR}/phase30-db-secret"
APP_SECRET_FILE="${SECRET_DIR}/phase30-app-secret"
WP_ADMIN_SECRET_FILE="${SECRET_DIR}/phase30-wp-admin-secret"

fail(){ echo "phase30: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
cli(){ multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' NAKPANEL_AGENT_SOCKET='/run/nakpanel/agent.sock' NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' panelctl --actor phase30 "$@"; }

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${SCRIPT_DIR}/phase29-verify.sh"
fi

require_nakpanel_vm_name "${VM_NAME}"
for tool in curl openssl python3; do
  command -v "${tool}" >/dev/null 2>&1 || fail "host prerequisite ${tool} is not installed"
done

tmpdir="$(mktemp -d)"
cleanup_phase30(){
  local status=$?
  multipass_exec_short "${VM_NAME}" -- sudo rm -f "${DB_SECRET_FILE}" "${APP_SECRET_FILE}" "${WP_ADMIN_SECRET_FILE}" "${SECRET_DIR}/database.cnf" "${SECRET_DIR}/request.out" >/dev/null 2>&1 || true
  multipass_exec_short "${VM_NAME}" -- sudo rm -rf "${SECRET_DIR}" >/dev/null 2>&1 || true
  multipass_exec_short "${VM_NAME}" -- sudo bash -c \
    'rm -f /usr/local/lib/nakpanel/phase30-agentprobe /tmp/phase30-composer-self-update.out /tmp/phase30-quota.out; rm -rf /tmp/nakpanel-phase30-certs' \
    >/dev/null 2>&1 || true
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup_phase30 EXIT

wait_for(){
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 120); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "${label}: got ${value:-empty}, want ${expected}"
}

wait_for_site_http(){
  local label="$1" domain="$2" expected="$3" status=""
  for _ in $(seq 1 120); do
    status="$(curl -sS -o /dev/null -w '%{http_code}' --resolve "${domain}:80:${VM_IP}" "http://${domain}/" || true)"
    [[ "${status}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "${label}: HTTP ${status:-none}, want ${expected}"
}

post_as(){
  local label="$1" endpoint="$2"
  shift 2
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "303" ]] || {
    echo "${label} returned HTTP ${status}, want 303" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  }
}

trusted_curl(){
  local domain="$1" path="$2"
  multipass_exec_short "${VM_NAME}" -- curl --cacert /usr/local/share/ca-certificates/nakpanel-phase30-root.crt \
    --fail --silent --show-error --resolve "${domain}:443:127.0.0.1" "https://${domain}${path}"
}

echo "phase30: install and prove the current worktree"
sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
src="$1"
cd "${src}"
# Phase 29 deliberately installs a synthetic 29.0.2 version. The verifier now
# installs the actual worktree; --allow-downgrade is required when VERSION is
# lower than that synthetic drill version.
deploy/install/install.sh --yes --allow-downgrade --force
go build -o /usr/local/lib/nakpanel/phase30-agentprobe ./deploy/multipass/agentprobe
chmod 0755 /usr/local/lib/nakpanel/phase30-agentprobe
for artifact in panel agent panelctl; do
  installed="/usr/local/bin/${artifact}"
  [[ "${artifact}" == panel ]] && installed=/usr/local/bin/nakpanel-panel
  [[ "${artifact}" == agent ]] && installed=/usr/local/bin/nakpanel-agent
  test "$(sha256sum "bin/${artifact}" | awk '{print $1}')" = "$(sha256sum "${installed}" | awk '{print $1}')"
done
systemctl is-active --quiet nakpanel.service
systemctl is-active --quiet nakpanel-agent.service
REMOTE

VM_IP="$(vm_ip)"
[[ -n "${VM_IP}" ]] || fail "could not determine ${VM_NAME} IPv4 address"
for _ in $(seq 1 120); do
  curl -skf "https://${VM_IP}:7443/healthz" >/dev/null && break
  sleep 2
done
curl -skf "https://${VM_IP}:7443/healthz" >/dev/null || fail "current panel is not healthy"

# RuntimeCapabilities is the authoritative inventory; PHPVersions is its
# ready-only list and must not contain a degraded runtime.
multipass exec "${VM_NAME}" -- sudo -u nakpanel /usr/local/lib/nakpanel/phase30-agentprobe \
  -op runtime_capabilities >"${tmpdir}/runtime.json"
python3 - "${tmpdir}/runtime.json" <<'PY'
import json, sys
outer = json.load(open(sys.argv[1], encoding="utf-8"))
assert outer.get("ok") is True, outer
data = outer["data"]
assert data["php_versions"] == ["8.5", "8.4", "8.3"], data["php_versions"]
assert data["composer_available"] and data["composer_version"] == "2.8.11"
assert data["wp_cli_available"] and data["wp_cli_version"] == "2.12.0"
required_extensions = {"bcmath","curl","dom","exif","fileinfo","gd","imagick","intl","mbstring","mysqli","openssl","redis","simplexml","soap","xml","zip","zend opcache"}
for version in ("8.3", "8.4", "8.5"):
    runtime = next(item for item in data["php_runtimes"] if item["version"] == version)
    loaded = {item.lower() for item in runtime["extensions"]}
    assert runtime["ready"] and runtime["cli_available"] and runtime["fpm_available"]
    assert runtime["fpm_config_valid"] and runtime["opcache_available"]
    assert not runtime.get("missing_extensions") and not runtime.get("validation_errors")
    assert required_extensions <= loaded, (version, required_extensions - loaded)
PY

multipass exec "${VM_NAME}" -- sudo bash -se <<'REMOTE'
set -euo pipefail
for version in 8.3 8.4 8.5; do
  command -v "php${version}" >/dev/null
  command -v "php-fpm${version}" >/dev/null
  "php${version}" -m | grep -Fqi 'Zend OPcache'
  "php-fpm${version}" -t >/dev/null 2>&1
  systemctl is-enabled --quiet "php${version}-fpm"
done
composer --version | grep -Fq 'Composer version 2.8.11'
if composer self-update >/tmp/phase30-composer-self-update.out 2>&1; then
  echo 'composer self-update was not blocked' >&2
  exit 1
fi
wp --info | grep -Fq 'WP-CLI version: 2.12.0'
wp --version | grep -Fq 'WP-CLI 2.12.0'
command -v freshclam >/dev/null
command -v clamscan >/dev/null
find /var/lib/clamav -maxdepth 1 -type f \( -name '*.cvd' -o -name '*.cld' \) | grep -q .
clamscan --version | grep -Eq 'ClamAV .+/.+'
REMOTE

echo "phase30: create panel-owned Classic and Managed PHP fixtures"
curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/admin.html"
grep -q 'data-np-role="admin"' "${tmpdir}/admin.html" || fail "admin login failed"

explicit83_site="$(db "SELECT id FROM sites WHERE desired_php_version='8.3' AND php_version='8.3' ORDER BY id LIMIT 1")"
[[ "${explicit83_site}" =~ ^[0-9]+$ ]] || fail "an existing explicit PHP 8.3 site is required"

plan_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND name='Phase30 Production PHP'")"
plan_args=(
  -d "plan_id=${plan_id:-0}" -d 'name=Phase30 Production PHP'
  -d 'description=Phase 30 Classic and Managed PHP acceptance'
  -d 'disk_mb=2048' -d 'max_sites=4' -d 'max_databases=4' -d 'bandwidth_mb=-1'
  -d 'max_mailboxes=0' -d 'backup_retention_days=7' -d 'max_backups=12'
  -d 'backup_storage_mb=2048' -d 'site_disk_quota_mb=512'
  -d 'php_allowlist=8.4,8.5,8.3' -d 'default_php_version=8.4'
  -d 'php_max_children=3' -d 'php_memory_mb=256' -d 'max_php_workers=2'
  -d 'max_php_releases=5' -d 'hosting_enabled=true' -d 'allow_tls=true'
  -d 'allow_backups=true' -d 'allow_php_settings=true' -d 'allow_git=true'
  -d 'allow_composer=true' -d 'allow_composer_code_execution=false'
  -d 'allow_managed_php_deployments=true' -d 'allow_php_workers=true'
  -d 'php_opcache_enabled=true' -d 'php_log_errors=true' -d 'is_active=true'
)
post_as phase30-plan plans "${plan_args[@]}"
plan_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND name='Phase30 Production PHP'")"
[[ "${plan_id}" =~ ^[0-9]+$ ]] || fail "Phase 30 plan was not saved"

customer_id="$(db "SELECT id FROM customers WHERE reseller_id IS NULL AND email='phase30@nakpanel.test'")"
if [[ -z "${customer_id}" ]]; then
  post_as phase30-customer customers -d 'customer_email=phase30@nakpanel.test' \
    -d 'customer_name=Phase Thirty Customer' -d 'company=Nakpanel Acceptance'
  customer_id="$(db "SELECT id FROM customers WHERE reseller_id IS NULL AND email='phase30@nakpanel.test'")"
fi
subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='Phase30 Production PHP'")"
if [[ -z "${subscription_id}" ]]; then
  post_as phase30-subscription subscriptions -d 'customer_mode=existing' -d "customer_id=${customer_id}" \
    -d "plan_id=${plan_id}" -d 'subscription_name=Phase30 Production PHP'
else
  post_as phase30-subscription subscriptions -d "subscription_id=${subscription_id}" -d 'customer_mode=existing' \
    -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d 'subscription_name=Phase30 Production PHP'
fi
subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='Phase30 Production PHP'")"
wait_for "subscription entitlement synchronization" "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" "in_sync"
username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")"
[[ -n "${username}" ]] || fail "subscription system account is missing"

post_as phase30-classic-site sites -d "subscription_id=${subscription_id}" -d 'domain=phase30-classic.test'
classic_site_id="$(db "SELECT id FROM sites WHERE domain='phase30-classic.test'")"
wait_for "Classic site provisioning" "SELECT status||':'||php_version FROM sites WHERE id=${classic_site_id}" "active:8.4"
[[ "$(db "SELECT php_version FROM sites WHERE id=${explicit83_site}")" == "8.3" ]] || fail "existing explicit PHP 8.3 site was rewritten"

database_id="$(db "SELECT id FROM databases WHERE subscription_id=${subscription_id} AND db_name='np_phase30_wp'")"
if [[ -z "${database_id}" ]]; then
  post_as phase30-database databases -d "subscription_id=${subscription_id}" -d "site_id=${classic_site_id}" \
    -d 'engine=mariadb' -d 'db_name=np_phase30_wp' -d 'db_user=np_phase30_wp'
  database_id="$(db "SELECT id FROM databases WHERE subscription_id=${subscription_id} AND db_name='np_phase30_wp'")"
fi
wait_for "tracked MariaDB provisioning" "SELECT status FROM databases WHERE id=${database_id}" "active"

# Generate credentials only in root-owned guest memory/files. The password
# rotation endpoint stages an encrypted secret reference and River receives
# only operation/database identities.
multipass exec "${VM_NAME}" -- sudo bash -se -- "${database_id}" <<'REMOTE'
set -euo pipefail
database_id="$1"
SECRET_DIR=/run/nakpanel/phase30-verifier
DB_SECRET_FILE="${SECRET_DIR}/phase30-db-secret"
APP_SECRET_FILE="${SECRET_DIR}/phase30-app-secret"
WP_ADMIN_SECRET_FILE="${SECRET_DIR}/phase30-wp-admin-secret"
install -d -m 0700 -o root -g root "${SECRET_DIR}"
DB_PASSWORD="Aa9!$(openssl rand -hex 18)"
APP_SECRET="$(openssl rand -hex 32)"
WP_ADMIN_PASSWORD="Wp9!$(openssl rand -hex 18)"
printf '%s' "${DB_PASSWORD}" >"${DB_SECRET_FILE}"
printf '%s' "${APP_SECRET}" >"${APP_SECRET_FILE}"
printf '%s' "${WP_ADMIN_PASSWORD}" >"${WP_ADMIN_SECRET_FILE}"
chmod 0600 "${DB_SECRET_FILE}" "${APP_SECRET_FILE}" "${WP_ADMIN_SECRET_FILE}"
unset DB_PASSWORD APP_SECRET WP_ADMIN_PASSWORD
curl -sk --fail -c "${SECRET_DIR}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  https://127.0.0.1:7443/login -o /dev/null
session="$(awk '$6=="nakpanel_session"{v=$7} END{print v}' "${SECRET_DIR}/admin.cookies")"
csrf="$(printf 'nakpanel-csrf-v1:%s' "${session}" | sha256sum | awk '{print $1}')"
status="$(curl -sk -o "${SECRET_DIR}/database-rotation.json" -w '%{http_code}' \
  -b "${SECRET_DIR}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -H 'Accept: application/json' \
  --data-urlencode "password@${DB_SECRET_FILE}" \
  "https://127.0.0.1:7443/tools-settings/databases/${database_id}/password")"
test "${status}" = 202
REMOTE
wait_for "database password rotation" "SELECT status FROM server_operations WHERE target_type='database' AND target_key='${database_id}' AND action='rotate_password' ORDER BY id DESC LIMIT 1" "succeeded"

echo "phase30: install WordPress 7.1 through Classic hosting"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${classic_site_id}" "${username}" <<'REMOTE'
set -euo pipefail
site_id="$1"; username="$2"
domain=phase30-classic.test
certs=/tmp/nakpanel-phase30-certs
rm -rf "${certs}"
install -d -m 0700 "${certs}"
cd "${certs}"
openssl ecparam -genkey -name prime256v1 -out root.key
openssl req -x509 -new -key root.key -sha256 -days 30 -subj '/CN=Nakpanel Phase30 Root' -out root.crt \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl ecparam -genkey -name prime256v1 -out site.key
openssl req -new -key site.key -subj "/CN=${domain}" -out site.csr
cat >site.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:${domain}
EOF
openssl x509 -req -in site.csr -CA root.crt -CAkey root.key -CAcreateserial -days 14 -sha256 -extfile site.ext -out site.crt
chmod 0644 root.crt site.crt
chmod 0600 site.key
chown nakpanel:nakpanel site.key
install -m 0644 root.crt /usr/local/share/ca-certificates/nakpanel-phase30-root.crt
update-ca-certificates >/dev/null
REMOTE
cli ssl set-custom phase30-classic.test --cert /tmp/nakpanel-phase30-certs/site.crt \
  --key /tmp/nakpanel-phase30-certs/site.key --yes >/dev/null
wait_for "custom certificate installation" "SELECT tls_issuer||':'||tls_status FROM sites WHERE id=${classic_site_id}" "custom:active"
post_as phase30-classic-redirect "sites/${classic_site_id}/hosting" -d 'desired_status=active' \
  -d 'desired_php_version=8.4' -d 'desired_https_redirect=true'
wait_for "Classic HTTPS redirect" "SELECT https_redirect::text||':'||settings_status FROM sites WHERE id=${classic_site_id}" "true:in_sync"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
echo | openssl s_client -connect 127.0.0.1:443 -servername phase30-classic.test \
  -CAfile /usr/local/share/ca-certificates/nakpanel-phase30-root.crt -verify_return_error 2>/dev/null \
  | openssl x509 -noout -checkhost phase30-classic.test >/dev/null
headers="$(curl --silent --show-error --head --resolve phase30-classic.test:80:127.0.0.1 http://phase30-classic.test/)"
grep -Eq '^HTTP/.* (301|308)' <<<"${headers}"
grep -Eqi '^location: https://phase30-classic\.test/' <<<"${headers}"
REMOTE

db_name="$(db "SELECT db_name FROM databases WHERE id=${database_id}")"
db_user="$(db "SELECT db_user FROM databases WHERE id=${database_id}")"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${db_name}" "${db_user}" <<'REMOTE'
set -euo pipefail
username="$1"; db_name="$2"; db_user="$3"
docroot="/home/${username}/domains/phase30-classic.test/public_html"
DB_SECRET_FILE=/run/nakpanel/phase30-verifier/phase30-db-secret
WP_ADMIN_SECRET_FILE=/run/nakpanel/phase30-verifier/phase30-wp-admin-secret
DB_CNF=/run/nakpanel/phase30-verifier/database.cnf
sudo -u "${username}" find "${docroot}" -mindepth 1 -delete
sudo -u "${username}" wp core download --version=7.1 --locale=en_US --path="${docroot}"
{
  printf '[client]\nuser=%s\npassword=' "${db_user}"
  cat "${DB_SECRET_FILE}"
  printf '\ndatabase=%s\nhost=localhost\n' "${db_name}"
} >"${DB_CNF}"
chmod 0600 "${DB_CNF}"
cat "${DB_SECRET_FILE}" | sudo -u "${username}" wp config create --path="${docroot}" \
  --dbname="${db_name}" --dbuser="${db_user}" --dbhost=localhost --prompt=dbpass --skip-check
chmod 0600 "${docroot}/wp-config.php"
chown "${username}:${username}" "${docroot}/wp-config.php"
cat "${WP_ADMIN_SECRET_FILE}" | sudo -u "${username}" wp core install --path="${docroot}" \
  --url=https://phase30-classic.test --title='Phase 30 WordPress' --admin_user=phase30admin \
  --prompt=admin_password --admin_email=phase30-wp@nakpanel.test --skip-email
sudo -u "${username}" wp core version --path="${docroot}" | grep -Fxq '7.1'
sudo -u "${username}" wp core verify-checksums --path="${docroot}" --version=7.1
sudo -u "${username}" wp rewrite structure '/%postname%/' --hard --path="${docroot}"
sudo -u "${username}" wp post create --path="${docroot}" --post_type=page --post_status=publish \
  --post_title='Phase30 Clean Permalink' --post_name=phase30-clean >/dev/null
install -d -m 0755 -o "${username}" -g "${username}" "${docroot}/wp-content/plugins/phase30-local"
cat >"${docroot}/wp-content/plugins/phase30-local/phase30-local.php" <<'PHP'
<?php
/* Plugin Name: Phase 30 Local Acceptance */
add_action('phase30_event', static function (): void { update_option('phase30_cron_ran', 'yes'); });
add_action('template_redirect', static function (): void {
    if (!isset($_GET['phase30_runtime'])) { return; }
    session_start();
    $_SESSION['phase30'] = 'ok';
    $upload = wp_upload_dir();
    $opcache = function_exists('opcache_get_status') && opcache_get_status(false) !== false;
    header('Content-Type: text/plain');
    echo 'session=' . (session_status() === PHP_SESSION_ACTIVE ? 'active' : 'inactive') . "\n";
    echo 'opcache=' . ($opcache ? 'active' : 'inactive') . "\n";
    echo 'uploads=' . (is_writable($upload['basedir']) ? 'writable' : 'readonly') . "\n";
    exit;
});
PHP
chown -R "${username}:${username}" "${docroot}/wp-content/plugins/phase30-local"
sudo -u "${username}" wp plugin activate phase30-local --path="${docroot}"
printf 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=' \
  | base64 -d >"${docroot}/phase30-media.png"
chown "${username}:${username}" "${docroot}/phase30-media.png"
attachment_id="$(sudo -u "${username}" wp media import "${docroot}/phase30-media.png" --title='Phase30 Media' --porcelain --path="${docroot}")"
test "${attachment_id}" -gt 0
sudo -u "${username}" wp cron event schedule phase30_event '+1 hour' --repeat=hourly --path="${docroot}"
sudo -u "${username}" wp cron event list --fields=hook --path="${docroot}" | grep -Fxq 'phase30_event'
sudo -u "${username}" wp eval '$r=wp_remote_get("https://api.wordpress.org/core/version-check/1.7/", ["timeout"=>20]); if (is_wp_error($r) || wp_remote_retrieve_response_code($r)!==200) { exit(1); }' --path="${docroot}"
sudo -u "${username}" wp option update phase30_restore_canary before --path="${docroot}" >/dev/null
printf 'before\n' >"${docroot}/phase30-restore.txt"
chown "${username}:${username}" "${docroot}/phase30-restore.txt"
test "$(stat -c '%U:%G' "${docroot}")" = "${username}:${username}"
REMOTE

trusted_curl phase30-classic.test / | grep -Fq 'Phase 30 WordPress'
trusted_curl phase30-classic.test /wp-admin/ >/dev/null
trusted_curl phase30-classic.test /phase30-clean/ | grep -Fq 'Phase30 Clean Permalink'
runtime_body="$(trusted_curl phase30-classic.test '/?phase30_runtime=1')"
grep -Fxq 'session=active' <<<"${runtime_body}"
grep -Fxq 'opcache=active' <<<"${runtime_body}"
grep -Fxq 'uploads=writable' <<<"${runtime_body}"

echo "phase30: back up and restore Classic files plus tracked MariaDB"
backup_output="$(cli backup create phase30-classic.test)"
backup_id="$(sed -nE 's/^Backup queued \(backup ([0-9]+)\)\.$/\1/p' <<<"${backup_output}")"
[[ "${backup_id}" =~ ^[0-9]+$ ]] || fail "could not parse Classic backup id"
wait_for "Classic backup" "SELECT status FROM backups WHERE id=${backup_id}" "active"
multipass exec "${VM_NAME}" -- sudo -u "${username}" bash -se <<'REMOTE'
set -euo pipefail
docroot=/home/"$(id -un)"/domains/phase30-classic.test/public_html
printf 'after\n' >"${docroot}/phase30-restore.txt"
wp option update phase30_restore_canary after --path="${docroot}" >/dev/null
REMOTE
multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' NAKPANEL_AGENT_SOCKET='/run/nakpanel/agent.sock' NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' panelctl --actor phase30 restore "${backup_id}" --yes >/dev/null
wait_for "Classic restore" "SELECT status FROM restore_runs WHERE backup_id=${backup_id} ORDER BY id DESC LIMIT 1" "active"
multipass exec "${VM_NAME}" -- sudo -u "${username}" bash -se <<'REMOTE'
set -euo pipefail
docroot=/home/"$(id -un)"/domains/phase30-classic.test/public_html
grep -Fxq before "${docroot}/phase30-restore.txt"
test "$(wp option get phase30_restore_canary --path="${docroot}")" = before
REMOTE

post_as phase30-classic-php85 "sites/${classic_site_id}/hosting" -d 'desired_status=active' \
  -d 'desired_php_version=8.5' -d 'desired_https_redirect=true'
wait_for "Classic PHP 8.5 switch" "SELECT php_version||':'||settings_status FROM sites WHERE id=${classic_site_id}" "8.5:in_sync"
trusted_curl phase30-classic.test / | grep -Fq 'Phase 30 WordPress'
multipass exec "${VM_NAME}" -- sudo bash -se -- "${classic_site_id}" "${username}" <<'REMOTE'
set -euo pipefail
site_id="$1"; username="$2"
unit="nakpanel-php-fpm@${site_id}.service"
systemctl is-active --quiet "${unit}"
curl --cacert /usr/local/share/ca-certificates/nakpanel-phase30-root.crt --fail --silent \
  --resolve phase30-classic.test:443:127.0.0.1 https://phase30-classic.test/ >/dev/null
master="$(systemctl show -p MainPID --value "${unit}")"
for _ in $(seq 1 30); do
  workers="$(ps --ppid "${master}" -o user= | tr -d ' ' || true)"
  grep -Fxq "${username}" <<<"${workers}" && exit 0
  sleep 1
done
echo 'PHP 8.5 FPM workers did not run as the subscription account' >&2
exit 1
REMOTE

echo "phase30: prove quota and cross-subscription filesystem isolation"
second_customer_id="$(db "SELECT id FROM customers WHERE reseller_id IS NULL AND email='phase30-isolated@nakpanel.test'")"
if [[ -z "${second_customer_id}" ]]; then
  post_as phase30-isolated-customer customers -d 'customer_email=phase30-isolated@nakpanel.test' -d 'customer_name=Phase Thirty Isolated'
  second_customer_id="$(db "SELECT id FROM customers WHERE reseller_id IS NULL AND email='phase30-isolated@nakpanel.test'")"
fi
second_subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${second_customer_id} AND name='Phase30 Isolated'")"
if [[ -z "${second_subscription_id}" ]]; then
  post_as phase30-isolated-sub subscriptions -d 'customer_mode=existing' -d "customer_id=${second_customer_id}" \
    -d "plan_id=${plan_id}" -d 'subscription_name=Phase30 Isolated'
fi
second_subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${second_customer_id} AND name='Phase30 Isolated'")"
wait_for "isolated account provisioning" "SELECT convergence_status FROM subscription_system_accounts WHERE subscription_id=${second_subscription_id}" "in_sync"
second_username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${second_subscription_id}")"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${second_username}" "${classic_site_id}" <<'REMOTE'
set -euo pipefail
username="$1"; second_username="$2"; site_id="$3"
quotaon -p / | grep -q 'user quota .* is on'
quota -u "${username}" >/tmp/phase30-quota.out
repquota -u / | awk -v user="${username}" '$1==user {found=1} END{exit found?0:1}'
slug="${username}-phase30-classic-test"
for path in \
  "/home/${username}/domains/phase30-classic.test/public_html/wp-config.php" \
  "/var/log/nginx/${slug}.access.log" \
  "/var/log/nginx/${slug}.error.log" \
  "/var/log/php-fpm/${slug}.error.log" \
  "/etc/nakpanel/php-fpm/sites/${site_id}.conf" \
  "/etc/nginx/sites-available/phase30-classic.test.conf" \
  "/run/nakpanel/phase30-verifier/phase30-db-secret" \
  "/etc/nakpanel/secret-keys.json"
do
  if sudo -u "${second_username}" test -r "${path}"; then
    echo "cross-subscription read succeeded: ${path}" >&2
    exit 1
  fi
done
REMOTE

post_as phase30-managed-site sites -d "subscription_id=${subscription_id}" -d 'domain=phase30-managed.test'
managed_site_id="$(db "SELECT id FROM sites WHERE domain='phase30-managed.test'")"
wait_for "Managed site provisioning" "SELECT status||':'||php_version FROM sites WHERE id=${managed_site_id}" "active:8.4"
post_as phase30-hosted-git "sites/${managed_site_id}/git" -d "subscription_id=${subscription_id}" \
  -d 'mode=hosted' -d 'branch=main' -d 'deploy_target=.' -d 'automatic=false'
wait_for "hosted Git provisioning" "SELECT convergence_status FROM git_repositories WHERE site_id=${managed_site_id}" "in_sync"
repository_id="$(db "SELECT id FROM git_repositories WHERE site_id=${managed_site_id}")"

multipass exec "${VM_NAME}" -- sudo -u "${username}" bash -se -- "${managed_site_id}" <<'REMOTE'
set -euo pipefail
site_id="$1"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
git -C "${work}" init -q
git -C "${work}" config user.name 'Nakpanel Phase30'
git -C "${work}" config user.email phase30@nakpanel.test
mkdir -p "${work}/public"
cat >"${work}/composer.json" <<'JSON'
{"name":"nakpanel/phase30-app","description":"Phase 30 managed PHP verifier","type":"project","require":{}}
JSON
cat >"${work}/public/index.php" <<'PHP'
<?php
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path === '/healthz') { header('Content-Type: text/plain'); echo "healthy\n"; exit; }
header('Content-Type: text/plain');
echo 'public=' . (getenv('PHASE30_PUBLIC') ?: 'missing') . "\n";
echo 'secret=' . (getenv('PHASE30_SECRET') ? 'present' : 'missing') . "\n";
PHP
cat >"${work}/worker.php" <<'PHP'
<?php
while (true) { sleep(2); }
PHP
git -C "${work}" add .
git -C "${work}" commit -qm 'healthy managed PHP release'
git -C "${work}" branch -M main
git -C "${work}" remote add origin "/var/lib/nakpanel/git/site-${site_id}/repository.git"
git -C "${work}" push -q --force origin main
REMOTE

post_as phase30-managed-config "sites/${managed_site_id}/php-application" \
  -d 'hosting_mode=managed' -d 'php_version=8.4' -d "repository_id=${repository_id}" \
  -d 'repository_ref=main' -d 'framework_profile=plain' -d 'public_path=public' \
  -d 'health_path=/healthz' -d 'release_retention=3' -d 'composer_install=true' \
  -d 'composer_allow_scripts=false' -d 'composer_allow_plugins=false'
managed_application_id="$(db "SELECT id FROM php_applications WHERE site_id=${managed_site_id}")"
post_as phase30-public-env "sites/${managed_site_id}/php-application/environment" \
  -d 'name=PHASE30_PUBLIC' -d 'value=visible' -d 'secret=false'

# File-backed form input keeps the encrypted write-only secret out of argv,
# River arguments, HTML, JSON, audit metadata, and command output.
multipass exec "${VM_NAME}" -- sudo bash -se -- "${managed_site_id}" <<'REMOTE'
set -euo pipefail
site_id="$1"
SECRET_DIR=/run/nakpanel/phase30-verifier
APP_SECRET_FILE="${SECRET_DIR}/phase30-app-secret"
session="$(awk '$6=="nakpanel_session"{v=$7} END{print v}' "${SECRET_DIR}/admin.cookies")"
csrf="$(printf 'nakpanel-csrf-v1:%s' "${session}" | sha256sum | awk '{print $1}')"
status="$(curl -sk -o "${SECRET_DIR}/application-secret.json" -w '%{http_code}' \
  -b "${SECRET_DIR}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -H 'Accept: application/json' \
  -d 'name=PHASE30_SECRET' -d 'secret=true' --data-urlencode "secret_value@${APP_SECRET_FILE}" \
  "https://127.0.0.1:7443/sites/${site_id}/php-application/environment")"
test "${status}" = 200
REMOTE

post_as phase30-healthy-deploy "sites/${managed_site_id}/php-application/deployments" -d 'revision=main'
wait_for "healthy managed deployment" "SELECT status FROM php_deployments WHERE application_id=${managed_application_id} ORDER BY id DESC LIMIT 1" "healthy"
active_deployment_id="$(db "SELECT active_deployment_id FROM php_applications WHERE id=${managed_application_id}")"
managed_body="$(curl -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/)"
grep -Fxq 'public=visible' <<<"${managed_body}"
grep -Fxq 'secret=present' <<<"${managed_body}"

post_as phase30-worker "sites/${managed_site_id}/php-application/workers" \
  -d 'name=queue' -d 'script=worker.php' -d 'processes=1' -d 'desired_state=running'
worker_id="$(db "SELECT id FROM php_workers WHERE application_id=${managed_application_id} AND name='queue'")"
wait_for "bounded PHP worker" "SELECT observed_state||':'||convergence_status FROM php_workers WHERE id=${worker_id}" "running:in_sync"
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-php-worker@${worker_id}.service" || fail "managed PHP worker is not active"

echo "phase30: reject an unhealthy release and retain the active release"
multipass exec "${VM_NAME}" -- sudo -u "${username}" bash -se -- "${managed_site_id}" <<'REMOTE'
set -euo pipefail
site_id="$1"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
git -C "${work}" clone -q "/var/lib/nakpanel/git/site-${site_id}/repository.git" .
git -C "${work}" config user.name 'Nakpanel Phase30'
git -C "${work}" config user.email phase30@nakpanel.test
cat >"${work}/public/index.php" <<'PHP'
<?php
http_response_code(500);
header('Content-Type: text/plain');
echo "unhealthy\n";
PHP
git -C "${work}" add public/index.php
git -C "${work}" commit -qm 'unhealthy replacement'
git -C "${work}" push -q origin main
REMOTE
post_as phase30-unhealthy-deploy "sites/${managed_site_id}/php-application/deployments" -d 'revision=main'
wait_for "unhealthy deployment rejection" "SELECT status FROM php_deployments WHERE application_id=${managed_application_id} ORDER BY id DESC LIMIT 1" "failed"
[[ "$(db "SELECT active_deployment_id FROM php_applications WHERE id=${managed_application_id}")" == "${active_deployment_id}" ]] || fail "unhealthy deployment replaced the active release"
curl -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/ | grep -Fq 'public=visible'

echo "phase30: prove secret absence from durable/control-plane surfaces"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${managed_site_id}/applications" -o "${tmpdir}/managed.html"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${managed_application_id}" "${managed_site_id}" "${second_username}" <<'REMOTE'
set -euo pipefail
application_id="$1"; site_id="$2"; second_username="$3"
SECRET_DIR=/run/nakpanel/phase30-verifier
APP_SECRET_FILE="${SECRET_DIR}/phase30-app-secret"
DB_SECRET_FILE="${SECRET_DIR}/phase30-db-secret"
assert_secret_absent(){
  local label="$1" path="$2" secret_file="$3"
  if grep -Fq -f "${secret_file}" "${path}"; then
    echo "secret leaked into ${label}" >&2
    exit 1
  fi
}
sudo -u postgres psql -Atqd nakpanel -c \
  "SELECT args::text FROM river_job
     WHERE kind LIKE '%php%' OR kind IN ('create_database','system_database_mutation');
   SELECT metadata::text FROM audit_events
     WHERE action LIKE 'php.%' OR action LIKE 'database.%';
   SELECT request::text||result::text||last_error FROM server_operations
     WHERE target_type='database';
   SELECT COALESCE(last_error,'')||COALESCE(health_message,'')||COALESCE(composer_audit::text,'')
     FROM php_deployments WHERE application_id=${application_id};" \
  >"${SECRET_DIR}/database-surfaces.out"
# deployment output is represented by bounded deployment health/error/audit data.
journalctl -u nakpanel.service -u nakpanel-agent.service --no-pager -n 2000 >"${SECRET_DIR}/journal.out"
systemctl show "nakpanel-php-fpm@${site_id}.service" "nakpanel-php-worker@*.service" >"${SECRET_DIR}/systemd.out" 2>/dev/null || true
find /etc/nginx /etc/nakpanel/php-fpm -type f -maxdepth 5 -print0 2>/dev/null \
  | xargs -0r grep -h '' >"${SECRET_DIR}/tenant-config.out"
assert_secret_absent 'River arguments, audit metadata, and deployment output' "${SECRET_DIR}/database-surfaces.out" "${APP_SECRET_FILE}"
assert_secret_absent 'logs' "${SECRET_DIR}/journal.out" "${APP_SECRET_FILE}"
assert_secret_absent 'systemd metadata' "${SECRET_DIR}/systemd.out" "${APP_SECRET_FILE}"
assert_secret_absent 'nginx/PHP configuration' "${SECRET_DIR}/tenant-config.out" "${APP_SECRET_FILE}"
assert_secret_absent 'application JSON' "${SECRET_DIR}/application-secret.json" "${APP_SECRET_FILE}"
assert_secret_absent 'database rotation JSON' "${SECRET_DIR}/database-rotation.json" "${DB_SECRET_FILE}"
assert_secret_absent 'River arguments and audit metadata (database)' "${SECRET_DIR}/database-surfaces.out" "${DB_SECRET_FILE}"
curl -sk --fail -b "${SECRET_DIR}/admin.cookies" \
  "https://127.0.0.1:7443/sites/${site_id}/applications" >"${SECRET_DIR}/application.html"
assert_secret_absent 'application HTML' "${SECRET_DIR}/application.html" "${APP_SECRET_FILE}"
environment_path="$(find "/var/lib/nakpanel/php-applications/app-${application_id}/environments" -type f | head -1)"
test -n "${environment_path}"
test "$(stat -c '%U:%G:%a' "${environment_path}")" = root:root:600
for path in "${environment_path}" "/var/lib/nakpanel/php-applications/app-${application_id}"; do
  if sudo -u "${second_username}" test -r "${path}"; then
    echo "second subscription read managed application environment/state" >&2
    exit 1
  fi
done
REMOTE
for secret_name in PHASE30_SECRET phase30-app-secret phase30-db-secret; do
  if grep -Fq "${secret_name}" "${tmpdir}/managed.html" && [[ "${secret_name}" != PHASE30_SECRET ]]; then
    fail "secret material appeared in PHP application HTML"
  fi
done

echo "phase30: suspend, reactivate, reboot, and reconcile"
post_as phase30-managed-suspend "sites/${managed_site_id}/hosting" -d 'desired_status=suspended' \
  -d 'desired_php_version=8.4' -d 'desired_https_redirect=false'
wait_for "managed suspension" "SELECT desired_state||':'||observed_state FROM php_applications WHERE id=${managed_application_id}" "suspended:suspended"
wait_for_site_http "managed unavailable response" phase30-managed.test 503
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-php-fpm@${managed_site_id}.service" && fail "managed FPM remained active while suspended"
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-php-worker@${worker_id}.service" && fail "managed worker remained active while suspended"

post_as phase30-managed-active "sites/${managed_site_id}/hosting" -d 'desired_status=active' \
  -d 'desired_php_version=8.4' -d 'desired_https_redirect=false'
post_as phase30-managed-reconcile "sites/${managed_site_id}/php-application/reconcile"
wait_for "managed reactivation" "SELECT desired_state||':'||observed_state||':'||convergence_status FROM php_applications WHERE id=${managed_application_id}" "active:healthy:in_sync"
wait_for "desired-active worker restoration" "SELECT desired_state||':'||observed_state FROM php_workers WHERE id=${worker_id}" "running:running"
curl -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/ | grep -Fq 'public=visible'

multipass restart "${VM_NAME}"
wait_for_cloud_init "${VM_NAME}"
VM_IP="$(vm_ip)"
for _ in $(seq 1 120); do curl -skf "https://${VM_IP}:7443/healthz" >/dev/null && break; sleep 2; done
cli site reconcile phase30-classic.test >/dev/null
cli reconcile --system >/dev/null
curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/admin-reboot.html"
post_as phase30-reboot-reconcile "sites/${managed_site_id}/php-application/reconcile"
wait_for "post-reboot managed application" "SELECT observed_state||':'||convergence_status FROM php_applications WHERE id=${managed_application_id}" "healthy:in_sync"
wait_for "post-reboot desired-active worker" "SELECT observed_state||':'||convergence_status FROM php_workers WHERE id=${worker_id}" "running:in_sync"
[[ "$(db "SELECT active_deployment_id FROM php_applications WHERE id=${managed_application_id}")" == "${active_deployment_id}" ]] || fail "reboot changed the active managed release"
trusted_curl phase30-classic.test / | grep -Fq 'Phase 30 WordPress'
curl -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/ | grep -Fq 'public=visible'

echo "phase30: verify PHP UI and product-boundary copy"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${classic_site_id}/applications" -o "${tmpdir}/classic-app.html"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${managed_site_id}/applications" -o "${tmpdir}/managed-app.html"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/tools-settings/php" -o "${tmpdir}/php-runtime.html"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/tools-settings/applications" -o "${tmpdir}/application-catalog.html"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/service-plans/${plan_id}" -o "${tmpdir}/plan.html"
for marker in 'PHP Application' 'Classic'; do grep -Fq "${marker}" "${tmpdir}/classic-app.html" || fail "Classic PHP UI is missing ${marker}"; done
for marker in 'PHP Application' 'Managed' 'PHP workers'; do grep -Fq "${marker}" "${tmpdir}/managed-app.html" || fail "Managed PHP UI is missing ${marker}"; done
# Runtime inventory is provider-only and must expose detailed readiness.
for marker in 'PHP Runtime Inventory' 'PHP 8.3' 'PHP 8.4' 'PHP 8.5' 'FPM validation' 'OPcache' 'Composer 2.8.11' 'WP-CLI 2.12.0'; do
  grep -Fq "${marker}" "${tmpdir}/php-runtime.html" || fail "runtime inventory is missing ${marker}"
done
for marker in 'Managed PHP deployments' 'PHP workers'; do grep -Fq "${marker}" "${tmpdir}/plan.html" || fail "plan controls are missing ${marker}"; done
for marker in 'Provider Application Catalog' 'OCI only' 'WordPress Toolkit, Node.js, and Python are not implemented'; do
  grep -Fq "${marker}" "${tmpdir}/application-catalog.html" || fail "application catalog boundary is missing ${marker}"
done
for stale_promise in 'Deploy WordPress' 'WordPress Toolkit' 'Node.js application' 'Python application'; do
  if grep -Fq "${stale_promise}" "${tmpdir}/managed-app.html"; then
    fail "PHP application UI advertises stale runtime promise: ${stale_promise}"
  fi
  if [[ "${stale_promise}" != 'WordPress Toolkit' ]] && grep -Fq "${stale_promise}" "${tmpdir}/application-catalog.html"; then
    fail "application catalog advertises stale runtime promise: ${stale_promise}"
  fi
done

[[ "$(db "SELECT php_version FROM sites WHERE id=${explicit83_site}")" == "8.3" ]] || fail "explicit PHP 8.3 site changed during Phase 30"
echo "Phase 30 production PHP, WordPress 7.1, managed release, worker, isolation, and reboot verification passed on ${VM_NAME} (${VM_IP})."
