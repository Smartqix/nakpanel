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
DB_PASSWORD=""
APP_SECRET=""
WP_ADMIN_PASSWORD=""

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
  multipass_exec_short "${VM_NAME}" -- sudo bash -c \
    'rm -f /usr/local/lib/nakpanel/phase30-agentprobe /tmp/phase30-composer-self-update.out /tmp/phase30-quota.out; rm -rf /tmp/nakpanel-phase30-certs' \
    >/dev/null 2>&1 || true
  unset DB_PASSWORD APP_SECRET WP_ADMIN_PASSWORD
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
    status="$(curl --connect-timeout 5 --max-time 30 -sS -o /dev/null -w '%{http_code}' --resolve "${domain}:80:${VM_IP}" "http://${domain}/" || true)"
    [[ "${status}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "${label}: HTTP ${status:-none}, want ${expected}"
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

trusted_curl(){
  local domain="$1" path="$2"
  multipass_exec_short "${VM_NAME}" -- curl --connect-timeout 5 --max-time 30 --cacert /usr/local/share/ca-certificates/nakpanel-phase30-root.crt \
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
timeout 45m deploy/install/install.sh --yes --allow-downgrade --force
timeout 15m go build -o /usr/local/lib/nakpanel/phase30-agentprobe ./deploy/multipass/agentprobe
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
  curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null && break
  sleep 2
done
curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null || fail "current panel is not healthy"

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
composer_wrapper_hash_before="$(sha256sum /usr/local/bin/composer | awk '{print $1}')"
composer_phar_hash_before="$(sha256sum /usr/local/lib/nakpanel/composer.phar | awk '{print $1}')"
composer_version_before="$(timeout 1m composer --version)"
grep -Fq 'Composer version 2.8.11' <<<"${composer_version_before}"
set +e
timeout 1m composer self-update >/tmp/phase30-composer-self-update.out 2>&1
composer_self_update_status=$?
set -e
test "${composer_self_update_status}" = 64
grep -Fxq 'composer self-update is disabled; use the nakpanel installer' /tmp/phase30-composer-self-update.out
composer_wrapper_hash_after="$(sha256sum /usr/local/bin/composer | awk '{print $1}')"
composer_phar_hash_after="$(sha256sum /usr/local/lib/nakpanel/composer.phar | awk '{print $1}')"
composer_version_after="$(timeout 1m composer --version)"
test "${composer_wrapper_hash_after}" = "${composer_wrapper_hash_before}"
test "${composer_phar_hash_after}" = "${composer_phar_hash_before}"
test "${composer_version_after}" = "${composer_version_before}"
test "$(stat -c '%U:%G:%a' /usr/local/bin/composer)" = root:root:755
test "$(stat -c '%U:%G:%a' /usr/local/lib/nakpanel/composer.phar)" = root:root:555
wp_info="$(timeout 1m wp --info)"
grep -Eq 'WP-CLI version:[[:space:]]+2\.12\.0' <<<"${wp_info}"
timeout 1m wp --version --allow-root | grep -Fq 'WP-CLI 2.12.0'
command -v freshclam >/dev/null
command -v clamscan >/dev/null
find /var/lib/clamav -maxdepth 1 -type f \( -name '*.cvd' -o -name '*.cld' \) | grep -q .
timeout 1m clamscan --version | grep -Eq 'ClamAV .+/.+'
REMOTE

echo "phase30: create panel-owned Classic and Managed PHP fixtures"
curl --connect-timeout 5 --max-time 30 -sk --fail -c "${tmpdir}/admin.cookies" -L \
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

# Keep comparison needles in this host shell. Stdin carries values into the
# supported guest operations, and River receives only operation/database IDs.
journal_cursor="$(multipass_exec_short "${VM_NAME}" -- sudo journalctl \
  -u nakpanel.service -u nakpanel-agent.service --no-pager -n 0 --show-cursor \
  | sed -n 's/^-- cursor: //p' | tail -1)"
[[ "${journal_cursor}" == s=* ]] || fail "could not capture the pre-secret panel/agent journal cursor"
DB_PASSWORD="Aa9_$(openssl rand -hex 18)"
APP_SECRET="$(openssl rand -hex 32)"
WP_ADMIN_PASSWORD="Wp9!$(openssl rand -hex 18)"
database_rotation_result="$(printf '%s' "${DB_PASSWORD}" | \
  curl --connect-timeout 5 --max-time 30 -sk -w $'\n%{http_code}' \
  -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
  -H 'Accept: application/json' \
  --data-urlencode "password@-" \
  "https://${VM_IP}:7443/tools-settings/databases/${database_id}/password")"
database_rotation_status="${database_rotation_result##*$'\n'}"
DATABASE_ROTATION_RESPONSE="${database_rotation_result%$'\n'*}"
test "${database_rotation_status}" = 202
wait_for "database password rotation" "SELECT status FROM server_operations WHERE target_type='database' AND target_key='${database_id}' AND action='rotate_password' ORDER BY id DESC LIMIT 1" "succeeded"

echo "phase30: install WordPress 7.1 through Classic hosting"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${classic_site_id}" "${username}" <<'REMOTE'
set -euo pipefail
site_id="$1"; username="$2"
domain=phase30-classic.test
certs=/tmp/nakpanel-phase30-certs
rm -rf "${certs}"
install -d -m 0750 -o root -g nakpanel "${certs}"
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
echo | timeout 1m openssl s_client -connect 127.0.0.1:443 -servername phase30-classic.test \
  -CAfile /usr/local/share/ca-certificates/nakpanel-phase30-root.crt -verify_return_error 2>/dev/null \
  | openssl x509 -noout -checkhost phase30-classic.test >/dev/null
headers="$(curl --connect-timeout 5 --max-time 30 --silent --show-error --head --resolve phase30-classic.test:80:127.0.0.1 http://phase30-classic.test/)"
grep -Eq '^HTTP/.* (301|308)' <<<"${headers}"
grep -Eqi '^location: https://phase30-classic\.test/' <<<"${headers}"
REMOTE

db_name="$(db "SELECT db_name FROM databases WHERE id=${database_id}")"
db_user="$(db "SELECT db_user FROM databases WHERE id=${database_id}")"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" <<'REMOTE'
set -euo pipefail
username="$1"
docroot="/home/${username}/domains/phase30-classic.test/public_html"
sudo -u "${username}" find "${docroot}" -mindepth 1 -delete
timeout 10m sudo -u "${username}" wp core download --version=7.1 --locale=en_US --path="${docroot}"
REMOTE
printf '%s' "${DB_PASSWORD}" | multipass exec "${VM_NAME}" -- sudo -u "${username}" timeout 5m \
  wp config create --path="/home/${username}/domains/phase30-classic.test/public_html" \
  --dbname="${db_name}" --dbuser="${db_user}" --dbhost=localhost --prompt=dbpass --skip-check
printf '%s' "${WP_ADMIN_PASSWORD}" | multipass exec "${VM_NAME}" -- sudo -u "${username}" timeout 5m \
  wp core install --path="/home/${username}/domains/phase30-classic.test/public_html" \
  --url=https://phase30-classic.test --title='Phase 30 WordPress' --admin_user=phase30admin \
  --prompt=admin_password --admin_email=phase30-wp@nakpanel.test --skip-email
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" <<'REMOTE'
set -euo pipefail
username="$1"
docroot="/home/${username}/domains/phase30-classic.test/public_html"
chmod 0600 "${docroot}/wp-config.php"
chown "${username}:${username}" "${docroot}/wp-config.php"
timeout 5m sudo -u "${username}" wp core version --path="${docroot}" | grep -Fxq '7.1'
timeout 5m sudo -u "${username}" wp core verify-checksums --path="${docroot}" --version=7.1
timeout 5m sudo -u "${username}" wp rewrite structure '/%postname%/' --hard --path="${docroot}"
timeout 5m sudo -u "${username}" wp post create --path="${docroot}" --post_type=page --post_status=publish \
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
timeout 5m sudo -u "${username}" wp plugin activate phase30-local --path="${docroot}"
printf 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=' \
  | base64 -d >"${docroot}/phase30-media.png"
chown "${username}:${username}" "${docroot}/phase30-media.png"
attachment_id="$(timeout 5m sudo -u "${username}" wp media import "${docroot}/phase30-media.png" --title='Phase30 Media' --porcelain --path="${docroot}")"
test "${attachment_id}" -gt 0
timeout 5m sudo -u "${username}" wp cron event schedule phase30_event '+1 hour' --repeat=hourly --path="${docroot}"
timeout 5m sudo -u "${username}" wp cron event list --fields=hook --path="${docroot}" | grep -Fxq 'phase30_event'
timeout 5m sudo -u "${username}" wp eval '$r=wp_remote_get("https://api.wordpress.org/core/version-check/1.7/", ["timeout"=>20]); if (is_wp_error($r) || wp_remote_retrieve_response_code($r)!==200) { exit(1); }' --path="${docroot}"
timeout 5m sudo -u "${username}" wp option update phase30_restore_canary before --path="${docroot}" >/dev/null
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
timeout 5m wp option update phase30_restore_canary after --path="${docroot}" >/dev/null
REMOTE
multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' NAKPANEL_AGENT_SOCKET='/run/nakpanel/agent.sock' NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' panelctl --actor phase30 restore "${backup_id}" --yes >/dev/null
wait_for "Classic restore" "SELECT status FROM restore_runs WHERE backup_id=${backup_id} ORDER BY id DESC LIMIT 1" "active"
multipass exec "${VM_NAME}" -- sudo -u "${username}" bash -se <<'REMOTE'
set -euo pipefail
docroot=/home/"$(id -un)"/domains/phase30-classic.test/public_html
grep -Fxq before "${docroot}/phase30-restore.txt"
test "$(timeout 5m wp option get phase30_restore_canary --path="${docroot}")" = before
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
curl --connect-timeout 5 --max-time 30 --cacert /usr/local/share/ca-certificates/nakpanel-phase30-root.crt --fail --silent \
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
classic_document_root="$(db "SELECT document_root FROM sites WHERE id=${classic_site_id}")"
[[ "${classic_document_root}" == "/home/${username}/"* ]] || fail "Classic document root is not owned by the first subscription"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${second_username}" "${classic_site_id}" "${classic_document_root}" <<'REMOTE'
set -euo pipefail
username="$1"; second_username="$2"; site_id="$3"; classic_document_root="$4"
quotaon -p / | grep -q 'user quota .* is on'
quota -u "${username}" >/tmp/phase30-quota.out
expected_hard_kib=$((512 * 1024))
hard_kib="$(repquota -up / | awk -v user="${username}" '$1==user {print $5; found=1} END{if (!found) exit 1}')"
[[ "${hard_kib}" =~ ^[0-9]+$ ]] || { echo 'effective hard block quota is not numeric' >&2; exit 1; }
test "${hard_kib}" -gt 0 || { echo 'effective hard block quota is unlimited' >&2; exit 1; }
test "${hard_kib}" -eq "${expected_hard_kib}" || {
  echo "effective hard block quota ${hard_kib} KiB does not match plan ${expected_hard_kib} KiB" >&2
  exit 1
}
slug="${username}-phase30-classic-test"
nonempty_artifacts=(
  "${classic_document_root}/wp-config.php"
  "/var/log/nginx/${slug}.access.log"
  "/etc/nakpanel/php-fpm/sites/${site_id}.conf"
  "/etc/nginx/sites-available/phase30-classic.test.conf"
)
existing_artifacts=(
  "/var/log/nginx/${slug}.error.log"
  "/var/log/php-fpm/${slug}.error.log"
  "/etc/nakpanel/secret-keys.json"
)
require_first_subscription_artifact(){
  local path="$1" require_content="$2"
  test -e "${path}" || { echo "first-subscription artifact is missing: ${path}" >&2; exit 1; }
  if [[ "${require_content}" == nonempty ]]; then
    test -s "${path}" || { echo "first-subscription artifact is empty: ${path}" >&2; exit 1; }
  fi
}
assert_cross_subscription_open_denied(){
  local path="$1" error_file
  error_file="$(mktemp)"
  if LC_ALL=C sudo -u "${second_username}" head -c 1 "${path}" >/dev/null 2>"${error_file}"; then
    rm -f "${error_file}"
    echo "cross-subscription open succeeded: ${path}" >&2
    exit 1
  fi
  grep -Fq 'Permission denied' "${error_file}" || {
    cat "${error_file}" >&2
    rm -f "${error_file}"
    echo "cross-subscription probe did not fail with Permission denied: ${path}" >&2
    exit 1
  }
  rm -f "${error_file}"
}
for path in "${nonempty_artifacts[@]}"; do require_first_subscription_artifact "${path}" nonempty; done
for path in "${existing_artifacts[@]}"; do require_first_subscription_artifact "${path}" exists; done
for path in "${nonempty_artifacts[@]}" "${existing_artifacts[@]}"; do assert_cross_subscription_open_denied "${path}"; done
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

# Stdin-backed form input keeps the encrypted write-only secret out of argv,
# guest storage, River arguments, HTML, JSON, audit metadata, and output.
application_secret_result="$(printf '%s' "${APP_SECRET}" | \
  curl --connect-timeout 5 --max-time 30 -sk -w $'\n%{http_code}' \
  -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
  -H 'Accept: application/json' \
  -d 'name=PHASE30_SECRET' -d 'secret=true' --data-urlencode "secret_value@-" \
  "https://${VM_IP}:7443/sites/${managed_site_id}/php-application/environment")"
application_secret_status="${application_secret_result##*$'\n'}"
APPLICATION_SECRET_RESPONSE="${application_secret_result%$'\n'*}"
test "${application_secret_status}" = 200

post_as phase30-healthy-deploy "sites/${managed_site_id}/php-application/deployments" -d 'revision=main'
wait_for "healthy managed deployment" "SELECT status FROM php_deployments WHERE application_id=${managed_application_id} ORDER BY id DESC LIMIT 1" "healthy"
active_deployment_id="$(db "SELECT active_deployment_id FROM php_applications WHERE id=${managed_application_id}")"
managed_body="$(curl --connect-timeout 5 --max-time 30 -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/)"
grep -Fxq 'public=visible' <<<"${managed_body}"
grep -Fxq 'secret=present' <<<"${managed_body}"

post_as phase30-worker "sites/${managed_site_id}/php-application/workers" \
  -d 'name=queue' -d 'script=worker.php' -d 'processes=1' -d 'desired_state=running'
worker_id="$(db "SELECT id FROM php_workers WHERE application_id=${managed_application_id} AND name='queue'")"
wait_for "bounded PHP worker" "SELECT observed_state||':'||convergence_status FROM php_workers WHERE id=${worker_id}" "running:in_sync"
assert_worker_active(){
  local label="$1" id="$2"
  multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-php-worker@${id}.service" || fail "${label}: desired-running PHP worker is inactive"
}
assert_worker_active "desired-running worker before suspension" "${worker_id}"
post_as phase30-stopped-worker "sites/${managed_site_id}/php-application/workers" \
  -d 'name=maintenance' -d 'script=worker.php' -d 'processes=1' -d 'desired_state=stopped'
stopped_worker_id="$(db "SELECT id FROM php_workers WHERE application_id=${managed_application_id} AND name='maintenance'")"
wait_for "desired-stopped worker before suspension" "SELECT desired_state||':'||observed_state||':'||convergence_status FROM php_workers WHERE id=${stopped_worker_id}" "stopped:stopped:in_sync"
assert_worker_inactive(){
  local label="$1" id="$2"
  if multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-php-worker@${id}.service"; then
    fail "${label}: desired-stopped PHP worker is active"
  fi
}
assert_worker_inactive "desired-stopped worker before suspension" "${stopped_worker_id}"

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
curl --connect-timeout 5 --max-time 30 -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/ | grep -Fq 'public=visible'

echo "phase30: prove secret absence from durable/control-plane surfaces"
MANAGED_APPLICATION_HTML="$(curl --connect-timeout 5 --max-time 30 -sk --fail \
  -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${managed_site_id}/applications")"
INITIAL_DATABASE_SURFACES="$(db "
  SELECT args::text FROM river_job
    WHERE kind LIKE '%php%' OR kind IN ('create_database','system_database_mutation');
  SELECT metadata::text FROM audit_events
    WHERE action LIKE 'php.%' OR action LIKE 'database.%';
  SELECT request::text||result::text||last_error FROM server_operations
    WHERE target_type='database';
  SELECT COALESCE(last_error,'')||COALESCE(health_message,'')||COALESCE(composer_audit::text,'')
    FROM php_deployments WHERE application_id=${managed_application_id};")"
INITIAL_JOURNAL="$(multipass_exec_short "${VM_NAME}" -- sudo journalctl \
  -u nakpanel.service -u nakpanel-agent.service --no-pager --output=short-precise \
  --after-cursor "${journal_cursor}")"
INITIAL_SYSTEMD_METADATA="$(multipass_exec_short "${VM_NAME}" -- sudo systemctl show \
  "nakpanel-php-fpm@${managed_site_id}.service" \
  "nakpanel-php-worker@${worker_id}.service" \
  "nakpanel-php-worker@${stopped_worker_id}.service")"
for unit in "nakpanel-php-fpm@${managed_site_id}.service" "nakpanel-php-worker@${worker_id}.service" "nakpanel-php-worker@${stopped_worker_id}.service"; do
  [[ "${INITIAL_SYSTEMD_METADATA}" == *"Id=${unit}"* ]] || fail "failed to capture PHP unit metadata for ${unit}"
done
INITIAL_TENANT_CONFIG="$(multipass_exec_short "${VM_NAME}" -- sudo bash -c \
  "find /etc/nginx /etc/nakpanel/php-fpm -type f -maxdepth 5 -print0 2>/dev/null | xargs -0r grep -h ''")"

multipass exec "${VM_NAME}" -- sudo bash -se -- "${managed_application_id}" "${second_username}" <<'REMOTE'
set -euo pipefail
application_id="$1"; second_username="$2"
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
assert_secret_absent_in_memory(){
  local label="$1" haystack="$2" needle="$3"
  [[ -n "${needle}" ]] || fail "${label}: secret comparison needle is empty"
  [[ "${haystack}" != *"${needle}"* ]] || fail "secret leaked into ${label}"
}
for secret_value in "${APP_SECRET}" "${DB_PASSWORD}" "${WP_ADMIN_PASSWORD}"; do
  assert_secret_absent_in_memory 'River/audit/deployment data' "${INITIAL_DATABASE_SURFACES}" "${secret_value}"
  assert_secret_absent_in_memory 'panel/agent journal' "${INITIAL_JOURNAL}" "${secret_value}"
  assert_secret_absent_in_memory 'exact systemd metadata' "${INITIAL_SYSTEMD_METADATA}" "${secret_value}"
  assert_secret_absent_in_memory 'nginx/PHP configuration' "${INITIAL_TENANT_CONFIG}" "${secret_value}"
  assert_secret_absent_in_memory 'application HTML' "${MANAGED_APPLICATION_HTML}" "${secret_value}"
  assert_secret_absent_in_memory 'application JSON' "${APPLICATION_SECRET_RESPONSE}" "${secret_value}"
  assert_secret_absent_in_memory 'database rotation JSON' "${DATABASE_ROTATION_RESPONSE}" "${secret_value}"
done

echo "phase30: suspend, reactivate, reboot, and reconcile"
post_as phase30-managed-suspend "sites/${managed_site_id}/hosting" -d 'desired_status=suspended' \
  -d 'desired_php_version=8.4' -d 'desired_https_redirect=false'
wait_for "managed suspension" "SELECT desired_state||':'||observed_state FROM php_applications WHERE id=${managed_application_id}" "suspended:suspended"
wait_for_site_http "managed unavailable response" phase30-managed.test 503
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-php-fpm@${managed_site_id}.service" && fail "managed FPM remained active while suspended"
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-php-worker@${worker_id}.service" && fail "managed worker remained active while suspended"
wait_for "desired-stopped worker during suspension" "SELECT desired_state||':'||observed_state FROM php_workers WHERE id=${stopped_worker_id}" "stopped:stopped"
assert_worker_inactive "desired-stopped worker during suspension" "${stopped_worker_id}"

post_as phase30-managed-active "sites/${managed_site_id}/hosting" -d 'desired_status=active' \
  -d 'desired_php_version=8.4' -d 'desired_https_redirect=false'
wait_for "managed reactivation" "SELECT desired_state||':'||observed_state||':'||convergence_status FROM php_applications WHERE id=${managed_application_id}" "active:healthy:in_sync"
wait_for "desired-active worker restoration" "SELECT desired_state||':'||observed_state FROM php_workers WHERE id=${worker_id}" "running:running"
assert_worker_active "desired-running worker after reactivation" "${worker_id}"
wait_for "desired-stopped worker after reactivation" "SELECT desired_state||':'||observed_state FROM php_workers WHERE id=${stopped_worker_id}" "stopped:stopped"
assert_worker_inactive "desired-stopped worker after reactivation" "${stopped_worker_id}"
post_as phase30-managed-reconcile "sites/${managed_site_id}/php-application/reconcile"
wait_for "desired-running worker after explicit reconciliation" "SELECT desired_state||':'||observed_state||':'||convergence_status FROM php_workers WHERE id=${worker_id}" "running:running:in_sync"
assert_worker_active "desired-running worker after explicit reconciliation" "${worker_id}"
wait_for "desired-stopped worker after explicit reconciliation" "SELECT desired_state||':'||observed_state||':'||convergence_status FROM php_workers WHERE id=${stopped_worker_id}" "stopped:stopped:in_sync"
assert_worker_inactive "desired-stopped worker after explicit reconciliation" "${stopped_worker_id}"
curl --connect-timeout 5 --max-time 30 -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/ | grep -Fq 'public=visible'

# Stop both secret-consuming daemons before the reboot-boundary capture. Once
# inactive, they cannot append a later pre-reboot entry outside this snapshot.
PRE_REBOOT_JOURNAL="$(multipass exec "${VM_NAME}" -- sudo bash -se -- "${journal_cursor}" <<'REMOTE'
set -euo pipefail
journal_cursor="$1"
systemctl stop nakpanel.service nakpanel-agent.service
for unit in nakpanel.service nakpanel-agent.service; do
  if systemctl is-active --quiet "${unit}"; then
    echo "${unit} remained active before the journal boundary capture" >&2
    exit 1
  fi
done
journalctl --sync
journalctl -u nakpanel.service -u nakpanel-agent.service --no-pager --output=short-precise \
  --after-cursor "${journal_cursor}"
REMOTE
)"
[[ -n "${PRE_REBOOT_JOURNAL}" ]] || fail "pre-reboot panel/agent journal capture is empty"

multipass restart "${VM_NAME}"
wait_for_cloud_init "${VM_NAME}"
VM_IP="$(vm_ip)"
for _ in $(seq 1 120); do curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null && break; sleep 2; done
cli site reconcile phase30-classic.test >/dev/null
cli reconcile --system >/dev/null
curl --connect-timeout 5 --max-time 30 -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/admin-reboot.html"
post_as phase30-reboot-reconcile "sites/${managed_site_id}/php-application/reconcile"
wait_for "post-reboot managed application" "SELECT observed_state||':'||convergence_status FROM php_applications WHERE id=${managed_application_id}" "healthy:in_sync"
wait_for "post-reboot desired-active worker" "SELECT observed_state||':'||convergence_status FROM php_workers WHERE id=${worker_id}" "running:in_sync"
assert_worker_active "post-reboot desired-running worker" "${worker_id}"
wait_for "post-reboot desired-stopped worker" "SELECT desired_state||':'||observed_state||':'||convergence_status FROM php_workers WHERE id=${stopped_worker_id}" "stopped:stopped:in_sync"
assert_worker_inactive "post-reboot desired-stopped worker" "${stopped_worker_id}"
[[ "$(db "SELECT active_deployment_id FROM php_applications WHERE id=${managed_application_id}")" == "${active_deployment_id}" ]] || fail "reboot changed the active managed release"
trusted_curl phase30-classic.test / | grep -Fq 'Phase 30 WordPress'
curl --connect-timeout 5 --max-time 30 -sS --fail --resolve "phase30-managed.test:80:${VM_IP}" http://phase30-managed.test/ | grep -Fq 'public=visible'

echo "phase30: verify PHP UI and product-boundary copy"
curl --connect-timeout 5 --max-time 30 -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${classic_site_id}/applications" -o "${tmpdir}/classic-app.html"
MANAGED_APPLICATION_HTML="$(curl --connect-timeout 5 --max-time 30 -sk --fail \
  -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${managed_site_id}/applications")"
curl --connect-timeout 5 --max-time 30 -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/tools-settings/php" -o "${tmpdir}/php-runtime.html"
curl --connect-timeout 5 --max-time 30 -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/tools-settings/applications" -o "${tmpdir}/application-catalog.html"
curl --connect-timeout 5 --max-time 30 -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/service-plans/${plan_id}" -o "${tmpdir}/plan.html"
for marker in 'PHP Application' 'Classic'; do grep -Fq "${marker}" "${tmpdir}/classic-app.html" || fail "Classic PHP UI is missing ${marker}"; done
for marker in 'PHP Application' 'Managed' 'PHP workers'; do grep -Fq "${marker}" <<<"${MANAGED_APPLICATION_HTML}" || fail "Managed PHP UI is missing ${marker}"; done
# Runtime inventory is provider-only and must expose detailed readiness.
for marker in 'PHP Runtime Inventory' 'PHP 8.3' 'PHP 8.4' 'PHP 8.5' 'FPM validation' 'OPcache' 'Composer 2.8.11' 'WP-CLI 2.12.0'; do
  grep -Fq "${marker}" "${tmpdir}/php-runtime.html" || fail "runtime inventory is missing ${marker}"
done
for marker in 'Managed PHP deployments' 'PHP workers'; do grep -Fq "${marker}" "${tmpdir}/plan.html" || fail "plan controls are missing ${marker}"; done
for marker in 'Provider Application Catalog' 'OCI only' 'WordPress Toolkit, Node.js, and Python are not implemented'; do
  grep -Fq "${marker}" "${tmpdir}/application-catalog.html" || fail "application catalog boundary is missing ${marker}"
done
for stale_promise in 'Deploy WordPress' 'WordPress Toolkit' 'Node.js application' 'Python application'; do
  if grep -Fq "${stale_promise}" <<<"${MANAGED_APPLICATION_HTML}"; then
    fail "PHP application UI advertises stale runtime promise: ${stale_promise}"
  fi
  if [[ "${stale_promise}" != 'WordPress Toolkit' ]] && grep -Fq "${stale_promise}" "${tmpdir}/application-catalog.html"; then
    fail "application catalog advertises stale runtime promise: ${stale_promise}"
  fi
done

final_secret_non_disclosure_sweep(){
  FINAL_APPLICATION_HTML="$(curl --connect-timeout 5 --max-time 30 -sk --fail \
    -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${managed_site_id}/applications")"
  FINAL_DATABASE_SURFACES="$(db "
    SELECT args::text FROM river_job
      WHERE kind LIKE '%php%' OR kind IN ('create_database','system_database_mutation');
    SELECT metadata::text FROM audit_events
      WHERE action LIKE 'php.%' OR action LIKE 'database.%';
    SELECT request::text||result::text||last_error FROM server_operations
      WHERE target_type='database';
    SELECT COALESCE(last_error,'')||COALESCE(health_message,'')||COALESCE(composer_audit::text,'')
      FROM php_deployments WHERE application_id=${managed_application_id};")"
  FINAL_SYSTEMD_METADATA="$(multipass_exec_short "${VM_NAME}" -- sudo systemctl show \
    "nakpanel-php-fpm@${managed_site_id}.service" \
    "nakpanel-php-worker@${worker_id}.service" \
    "nakpanel-php-worker@${stopped_worker_id}.service")"
  for unit in "nakpanel-php-fpm@${managed_site_id}.service" "nakpanel-php-worker@${worker_id}.service" "nakpanel-php-worker@${stopped_worker_id}.service"; do
    [[ "${FINAL_SYSTEMD_METADATA}" == *"Id=${unit}"* ]] || fail "failed to capture final PHP unit metadata for ${unit}"
  done
  FINAL_TENANT_CONFIG="$(multipass_exec_short "${VM_NAME}" -- sudo bash -c \
    "find /etc/nginx /etc/nakpanel/php-fpm -type f -maxdepth 5 -print0 2>/dev/null | xargs -0r grep -h ''")"
  POST_REBOOT_JOURNAL="$(multipass_exec_short "${VM_NAME}" -- sudo bash -c \
    'journalctl --sync; journalctl -b 0 -u nakpanel.service -u nakpanel-agent.service --no-pager --output=short-precise')"
  FINAL_JOURNAL="${PRE_REBOOT_JOURNAL}"$'\n'"${POST_REBOOT_JOURNAL}"
  [[ -n "${FINAL_JOURNAL}" ]] || fail "final panel/agent journal capture is empty"

  for secret_value in "${APP_SECRET}" "${DB_PASSWORD}" "${WP_ADMIN_PASSWORD}"; do
    assert_secret_absent_in_memory 'final journal window' "${FINAL_JOURNAL}" "${secret_value}"
    assert_secret_absent_in_memory 'final durable database/deployment surfaces' "${FINAL_DATABASE_SURFACES}" "${secret_value}"
    assert_secret_absent_in_memory 'final exact systemd metadata' "${FINAL_SYSTEMD_METADATA}" "${secret_value}"
    assert_secret_absent_in_memory 'final nginx/PHP configuration' "${FINAL_TENANT_CONFIG}" "${secret_value}"
    assert_secret_absent_in_memory 'final application HTML' "${FINAL_APPLICATION_HTML}" "${secret_value}"
    assert_secret_absent_in_memory 'application JSON' "${APPLICATION_SECRET_RESPONSE}" "${secret_value}"
    assert_secret_absent_in_memory 'database rotation JSON' "${DATABASE_ROTATION_RESPONSE}" "${secret_value}"
  done
}
final_secret_non_disclosure_sweep

[[ "$(db "SELECT php_version FROM sites WHERE id=${explicit83_site}")" == "8.3" ]] || fail "explicit PHP 8.3 site changed during Phase 30"
echo "Phase 30 production PHP, WordPress 7.1, managed release, worker, isolation, and reboot verification passed on ${VM_NAME} (${VM_IP})."
