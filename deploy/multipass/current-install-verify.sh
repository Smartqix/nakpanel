#!/usr/bin/env bash
# Bootstrap the current stack, not historical UI/token contracts.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
if [[ "${NAKPANEL_INSTALL_ONLY:-0}" == 1 && -z "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
  echo 'install-only qualification requires the selected signed release' >&2
  exit 1
fi
if [[ "${NAKPANEL_INSTALL_ONLY:-0}" == 1 && "${NAKPANEL_RELEASE_LEGACY_INSTALLER:-0}" == 1 ]]; then
  echo 'install-only recovery qualification requires modern secure administrator setup' >&2
  exit 1
fi
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
require_nakpanel_vm_name "${VM_NAME}"
ensure_vm 4 6G 48G
sync_repo "${ROOT_DIR}"
assert_current_vm_identity
if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
  stage_qualification_release
  assert_qualification_bundle_staged
fi
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${NAKPANEL_REMOTE_SRC}" "${IMAGE}" "${NAKPANEL_RELEASE_BUNDLE:+1}" "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" "${NAKPANEL_RELEASE_LEGACY_INSTALLER:-0}" "${NAKPANEL_QUALIFICATION_PHP_PROVIDER}" "${NAKPANEL_GUEST_RELEASE_DIR:-}" "${NAKPANEL_GUEST_RELEASE_PUBLIC_KEY:-}" <<'REMOTE'
set -euo pipefail
cd "$1"
if ! id nakpanel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi
if [[ "$3" != 1 ]]; then chown -R nakpanel:nakpanel "$1"; fi
test ! -e /etc/nakpanel/version
export NAKPANEL_RELEASE_ALLOW_DEVELOPMENT="$4"
install_args=(--yes)
if [[ "$6" == sury ]]; then install_args+=(--php-provider sury); fi
if [[ "$3" == 1 ]]; then
  install_args+=(--bundle "$7" --release-public-key "$8")
  if [[ "$4" == 1 ]]; then install_args+=(--allow-development-bundle); fi
fi
if [[ "$5" == 1 ]]; then
  # The historical installer predates --bundle. The host already verified
  # every file and signature before staging this exact trusted artifact.
  timeout 45m "$7/deploy/install/install.sh" --yes --bin-dir "$7/bin"
else
  umask 077
  admin_password_file="$(mktemp /root/nakpanel-qualification-admin.XXXXXXXX)"
  trap 'rm -f "${admin_password_file}"' EXIT
  printf '%s' 'NakpanelAdmin!2026' >"${admin_password_file}"
  install_args+=(--admin-email admin@nakpanel.test --admin-password-file "${admin_password_file}")
  timeout 45m deploy/install/install.sh "${install_args[@]}"
fi
# The installer restores the distribution's normal APT timers. Their first run
# can restart PostgreSQL and other core services; wait read-only before fixtures.
python3 -I -B deploy/multipass/qualification_maintenance_ready.py
systemctl is-active --quiet nakpanel nakpanel-agent nginx postgresql mariadb named stalwart-mail
/usr/local/bin/panelctl version
nginx -t
named-checkconf
sshd -t
REMOTE
VM_IP="$(vm_ip)"
test -n "${VM_IP}"
curl -skf --connect-timeout 5 --max-time 30 "https://${VM_IP}:7443/healthz" >/dev/null
if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then assert_qualification_installed_release; fi
if [[ "${NAKPANEL_INSTALL_ONLY:-0}" == 1 ]]; then
  echo "Fresh signed installation and health verified without product fixtures on ${VM_NAME}."
  exit 0
fi
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
base="https://${VM_IP}:7443"
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
assert_bootstrap_mariadb() {
  local engine name canary
  engine="$(db "SELECT engine FROM databases WHERE id=${database_id}")"
  name="$(db "SELECT db_name FROM databases WHERE id=${database_id}")"
  [[ "${engine}" == mariadb && "${name}" == np_current_bootstrap ]] || {
    echo "current-install: bootstrap database identity is ${engine}:${name}, expected mariadb:np_current_bootstrap" >&2
    return 1
  }
  # The control database's active flag alone cannot prove that MariaDB owns
  # a usable schema. Write and read a canary through the actual engine now,
  # before a later upgrade/restore gate relies on this physical database.
  canary="$(multipass_exec_short "${VM_NAME}" -- sudo mariadb --batch --skip-column-names "${name}" -e "CREATE TABLE IF NOT EXISTS nakpanel_qualification_canary (id TINYINT PRIMARY KEY, value VARCHAR(64) NOT NULL); INSERT INTO nakpanel_qualification_canary VALUES (1,'current-bootstrap-mariadb-canary') ON DUPLICATE KEY UPDATE value=VALUES(value); SELECT value FROM nakpanel_qualification_canary WHERE id=1;")" || return 1
  [[ "${canary}" == current-bootstrap-mariadb-canary ]] || {
    echo 'current-install: physical MariaDB canary did not round trip' >&2
    return 1
  }
}
wait_for(){
  local value=""
  for _ in $(seq 1 120); do
    value="$(db "$1")"
    [[ "${value}" == "$2" ]] && return
    sleep 2
  done
  echo "current-install: expected $2, observed ${value:-empty}" >&2; exit 1
}
curl -skfL --max-time 30 -c "${tmpdir}/cookies" -d email=admin@nakpanel.test \
  -d 'password=NakpanelAdmin!2026' "${base}/login" -o "${tmpdir}/login.html"
grep -q 'data-np-role="admin"' "${tmpdir}/login.html"
if [[ "${NAKPANEL_RELEASE_LEGACY_INSTALLER:-0}" != 1 ]]; then
  [[ "$(db "SELECT count(*) FROM users WHERE email IN ('client@nakpanel.test','reseller@nakpanel.test') AND NOT login_disabled")" == 0 ]] || { echo 'public seed clients remain enabled' >&2; exit 1; }
fi
post(){
  local path="$1" code; shift
  code="$(curl -sk --max-time 30 -b "${tmpdir}/cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/cookies")" -H 'X-Nakpanel-SPA: true' "$@" \
    -o "${tmpdir}/response" -w '%{http_code}' "${base}/${path}")"
  if [[ "${code}" != 303 && "${code}" != 202 ]]; then
    cat "${tmpdir}/response" >&2
    echo "current-install: ${path} returned ${code}" >&2; exit 1
  fi
}
# Fresh bootstrap mail fixtures own their plan and subscription. Never borrow
# a seeded tenant snapshot: mail can be enabled while webmail is disabled.
configure_bootstrap_mail_profile() {
  [[ "${NAKPANEL_RUN_TOKEN:-}" =~ ^[A-Za-z0-9][A-Za-z0-9-]{5,63}$ ]] || { echo 'current-install: invalid fixture owner token' >&2; return 1; }
  case "${NAKPANEL_QUALIFICATION_PROFILE}:${IMAGE}" in
    ubuntu-26.04-native:26.04)
      bootstrap_default_php=8.5; bootstrap_php_versions=8.5; bootstrap_php_json='["8.5"]'
      [[ "${NAKPANEL_BASELINE_PHP}" == 8.5 ]] || return 1 ;;
    ubuntu-24.04:24.04|ubuntu-26.04-sury:26.04)
      bootstrap_default_php=8.4; bootstrap_php_versions=8.3,8.4,8.5; bootstrap_php_json='["8.3","8.4","8.5"]'
      [[ "${NAKPANEL_BASELINE_PHP}" == 8.3 ]] || return 1 ;;
    *) echo 'current-install: unsupported mail fixture profile' >&2; return 1 ;;
  esac
  bootstrap_plan_name="Qualification Mail ${NAKPANEL_RUN_TOKEN}"
  bootstrap_subscription_name="Qualification Bootstrap ${NAKPANEL_RUN_TOKEN}"
}
find_bootstrap_mail_plan() {
  db "SELECT id FROM plans
WHERE reseller_id IS NULL AND name='${bootstrap_plan_name}'
  AND lifecycle_status='active' AND is_active AND hosting_enabled
  AND last_validated_at IS NOT NULL AND readiness_error=''
  AND default_php_version='${bootstrap_default_php}' AND php_allowlist='${bootstrap_php_versions}'
  AND max_mailboxes >= -1 AND max_mailboxes <> 0
  AND hosting_policy#>>'{php,default_version}'='${bootstrap_default_php}'
  AND hosting_policy#>'{php,allowed_versions}'='${bootstrap_php_json}'::jsonb
  AND hosting_policy#>'{permissions,hosting}'='true'::jsonb
  AND hosting_policy#>'{permissions,mail}'='true'::jsonb
  AND hosting_policy#>'{mail,enabled}'='true'::jsonb
  AND hosting_policy#>'{mail,webmail}'='true'::jsonb
  AND jsonb_typeof(hosting_policy#>'{resources,max_mailboxes}')='number'
  AND COALESCE((hosting_policy#>>'{resources,max_mailboxes}')::integer,0) >= -1
  AND COALESCE((hosting_policy#>>'{resources,max_mailboxes}')::integer,0) <> 0
  AND jsonb_typeof(hosting_policy#>'{mail,mailbox_quota_mb}')='number'
  AND COALESCE((hosting_policy#>>'{mail,mailbox_quota_mb}')::integer,0) >= -1
  AND COALESCE((hosting_policy#>>'{mail,mailbox_quota_mb}')::integer,0) <> 0"
}
assert_bootstrap_mail_fixture() {
  local site_filter="" eligible
  [[ "${subscription_id:-}" =~ ^[1-9][0-9]*$ && "${plan_id:-}" =~ ^[1-9][0-9]*$ && "${customer_id:-}" =~ ^[1-9][0-9]*$ ]] || return 1
  if [[ -n "${site_id:-}" ]]; then
    [[ "${site_id}" =~ ^[1-9][0-9]*$ ]] || return 1
    site_filter="AND EXISTS(SELECT 1 FROM sites site WHERE site.id=${site_id} AND site.subscription_id=subscription.id AND site.domain='current-bootstrap.test' AND site.status='active' AND site.desired_status='active' AND site.php_version='${NAKPANEL_BASELINE_PHP}' AND site.desired_php_version='${NAKPANEL_BASELINE_PHP}' AND site.settings_status='in_sync' AND site.removal_state='none') AND NOT EXISTS(SELECT 1 FROM site_policy_overrides WHERE site_id=${site_id})"
  fi
  # With no overrides, the freshly synced snapshot is the effective policy.
  # Check its exact source revision as well as all three mail permission bits.
  eligible="$(db "SELECT count(*) FROM subscriptions subscription
JOIN customers customer ON customer.id=subscription.customer_id AND customer.id=${customer_id} AND customer.email='admin@nakpanel.test' AND customer.status='active' AND customer.reseller_id IS NULL
JOIN plans plan ON plan.id=subscription.plan_id AND plan.id=${plan_id} AND plan.name='${bootstrap_plan_name}' AND plan.reseller_id IS NULL AND plan.lifecycle_status='active' AND plan.is_active AND plan.last_validated_at IS NOT NULL AND plan.readiness_error=''
JOIN subscription_entitlements entitlement ON entitlement.subscription_id=subscription.id AND entitlement.source_revision=plan.revision AND entitlement.plan_name=plan.name
WHERE subscription.id=${subscription_id} AND subscription.name='${bootstrap_subscription_name}' AND subscription.status='active' AND subscription.sync_status='in_sync' AND subscription.plan_mode='synced'
  AND entitlement.hosting_enabled AND entitlement.default_php_version='${bootstrap_default_php}' AND entitlement.php_allowlist='${bootstrap_php_versions}'
  AND entitlement.max_mailboxes >= -1 AND entitlement.max_mailboxes <> 0
  AND entitlement.hosting_policy#>>'{php,default_version}'='${bootstrap_default_php}'
  AND entitlement.hosting_policy#>'{php,allowed_versions}'='${bootstrap_php_json}'::jsonb
  AND entitlement.hosting_policy#>'{permissions,hosting}'='true'::jsonb
  AND entitlement.hosting_policy#>'{permissions,mail}'='true'::jsonb
  AND entitlement.hosting_policy#>'{mail,enabled}'='true'::jsonb
  AND entitlement.hosting_policy#>'{mail,webmail}'='true'::jsonb
  AND jsonb_typeof(entitlement.hosting_policy#>'{resources,max_mailboxes}')='number'
  AND COALESCE((entitlement.hosting_policy#>>'{resources,max_mailboxes}')::integer,0) >= -1
  AND COALESCE((entitlement.hosting_policy#>>'{resources,max_mailboxes}')::integer,0) <> 0
  AND jsonb_typeof(entitlement.hosting_policy#>'{mail,mailbox_quota_mb}')='number'
  AND COALESCE((entitlement.hosting_policy#>>'{mail,mailbox_quota_mb}')::integer,0) >= -1
  AND COALESCE((entitlement.hosting_policy#>>'{mail,mailbox_quota_mb}')::integer,0) <> 0
  AND NOT EXISTS(SELECT 1 FROM subscription_policy_overrides WHERE subscription_id=subscription.id)
  ${site_filter}")" || return 1
  [[ "${eligible}" == 1 ]] || { echo 'current-install: owned fixture effective PHP/mail/webmail entitlement is unavailable' >&2; return 1; }
}
setup_bootstrap_mail_fixture() {
  configure_bootstrap_mail_profile || return 1
  local count version query
  local -a php_args=() bootstrap_versions=()
  # This is fresh-run setup, not adoption or repair of a partial earlier run.
  # Refuse all collisions before the first normal product API call.
  customer_id="$(db "SELECT id FROM customers WHERE email='admin@nakpanel.test' AND reseller_id IS NULL AND status='active'")" || return 1
  [[ "${customer_id}" =~ ^[1-9][0-9]*$ ]] || return 1
  for query in \
    "SELECT count(*) FROM plans WHERE name='${bootstrap_plan_name}'" \
    "SELECT count(*) FROM subscriptions WHERE name='${bootstrap_subscription_name}'" \
    "SELECT count(*) FROM sites WHERE domain='current-bootstrap.test'"; do
    count="$(db "${query}")" || return 1
    [[ "${count}" == 0 ]] || { echo 'current-install: owned fixture row or bootstrap domain already exists; refusing reuse' >&2; return 1; }
  done
  IFS=, read -r -a bootstrap_versions <<<"${bootstrap_php_versions}"
  for version in "${bootstrap_versions[@]}"; do php_args+=(-d "php_versions=${version}"); done
  post plans -d plan_id=0 -d "name=${bootstrap_plan_name}" -d 'description=Owned mail recovery qualification fixture' \
    -d lifecycle_status=active -d change_reason=MailQualification \
    -d disk_mb=5120 -d bandwidth_mb=10240 -d max_sites=4 -d max_databases=4 \
    -d max_mailboxes=4 -d mailbox_quota_mb=64 -d allow_mail=true -d mail_webmail_enabled=true \
    -d max_backups=8 -d backup_storage_mb=5120 -d backup_retention_days=7 -d site_disk_quota_mb=5120 \
    -d max_subdomains=2 -d max_domain_aliases=2 -d php_max_children=3 -d php_memory_mb=256 \
    -d "php_allowlist=${bootstrap_php_versions}" "${php_args[@]}" -d "default_php_version=${bootstrap_default_php}" \
    -d hosting_enabled=true -d allow_dns=true -d allow_tls=true -d allow_backups=true \
    -d overuse_policy=block -d validity_days=365 || return 1
  plan_id="$(find_bootstrap_mail_plan)" || return 1
  [[ "${plan_id}" =~ ^[1-9][0-9]*$ ]] || { echo 'current-install: owned plan is not ready with the required PHP/mail/webmail contract' >&2; return 1; }
  post subscriptions -d customer_mode=existing -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d "subscription_name=${bootstrap_subscription_name}" || return 1
  subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND plan_id=${plan_id} AND name='${bootstrap_subscription_name}'")" || return 1
  [[ "${subscription_id}" =~ ^[1-9][0-9]*$ ]] || return 1
  wait_for "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" in_sync || return 1
  site_id=''
  assert_bootstrap_mail_fixture || return 1
  post sites -d "subscription_id=${subscription_id}" -d domain=current-bootstrap.test -d php_version=${NAKPANEL_BASELINE_PHP} -d issue_certificate=false || return 1
  site_id="$(db "SELECT id FROM sites WHERE domain='current-bootstrap.test'")" || return 1
  [[ "${site_id}" =~ ^[1-9][0-9]*$ ]] || return 1
  wait_for "SELECT status||':'||php_version||':'||desired_php_version||':'||settings_status||':'||removal_state FROM sites WHERE id=${site_id}" "active:${NAKPANEL_BASELINE_PHP}:${NAKPANEL_BASELINE_PHP}:in_sync:none" || return 1
  assert_bootstrap_mail_fixture
}
setup_bootstrap_mail_fixture || exit 1
if [[ "$(db "SELECT count(*) FROM dns_zones WHERE site_id=${site_id}")" == 0 ]]; then
  post dns -d domain=current-bootstrap.test -d "address=${VM_IP}" -d "site_id=${site_id}"
fi
wait_for "SELECT status FROM dns_zones WHERE site_id=${site_id}" active
test -n "$(dig +short "@${VM_IP}" current-bootstrap.test A)"
if [[ "$(db "SELECT tls_status FROM sites WHERE id=${site_id}")" != active ]]; then
  post certificates -d domain=current-bootstrap.test -d issuer=local-self-signed -d "site_id=${site_id}"
fi
wait_for "SELECT tls_status FROM sites WHERE id=${site_id}" active
curl -skf --max-time 20 --resolve "current-bootstrap.test:443:${VM_IP}" https://current-bootstrap.test/ >/dev/null
database_id="$(db "SELECT id FROM databases WHERE db_name='np_current_bootstrap'")"
if [[ -z "${database_id}" ]]; then
  post databases -d "subscription_id=${subscription_id}" -d "site_id=${site_id}" \
    -d engine=mariadb -d db_name=np_current_bootstrap -d db_user=npu_current_bootstrap -d 'password=NakpanelBootstrap_2026'
  database_id="$(db "SELECT id FROM databases WHERE db_name='np_current_bootstrap'")"
fi
[[ "${database_id}" =~ ^[0-9]+$ ]]
wait_for "SELECT status FROM databases WHERE id=${database_id}" active
assert_bootstrap_mariadb
echo "Current installation verified on ${VM_NAME} (${VM_IP})."
