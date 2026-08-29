#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase26 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

fail() {
  echo "phase26: $*" >&2
  exit 1
}

assert_contains() {
  local path="$1" marker="$2"
  grep -Fq "${marker}" "${path}" || fail "${path} is missing ${marker}"
}

assert_no_privileged_editor() {
  local path="$1"
  if grep -Eiq \
    'href="/(terminal|shell)([/?"]|$)|action="/(terminal|shell)([/?"]|$)|data-np-(raw-config|root-terminal)|name="(command|raw_config|config_fragment)"|>Open root terminal<|>Run arbitrary command<|>Edit raw configuration<' \
    "${path}"; then
    fail "${path} exposes a raw terminal, command, or privileged configuration editor"
  fi
}

run_prior_verifier() {
  local verifier="${NAKPANEL_PHASE26_PRIOR_VERIFIER:-}"
  local candidate
  if [[ -z "${verifier}" ]]; then
    for candidate in \
      phase25-verify.sh phase24-verify.sh phase23-verify.sh \
      phase22-verify.sh phase21-verify.sh phase20-verify.sh; do
      if [[ -x "${SCRIPT_DIR}/${candidate}" ]]; then
        verifier="${SCRIPT_DIR}/${candidate}"
        break
      fi
    done
  fi
  [[ -n "${verifier}" && -x "${verifier}" ]] || fail "no executable Phase 20-25 verifier is available"
  "${verifier}"
}

bootstrap_secret_key() {
  multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
umask 077
if ! id nakpanel >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi
sudo install -d -o root -g nakpanel -m 0750 /etc/nakpanel
if ! sudo test -s /etc/nakpanel/secret-keys.json; then
  key="$(openssl rand -base64 32)"
  key_file="$(mktemp)"
  trap 'rm -f "${key_file}"' EXIT
  printf '{"active_version":1,"keys":{"1":"%s"}}\n' "${key}" >"${key_file}"
  unset key
  sudo install -o nakpanel -g nakpanel -m 0600 "${key_file}" /etc/nakpanel/secret-keys.json
fi
sudo chown nakpanel:nakpanel /etc/nakpanel/secret-keys.json
sudo chmod 0600 /etc/nakpanel/secret-keys.json
[[ "$(sudo stat -c '%U:%G:%a' /etc/nakpanel)" == "root:nakpanel:750" ]]
[[ "$(sudo stat -c '%U:%G:%a' /etc/nakpanel/secret-keys.json)" == "nakpanel:nakpanel:600" ]]
REMOTE
}

ensure_vm 2 3G 16G
bootstrap_secret_key

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  run_prior_verifier
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
if [[ -x bin/panelctl ]]; then
  sudo install -m 0755 bin/panelctl /usr/local/bin/panelctl
fi
sudo install -d -o root -g nakpanel -m 0750 /etc/nakpanel
if ! sudo test -f /etc/nakpanel/secret-keys.json; then
  sudo /usr/local/bin/panelctl secret-key init --path /etc/nakpanel/secret-keys.json
fi
sudo chown nakpanel:nakpanel /etc/nakpanel/secret-keys.json
sudo chmod 0600 /etc/nakpanel/secret-keys.json

# Exercise semantic rollback, not only schema shape. Phase 23 must restore
# legacy subscription-wide tasks, and Phase 25 must restore the exact prior
# entitlement JSON rather than reconstructing it from a mutable plan.
semantic_test_db=nakpanel_toolkit_semantic_rollback
sudo -u postgres dropdb --if-exists --force "${semantic_test_db}" >/dev/null
sudo -u postgres createdb -O nakpanel "${semantic_test_db}"
cleanup_semantic_test_db() {
  sudo -u postgres dropdb --if-exists --force "${semantic_test_db}" >/dev/null
}
trap cleanup_semantic_test_db EXIT
semantic_test_dsn="postgres:///${semantic_test_db}?host=/var/run/postgresql&sslmode=disable"
goose_semantic() {
  sudo -u nakpanel go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 \
    -dir migrations postgres "${semantic_test_dsn}" "$@" >/dev/null
}
goose_semantic up-to 20260723000024
sudo -u postgres psql -v ON_ERROR_STOP=1 -qd "${semantic_test_db}" <<'SQL'
INSERT INTO sites(
  owner_user_id,customer_id,subscription_id,system_account_id,domain,
  username,php_version,status,document_root
)
SELECT customer.login_user_id,subscription.customer_id,subscription.id,account.id,
       'phase23-legacy-rollback.test',account.username,'8.3','active',
       account.home_path || '/domains/phase23-legacy-rollback.test/public_html'
FROM subscriptions subscription
JOIN customers customer ON customer.id=subscription.customer_id
JOIN subscription_system_accounts account ON account.subscription_id=subscription.id
WHERE customer.login_user_id IS NOT NULL
ORDER BY subscription.id
LIMIT 1;
INSERT INTO scheduled_tasks(subscription_id,name,schedule,command,enabled)
SELECT subscription_id,'phase23-legacy-rollback','0 3 * * *','true',true
FROM sites WHERE domain='phase23-legacy-rollback.test';
SQL
goose_semantic up-to 20260723000025
test "$(sudo -u postgres psql -Atqd "${semantic_test_db}" -c \
  "SELECT site_id IS NOT NULL AND phase23_legacy_site_backfill AND phase23_legacy_enabled
   FROM scheduled_tasks WHERE name='phase23-legacy-rollback'")" = t
goose_semantic down
test "$(sudo -u postgres psql -Atqd "${semantic_test_db}" -c \
  "SELECT site_id IS NULL AND enabled
   FROM scheduled_tasks WHERE name='phase23-legacy-rollback'")" = t
goose_semantic up-to 20260723000029
sudo -u postgres psql -v ON_ERROR_STOP=1 -qd "${semantic_test_db}" <<'SQL'
UPDATE subscriptions
SET sync_mode='synced'
WHERE id=(SELECT id FROM subscriptions WHERE plan_id IS NOT NULL ORDER BY id LIMIT 1);
UPDATE subscription_entitlements
SET hosting_policy='{"schema_version":1}'::jsonb
WHERE subscription_id=(SELECT id FROM subscriptions WHERE plan_id IS NOT NULL ORDER BY id LIMIT 1);
UPDATE plans
SET hosting_policy='{"schema_version":2,"permissions":{"git":true}}'::jsonb
WHERE id=(SELECT plan_id FROM subscriptions WHERE plan_id IS NOT NULL ORDER BY id LIMIT 1);
SQL
goose_semantic up-to 20260723000030
test "$(sudo -u postgres psql -Atqd "${semantic_test_db}" -c \
  "SELECT entitlement.hosting_policy=plan.hosting_policy
          AND backup.hosting_policy='{\"schema_version\":1}'::jsonb
   FROM subscriptions subscription
   JOIN plans plan ON plan.id=subscription.plan_id
   JOIN subscription_entitlements entitlement ON entitlement.subscription_id=subscription.id
   JOIN phase25_entitlement_snapshot_backup backup ON backup.subscription_id=subscription.id
   WHERE subscription.plan_id IS NOT NULL ORDER BY subscription.id LIMIT 1")" = t
goose_semantic down
test "$(sudo -u postgres psql -Atqd "${semantic_test_db}" -c \
  "SELECT hosting_policy='{\"schema_version\":1}'::jsonb
   FROM subscription_entitlements
   WHERE subscription_id=(SELECT id FROM subscriptions WHERE plan_id IS NOT NULL ORDER BY id LIMIT 1)")" = t
test "$(sudo -u postgres psql -Atqd "${semantic_test_db}" -c \
  "SELECT to_regclass('public.phase25_entitlement_snapshot_backup') IS NULL")" = t
sudo -u postgres dropdb --force "${semantic_test_db}" >/dev/null
trap - EXIT

migration_test_db=nakpanel_phase26_migration_test
cleanup_migration_test_db() {
  sudo -u postgres dropdb --if-exists --force "${migration_test_db}" >/dev/null
}
trap cleanup_migration_test_db EXIT
cleanup_migration_test_db
sudo -u postgres createdb -O nakpanel "${migration_test_db}"
migration_test_dsn="postgres:///${migration_test_db}?host=/var/run/postgresql&sslmode=disable"
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-up >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT to_regclass('public.server_settings') IS NOT NULL
          AND to_regclass('public.server_inventory') IS NOT NULL
          AND to_regclass('public.server_operations') IS NOT NULL
          AND to_regclass('public.service_secrets') IS NOT NULL
          AND to_regclass('public.server_operations_active_host_action_idx') IS NOT NULL")" = t
# Phase 29 note: later phases stacked migrations above 20260723000034; step
# down through them first so the ladder below keeps asserting the exact
# Phase 26-era rollback semantics it was written for.
sudo -u nakpanel go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 \
  -dir migrations postgres "${migration_test_dsn}" down-to 20260723000034 >/dev/null
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='mail_domains' AND column_name='effective_enabled'
          )
          AND EXISTS (
            SELECT 1 FROM goose_db_version
            WHERE version_id=20260723000033 AND is_applied
          )")" = t
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT to_regprocedure('public.nakpanel_guard_account_teardown()') IS NULL
          AND EXISTS (
            SELECT 1 FROM goose_db_version
            WHERE version_id=20260723000032 AND is_applied
          )")" = t
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='application_instances' AND column_name='desired_revision'
          )
          AND EXISTS (
            SELECT 1 FROM goose_db_version
            WHERE version_id=20260723000031 AND is_applied
          )")" = t
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT to_regclass('public.server_settings') IS NOT NULL
          AND to_regclass('public.server_operations_active_host_action_idx') IS NOT NULL
          AND EXISTS (
            SELECT 1
            FROM goose_db_version
            WHERE version_id=20260723000030 AND is_applied
          )")" = t
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT to_regclass('public.server_settings') IS NOT NULL
          AND to_regclass('public.server_operations_active_host_action_idx') IS NOT NULL
          AND EXISTS (
            SELECT 1
            FROM goose_db_version
            WHERE version_id=20260723000029 AND is_applied
          )")" = t
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT to_regclass('public.server_settings') IS NOT NULL
          AND to_regclass('public.server_operations_active_host_action_idx') IS NULL
          AND EXISTS (
            SELECT 1
            FROM goose_db_version
            WHERE version_id=20260723000028 AND is_applied
          )")" = t
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT to_regclass('public.server_settings') IS NULL")" = t
sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-up >/dev/null
test "$(sudo -u postgres psql -Atqd "${migration_test_db}" -c \
  "SELECT version_id>=20260723000034 AND is_applied FROM goose_db_version ORDER BY id DESC LIMIT 1")" = t
sudo -u postgres psql -v ON_ERROR_STOP=1 -qd "${migration_test_db}" <<'SQL'
DO $$
DECLARE
  source_customer BIGINT;
  target_customer BIGINT;
  source_subscription BIGINT;
  target_subscription BIGINT;
  source_account BIGINT;
  resource_id BIGINT;
BEGIN
  INSERT INTO customers(email,display_name,status)
  VALUES('phase26-source@test','Phase 26 Source','active')
  RETURNING id INTO source_customer;
  INSERT INTO subscriptions(customer_id,name,status,sync_mode,sync_status,plan_revision)
  VALUES(source_customer,'source','active','custom','in_sync',1)
  RETURNING id INTO source_subscription;
  INSERT INTO subscription_system_accounts(
    subscription_id,username,home_path,desired_state,applied_state,migration_status
  ) VALUES(source_subscription,'phase26source','/home/phase26source','active','active','complete')
  RETURNING id INTO source_account;
  INSERT INTO billing_accounts(subscription_id,public_id,external_ref,provisioning_state)
  VALUES(source_subscription,'acc_phase26_source_123456','phase26-source','terminating');

  INSERT INTO customers(email,display_name,status)
  VALUES('phase26-target@test','Phase 26 Target','active')
  RETURNING id INTO target_customer;
  INSERT INTO subscriptions(customer_id,name,status,sync_mode,sync_status,plan_revision)
  VALUES(target_customer,'target','active','custom','in_sync',1)
  RETURNING id INTO target_subscription;
  INSERT INTO subscription_system_accounts(
    subscription_id,username,home_path,desired_state,applied_state,migration_status
  ) VALUES(target_subscription,'phase26target','/home/phase26target','active','active','complete');

  PERFORM set_config('nakpanel.account_teardown','on',true);
  INSERT INTO sites(
    owner_user_id,customer_id,subscription_id,system_account_id,domain,
    username,php_version,status,document_root
  ) VALUES(
    1,source_customer,source_subscription,source_account,'phase26-transfer.test',
    'phase26source','8.3','active',
    '/home/phase26source/domains/phase26-transfer.test/public_html'
  ) RETURNING id INTO resource_id;
  PERFORM set_config('nakpanel.account_teardown','off',true);

  BEGIN
    UPDATE sites
    SET subscription_id=target_subscription,customer_id=target_customer
    WHERE id=resource_id;
    RAISE EXCEPTION 'resource escaped a terminating billing account';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN
    NULL;
  END;
END $$;
SQL

# Prove the Phase 26 rollback guard is valid SQL and refuses to discard the
# only encrypted relay credential with the expected operator-facing reason.
sudo -u postgres psql -v ON_ERROR_STOP=1 -qd "${migration_test_db}" <<'SQL'
UPDATE mail_settings
SET smarthost_host='relay.test',smarthost_password=''
WHERE id;
INSERT INTO service_secrets(
  secret_id,scope,name,key_version,wrapped_key_nonce,wrapped_data_key,
  value_nonce,ciphertext,metadata
) VALUES (
  'sec_12345678901234567890','mail','smarthost',1,
  decode(repeat('00',12),'hex'),decode(repeat('00',48),'hex'),
  decode(repeat('00',12),'hex'),decode(repeat('00',16),'hex'),'{}'
);
SQL
# Roll back everything above the guarded Phase 26 foundation migration so the
# next down executes it. down-to keeps this correct as later phases add
# migrations (a fixed count went stale twice already).
sudo -u nakpanel go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 \
  -dir migrations postgres "${migration_test_dsn}" down-to 20260723000028 >/dev/null
if sudo -u nakpanel env DB_DSN="${migration_test_dsn}" make goose-down >"${migration_test_db}.down.log" 2>&1; then
  echo "phase26: encrypted-credential rollback guard did not refuse downgrade" >&2
  exit 1
fi
grep -Fq "cannot roll back Phase 26: restore the legacy smarthost credential" "${migration_test_db}.down.log" ||
  {
    echo "phase26: rollback failed without the encrypted-credential guard reason" >&2
    cat "${migration_test_db}.down.log" >&2
    exit 1
  }
rm -f "${migration_test_db}.down.log"
cleanup_migration_test_db
trap - EXIT

sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo -u nakpanel env \
  NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json \
  /usr/local/bin/panelctl secret-key migrate --path /etc/nakpanel/secret-keys.json
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

VM_IP="$(vm_ip)"
BASE_URL="https://${VM_IP}:7443"
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT

for _ in $(seq 1 90); do
  curl -skf "${BASE_URL}/healthz" >"${tmpdir}/healthz" && break
  sleep 2
done
assert_contains "${tmpdir}/healthz" "ok"

curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'password=NakpanelAdmin!2026' \
  "${BASE_URL}/login" >/dev/null
curl -sk --fail -b "${tmpdir}/admin.cookies" \
  "${BASE_URL}/tools-settings" -o "${tmpdir}/tools-settings.html"
assert_contains "${tmpdir}/tools-settings.html" 'data-np-role="admin"'
assert_contains "${tmpdir}/tools-settings.html" 'name="viewport"'
assert_contains "${tmpdir}/tools-settings.html" 'data-np-settings-search'
assert_contains "${tmpdir}/tools-settings.html" 'data-np-settings-tool'
assert_contains "${tmpdir}/tools-settings.html" 'data-np-settings-empty'
assert_contains "${tmpdir}/tools-settings.html" 'data-np-settings-health'

for category in \
  'General Settings' \
  'Web &amp; PHP' \
  'Security' \
  'Tools &amp; Resources' \
  'Server Management' \
  'Mail' \
  'Applications &amp; Databases' \
  'Monitoring &amp; Logs' \
  'Panel Administration'; do
  assert_contains "${tmpdir}/tools-settings.html" "${category}"
done

for stale_placeholder in \
  'Privileged agent op pending' \
  'panel.host:7443' \
  'nftables preview'; do
  if grep -Fq "${stale_placeholder}" "${tmpdir}/tools-settings.html"; then
    fail "Tools & Settings still renders placeholder state: ${stale_placeholder}"
  fi
done
assert_no_privileged_editor "${tmpdir}/tools-settings.html"

admin_csrf="$(csrf_token "${tmpdir}/admin.cookies")"
curl -sk --fail -b "${tmpdir}/admin.cookies" \
  -H "Origin: ${BASE_URL}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "csrf_token=${admin_csrf}" \
  --data-urlencode 'password=NakpanelAdmin!2026' \
  "${BASE_URL}/tools-settings/reauthenticate" \
  -o "${tmpdir}/reauthenticate.json"
assert_contains "${tmpdir}/reauthenticate.json" '"ok":true'

service_status="$(curl -sk -o "${tmpdir}/service-action.json" -w '%{http_code}' \
  -b "${tmpdir}/admin.cookies" \
  -H "Origin: ${BASE_URL}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "csrf_token=${admin_csrf}" \
  --data-urlencode 'service_id=web' \
  --data-urlencode 'action=reload' \
  "${BASE_URL}/tools-settings/services/action")"
[[ "${service_status}" == "202" ]] \
  || fail "safe managed web reload returned ${service_status}: $(cat "${tmpdir}/service-action.json")"
assert_contains "${tmpdir}/service-action.json" '"validation":"queued"'

operation_state=""
reload_audits="0"
for _ in $(seq 1 30); do
  operation_state="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c \
    "SELECT status FROM server_operations WHERE category='services' AND action='reload' AND target_type='server_service' AND target_key='web' ORDER BY created_at DESC LIMIT 1")"
  reload_audits="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c \
    "SELECT count(*) FROM audit_events WHERE action='server.service_reload_succeeded'")"
  if [[ "${operation_state//$'\r'/}" == "succeeded" && "${reload_audits//$'\r'/}" -ge 1 ]]; then
    break
  fi
  sleep 1
done
[[ "${operation_state//$'\r'/}" == "succeeded" ]] || fail "managed web reload did not complete successfully"
reauth_audits="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c \
  "SELECT count(*) FROM audit_events WHERE action='server.reauthenticated'")"
[[ "${reauth_audits//$'\r'/}" -ge 1 ]] || fail "administrator reauthentication was not audited"
[[ "${reload_audits//$'\r'/}" -ge 1 ]] || fail "managed web reload was not audited"

curl -sk --fail -b "${tmpdir}/admin.cookies" \
  "${BASE_URL}/assets/app.css" -o "${tmpdir}/app.css"
for css_marker in \
  '.np-settings-health' \
  '.np-settings-tool' \
  '@media (max-width:'; do
  assert_contains "${tmpdir}/app.css" "${css_marker}"
done

# Any focused page advertised by the index is part of the contract. Optional
# modules that are neither linked nor installed remain absent instead of
# becoming misleading, broken controls.
grep -oE 'href="/tools-settings[^"]*"' "${tmpdir}/tools-settings.html" \
  | cut -d'"' -f2 \
  | sed 's/[?#].*$//' \
  | sort -u >"${tmpdir}/focused-routes" || true
while IFS= read -r route; do
  [[ -n "${route}" && "${route}" != "/tools-settings" ]] || continue
  safe_name="$(printf '%s' "${route}" | tr '/?' '__')"
  status="$(curl -sk -o "${tmpdir}/${safe_name}.html" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" "${BASE_URL}${route}")"
  [[ "${status}" == "200" ]] || fail "advertised admin route ${route} returned ${status}"
  assert_contains "${tmpdir}/${safe_name}.html" 'name="viewport"'
  assert_no_privileged_editor "${tmpdir}/${safe_name}.html"
done <"${tmpdir}/focused-routes"

# All focused workspace routes are safe, authenticated reads. They remain
# reachable even when their inventory reports that a component is absent.
for route in \
  /tools-settings/server \
  /tools-settings/php \
  /tools-settings/security \
  /tools-settings/services \
  /tools-settings/logs \
  /tools-settings/updates; do
  safe_name="$(printf '%s' "${route}" | tr '/' '_')"
  status="$(curl -sk -o "${tmpdir}/probe-${safe_name}" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" "${BASE_URL}${route}")"
  [[ "${status}" == "200" ]] || fail "admin route ${route} returned ${status}"
  [[ -s "${tmpdir}/probe-${safe_name}" ]] || fail "${route} returned an empty response"
  assert_contains "${tmpdir}/probe-${safe_name}" 'name="viewport"'
  assert_no_privileged_editor "${tmpdir}/probe-${safe_name}"
done

# These bounded, typed inspection contracts must work with healthy empty
# inventories. Structure is asserted without coupling to mutable host values.
read_contracts=(
  '/tools-settings/inventory|inventory.json|"inventory"'
  '/tools-settings/status|status.json|"inventory"'
  '/tools-settings/journal?source=panel&source=agent&hours=1&limit=25|journal.json|"result"'
  '/tools-settings/updates/inventory|updates.json|"updates"'
  '/tools-settings/operations/updates|managed-updates.json|"updates"'
  '/tools-settings/security/status|security.json|"policy"'
  '/tools-settings/mail/queue?limit=25|mail-queue.json|"queue"'
  '/tools-settings/mail/logs?since_minutes=60&limit=25|mail-logs.json|"logs"'
  '/tools-settings/databases/status|databases.json|"database_admin"'
  '/tools-settings/operations/application-catalog|application-catalog.json|"catalog"'
  '/mail/status|mail-status.json|"state"'
)
for contract in "${read_contracts[@]}"; do
  IFS='|' read -r route output marker <<<"${contract}"
  status="$(curl -sk -o "${tmpdir}/${output}" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" "${BASE_URL}${route}")"
  [[ "${status}" == "200" ]] \
    || fail "read contract ${route} returned ${status}: $(cat "${tmpdir}/${output}")"
  assert_contains "${tmpdir}/${output}" '"ok":true'
  assert_contains "${tmpdir}/${output}" "${marker}"
done
assert_contains "${tmpdir}/inventory.json" '"checked_at"'
# Phase 29 enabled managed firewall and Fail2ban mutation through the staged
# operation lifecycle; SSH policy remains read-only.
assert_contains "${tmpdir}/security.json" '"firewall_mutation":true'
assert_contains "${tmpdir}/security.json" '"ssh_mutation":false'

# Exercise the only safe update action: package simulation. This verifier
# never calls the install or host-power operations.
dry_run_status="$(curl -sk -o "${tmpdir}/update-dry-run.json" -w '%{http_code}' \
  -b "${tmpdir}/admin.cookies" \
  -H "Origin: ${BASE_URL}" \
  -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -X POST "${BASE_URL}/tools-settings/updates/dry-run")"
assert_contains "${tmpdir}/update-dry-run.json" '"ok":true'
assert_contains "${tmpdir}/update-dry-run.json" '"dry_run":true'
case "${dry_run_status}" in
  200)
    # No package was eligible, so there is nothing to enqueue.
    assert_contains "${tmpdir}/update-dry-run.json" '"updates"'
    ;;
  202)
    assert_contains "${tmpdir}/update-dry-run.json" '"operation_id"'
    dry_run_operation="$(sed -n 's/.*"operation_id":"\([^"]*\)".*/\1/p' "${tmpdir}/update-dry-run.json")"
    [[ "${dry_run_operation}" == op_* ]] || fail "update dry-run returned an invalid operation id"
    dry_run_state=""
    for _ in $(seq 1 90); do
      dry_run_state="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c \
        "SELECT status FROM server_operations WHERE operation_id='${dry_run_operation}'")"
      [[ "${dry_run_state}" == "succeeded" || "${dry_run_state}" == "failed" ]] && break
      sleep 1
    done
    [[ "${dry_run_state}" == "succeeded" ]] \
      || fail "queued update dry-run ${dry_run_operation} ended in ${dry_run_state:-missing}"
    ;;
  *)
    fail "update dry-run returned ${dry_run_status}: $(cat "${tmpdir}/update-dry-run.json")"
    ;;
esac

# Bounds and registry IDs are validated before privileged code is reached.
for rejected_route in \
  '/tools-settings/journal?source=panel&limit=5000' \
  '/tools-settings/journal?source=not-registered&limit=25' \
  '/tools-settings/mail/logs?since_minutes=60&limit=501' \
  '/tools-settings/mail/queue/not-a-message'; do
  status="$(curl -sk -o /dev/null -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" "${BASE_URL}${rejected_route}")"
  [[ "${status}" == "400" ]] \
    || fail "unsafe reader input ${rejected_route} returned ${status}, want 400"
done

# Phase 12 creates this deterministic reseller and every later chained
# verifier preserves it. Resellers may receive provider-scoped utilities, but
# never the host-wide settings or focused server controls.
curl -sk --fail -c "${tmpdir}/reseller.cookies" -L \
  -d 'email=phase12-reseller@nakpanel.test' \
  -d 'password=NakpanelPhase12!2026' \
  "${BASE_URL}/login" -o "${tmpdir}/reseller-dashboard.html"
assert_contains "${tmpdir}/reseller-dashboard.html" 'data-np-role="reseller"'
reseller_csrf="$(csrf_token "${tmpdir}/reseller.cookies")"
if grep -Fq 'Tools &amp; Settings' "${tmpdir}/reseller-dashboard.html"; then
  fail "reseller navigation exposes host-wide Tools & Settings"
fi
for route in \
  /tools-settings \
  /tools-settings/server \
  /tools-settings/php \
  /tools-settings/security \
  /tools-settings/services \
  /tools-settings/logs \
  /tools-settings/updates \
  /tools-settings/inventory \
  /tools-settings/status \
  '/tools-settings/journal?source=panel&limit=25' \
  /tools-settings/updates/inventory \
  /tools-settings/operations/updates \
  /tools-settings/security/status \
  '/tools-settings/mail/queue?limit=25' \
  '/tools-settings/mail/logs?since_minutes=60&limit=25' \
  /tools-settings/databases/status \
  /tools-settings/operations/application-catalog; do
  status="$(curl -sk -o /dev/null -w '%{http_code}' \
    -b "${tmpdir}/reseller.cookies" "${BASE_URL}${route}")"
  [[ "${status}" == "403" || "${status}" == "404" ]] \
    || fail "reseller reached admin route ${route}: HTTP ${status}"
done
reseller_dry_run_status="$(curl -sk -o /dev/null -w '%{http_code}' \
  -b "${tmpdir}/reseller.cookies" \
  -H "Origin: ${BASE_URL}" \
  -H "X-Nakpanel-CSRF: ${reseller_csrf}" \
  -X POST "${BASE_URL}/tools-settings/updates/dry-run")"
[[ "${reseller_dry_run_status}" == "403" ]] \
  || fail "reseller update dry-run returned ${reseller_dry_run_status}, want 403"

utilities_status="$(curl -sk -o "${tmpdir}/tools-utilities.html" -w '%{http_code}' \
  -b "${tmpdir}/reseller.cookies" "${BASE_URL}/tools-utilities")"
case "${utilities_status}" in
  200)
    assert_contains "${tmpdir}/tools-utilities.html" 'Tools &amp; Utilities'
    assert_no_privileged_editor "${tmpdir}/tools-utilities.html"
    ;;
  404) ;;
  *) fail "reseller Tools & Utilities returned ${utilities_status}" ;;
esac

curl -sk --fail -c "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'password=NakpanelClient!2026' \
  "${BASE_URL}/login" >/dev/null
for route in \
  /tools-settings \
  /tools-settings/inventory \
  '/tools-settings/journal?source=panel&limit=25' \
  /tools-settings/updates/inventory \
  /tools-settings/operations/updates \
  /tools-settings/security/status \
  '/tools-settings/mail/queue?limit=25' \
  '/tools-settings/mail/logs?since_minutes=60&limit=25' \
  /tools-settings/databases/status \
  /tools-settings/operations/application-catalog; do
  client_status="$(curl -sk -o /dev/null -w '%{http_code}' \
    -b "${tmpdir}/client.cookies" "${BASE_URL}${route}")"
  [[ "${client_status}" == "403" ]] \
    || fail "customer reached admin route ${route}: HTTP ${client_status}"
done

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
go test ./internal/control/http ./internal/control/web ./internal/agent/ops ./internal/agent/rpc -count=1
REMOTE

echo "Phase 26 implemented Tools & Settings surface verification passed for ${VM_NAME} (${VM_IP})."
