#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase14-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
quota_target="\$(findmnt -n -o TARGET --target /home)"
if ! findmnt -n -o OPTIONS --target /home | tr ',' '\n' | grep -qx usrquota; then
  sudo mount -o remount,usrquota,grpquota "\${quota_target}"
fi
quota_state="\$(sudo quotaon -p "\${quota_target}" 2>/dev/null || true)"
if ! grep -Eq 'user quota .* is on' <<<"\${quota_state}"; then
  sudo quotacheck -cugm "\${quota_target}" || sudo quotacheck -ugm "\${quota_target}"
  sudo quotaon -uv "\${quota_target}" || true
fi
quota_state="\$(sudo quotaon -p "\${quota_target}" 2>/dev/null || true)"
grep -Eq 'user quota .* is on' <<<"\${quota_state}"
cd "${NAKPANEL_REMOTE_SRC}"
make build
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo -u nakpanel env PATH="\${PATH}" HOME=/var/lib/nakpanel \
  DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo -u postgres psql -d nakpanel -v ON_ERROR_STOP=1 -c "UPDATE subscription_system_accounts SET migration_status='legacy',updated_at=now()-interval '16 minutes' WHERE migration_status='failed';"
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

db_value() {
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}

assert_contains() {
  local file="$1" needle="$2"
  grep -Fq -- "${needle}" "${file}" || { echo "${file} is missing ${needle}" >&2; exit 1; }
}

post_admin() {
  local label="$1" endpoint="$2"
  shift 2
  local status
  status="$(curl -sk -X POST -o "${tmpdir}/${label}.out" -w '%{http_code}' -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "303" ]] || { echo "${label} returned ${status}, want 303" >&2; cat "${tmpdir}/${label}.out" >&2; exit 1; }
}

wait_for_value() {
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 120); do
    value="$(db_value "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  echo "${label}: got ${value}, want ${expected}" >&2
  exit 1
}

schema="$(db_value "SELECT (SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('subscription_system_accounts','subscription_policy_overrides','site_policy_overrides','sftp_access_identities','scheduled_tasks','mail_domains','application_instances'))||':'||(SELECT COUNT(*) FROM information_schema.columns WHERE table_name='sites' AND column_name IN ('system_account_id','document_root'))")"
[[ "${schema}" == "7:2" ]] || { echo "Phase 15 schema is incomplete: ${schema}" >&2; exit 1; }
[[ "$(db_value "SELECT COUNT(*) FROM information_schema.columns WHERE column_name='delete_requested' AND table_name IN ('mail_domains','application_instances')")" == '2' ]] || { echo 'Phase 15 service cleanup schema is incomplete' >&2; exit 1; }
[[ "$(db_value "SELECT COUNT(*) FROM subscriptions")" == "$(db_value "SELECT COUNT(*) FROM subscription_system_accounts")" ]] || { echo 'subscriptions do not have exactly one account' >&2; exit 1; }

curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin.html"

customer_id="$(db_value "SELECT id FROM customers WHERE email='phase15-account@nakpanel.test'")"
if [[ -z "${customer_id}" ]]; then
  post_admin phase15-customer customers -d 'customer_email=phase15-account@nakpanel.test' -d 'customer_name=Phase Fifteen Account'
  customer_id="$(db_value "SELECT id FROM customers WHERE email='phase15-account@nakpanel.test'")"
fi
plan_id="$(db_value "SELECT id FROM plans WHERE reseller_id IS NULL AND is_active=true ORDER BY id LIMIT 1")"
subscription_id="$(db_value "SELECT id FROM subscriptions WHERE name='Phase15 Account Boundary'")"
if [[ -z "${subscription_id}" ]]; then
  post_admin phase15-onboard subscriptions/onboard -d 'customer_mode=existing' -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" \
    -d 'subscription_name=Phase15 Account Boundary' -d 'system_username=phase15acct'
  subscription_id="$(db_value "SELECT id FROM subscriptions WHERE name='Phase15 Account Boundary'")"
else
  post_admin phase15-refresh "subscriptions/${subscription_id}/status" -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" \
    -d 'subscription_name=Phase15 Account Boundary' -d 'status=active' -d 'sync_mode=synced'
fi
wait_for_value 'account convergence' "SELECT convergence_status FROM subscription_system_accounts WHERE subscription_id=${subscription_id}" 'in_sync'
[[ "$(db_value "SELECT username||':'||home_path FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")" == 'phase15acct:/home/phase15acct' ]] || exit 1

site_id="$(db_value "SELECT id FROM sites WHERE domain='phase15-account.test'")"
if [[ -z "${site_id}" ]]; then
  post_admin phase15-domain sites -d "subscription_id=${subscription_id}" -d 'domain=phase15-account.test' -d 'username=phase15acct' -d 'php_version=8.3'
  site_id="$(db_value "SELECT id FROM sites WHERE domain='phase15-account.test'")"
fi
wait_for_value 'shared domain provisioning' "SELECT status FROM sites WHERE id=${site_id}" 'active'
expected_root='/home/phase15acct/domains/phase15-account.test/public_html'
[[ "$(db_value "SELECT username||':'||document_root FROM sites WHERE id=${site_id}")" == "phase15acct:${expected_root}" ]] || exit 1
[[ "$(multipass exec "${VM_NAME}" -- sudo stat -c %U "${expected_root}" | tr -d '[:space:]')" == 'phase15acct' ]] || { echo 'shared document root ownership is incorrect' >&2; exit 1; }

backup_id="$(db_value "SELECT id FROM backups WHERE site_id=${site_id} ORDER BY id DESC LIMIT 1")"
if [[ -z "${backup_id}" ]]; then
  post_admin phase15-backup backups -d "subscription_id=${subscription_id}" -d "site_id=${site_id}" -d 'domain=phase15-account.test'
  backup_id="$(db_value "SELECT id FROM backups WHERE site_id=${site_id} ORDER BY id DESC LIMIT 1")"
fi
wait_for_value 'heavy queue backup' "SELECT status FROM backups WHERE id=${backup_id}" 'active'

post_admin phase15-subscription-policy "subscriptions/${subscription_id}/policy" \
  --data-urlencode 'policy_patch={"resources":{"max_sftp_identities":2,"max_scheduled_tasks":2},"permissions":{"sftp":true,"scheduled_tasks":true},"access":{"shell_mode":"sftp","sftp_only":true},"web":{"request_rate_per_second":0,"request_burst":0,"max_connections":0,"static_cache":true}}'
post_admin phase15-site-policy "sites/${site_id}/policy" \
  --data-urlencode 'policy_patch={"web":{"request_rate_per_second":0,"request_burst":0,"max_connections":0,"static_cache":true},"php":{"memory_limit_mb":0}}'

sftp_id="$(db_value "SELECT id FROM sftp_access_identities WHERE subscription_id=${subscription_id} AND name='phase15-deploy'")"
if [[ -z "${sftp_id}" ]]; then
  post_admin phase15-sftp "subscriptions/${subscription_id}/sftp" -d 'name=phase15-deploy' -d 'relative_root=domains/phase15-account.test' \
    --data-urlencode 'public_key=ssh-ed25519 YWJjZA== phase15-verify' -d 'enabled=true'
  sftp_id="$(db_value "SELECT id FROM sftp_access_identities WHERE subscription_id=${subscription_id} AND name='phase15-deploy'")"
fi
task_id="$(db_value "SELECT id FROM scheduled_tasks WHERE subscription_id=${subscription_id} AND name='phase15-daily'")"
if [[ -z "${task_id}" ]]; then
  post_admin phase15-task "subscriptions/${subscription_id}/scheduled-tasks" -d 'name=phase15-daily' -d 'schedule=0 2 * * *' \
    -d 'working_directory=.' -d 'timeout_seconds=60' -d 'command=/usr/bin/true' -d 'enabled=true'
  task_id="$(db_value "SELECT id FROM scheduled_tasks WHERE subscription_id=${subscription_id} AND name='phase15-daily'")"
fi
wait_for_value 'task convergence' "SELECT convergence_status FROM scheduled_tasks WHERE id=${task_id}" 'in_sync'
multipass exec "${VM_NAME}" -- sudo grep -Fq 'phase15-verify' /home/phase15acct/.ssh/authorized_keys
multipass exec "${VM_NAME}" -- sudo test -f "/etc/systemd/system/nakpanel-task-${task_id}.timer"

post_admin phase15-task-delete "subscriptions/${subscription_id}/services/task/${task_id}/delete"
post_admin phase15-sftp-delete "subscriptions/${subscription_id}/services/sftp/${sftp_id}/delete"
wait_for_value 'service cleanup convergence' "SELECT convergence_status FROM subscription_system_accounts WHERE subscription_id=${subscription_id}" 'in_sync'
multipass exec "${VM_NAME}" -- sudo test ! -e "/etc/systemd/system/nakpanel-task-${task_id}.timer"
if multipass exec "${VM_NAME}" -- sudo grep -Fq 'phase15-verify' /home/phase15acct/.ssh/authorized_keys; then
  echo 'deleted SFTP identity remains in authorized_keys' >&2
  exit 1
fi

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/subscriptions/${subscription_id}" > "${tmpdir}/subscription.html"
for marker in 'Websites &amp; Domains' 'Resources' 'Account Access' 'Mail' 'Scheduled Tasks' 'Applications' 'Activity' 'phase15-account.test'; do
  assert_contains "${tmpdir}/subscription.html" "${marker}"
done
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}?tab=hosting" > "${tmpdir}/domain.html"
for marker in 'Domain policy' 'Request rate per second' 'PHP-FPM children' 'data-np-site-policy-builder'; do
  assert_contains "${tmpdir}/domain.html" "${marker}"
done

[[ "$(db_value "SELECT COUNT(*) FROM river_job WHERE kind='create_site' AND queue='default' AND args->>'site_id'='${site_id}'")" -gt 0 ]] || { echo 'interactive site provisioning left the default queue' >&2; exit 1; }
[[ "$(db_value "SELECT COUNT(*) FROM river_job WHERE kind='create_backup' AND queue='heavy' AND args->>'backup_id'='${backup_id}'")" -gt 0 ]] || { echo 'backup work was not isolated on heavy' >&2; exit 1; }
[[ "$(db_value "SELECT COUNT(*) FROM river_job WHERE kind='maintenance_reconcile' AND queue='maintenance'")" -gt 0 ]] || { echo 'maintenance queue is missing' >&2; exit 1; }

multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC}"
go test ./internal/control/policy ./internal/control/quota ./internal/agent/ops
REMOTE

echo "Phase 15 subscription account and provisioning verification passed for ${VM_NAME} (${VM_IP})."
