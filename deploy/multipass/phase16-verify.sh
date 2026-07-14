#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase15-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0755 bin/panelctl /usr/local/bin/panelctl
sudo install -d -o nakpanel -g nakpanel -m 0700 /var/lib/nakpanel/tls-staging
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

db_value() {
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}

cli() {
  multipass exec "${VM_NAME}" -- sudo -u nakpanel env \
    NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
    NAKPANEL_AGENT_SOCKET='/run/nakpanel/agent.sock' panelctl --actor phase16-verifier "$@"
}

[[ "$(db_value "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='sessions' AND column_name='id'")" == "1" ]]
[[ "$(db_value "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='audit_events' AND column_name='actor_label'")" == "1" ]]
cli user list | grep -Fq 'admin@nakpanel.test'

cli user suspend client@nakpanel.test --yes
[[ "$(db_value "SELECT status FROM customers WHERE email='client@nakpanel.test'")" == "suspended" ]]
cli user unsuspend client@nakpanel.test
[[ "$(db_value "SELECT status FROM customers WHERE email='client@nakpanel.test'")" == "active" ]]

cli site show phase15-account.test | grep -Fq 'phase15-account.test'
cli site reconcile phase15-account.test >/tmp/phase16-site-reconcile.out
cli reconcile --system >/tmp/phase16-system-reconcile.out
multipass exec "${VM_NAME}" -- sudo systemctl stop nakpanel.service
cli ssl renew phase15-account.test >/tmp/phase16-ssl-renew.out
issue_job_id="$(db_value "SELECT id FROM river_job WHERE kind='issue_cert' AND args->>'domain'='phase15-account.test' ORDER BY id DESC LIMIT 1")"
[[ -n "${issue_job_id}" ]]
multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -v ON_ERROR_STOP=1 -c \
  "DELETE FROM river_job WHERE id=${issue_job_id};" >/tmp/phase16-delete-renew-job.out
multipass exec "${VM_NAME}" -- sudo systemctl start nakpanel.service

subscription_id="$(db_value "SELECT subscription_id FROM sites WHERE domain='phase15-account.test'")"
old_max_backups="$(db_value "SELECT max_backups FROM subscription_entitlements WHERE subscription_id=${subscription_id}")"
backup_count="$(db_value "SELECT COUNT(*) FROM backups WHERE subscription_id=${subscription_id} AND status IN ('pending','active')")"
multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -v ON_ERROR_STOP=1 -c \
  "UPDATE subscription_entitlements SET max_backups=${backup_count} WHERE subscription_id=${subscription_id};" >/tmp/phase16-limit-backups.out
if cli backup create phase15-account.test >/tmp/phase16-over-quota.out 2>&1; then
  echo 'panelctl bypassed the backup entitlement gate' >&2
  exit 1
fi
grep -Eq 'quota exceeded|backup limit' /tmp/phase16-over-quota.out
multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -v ON_ERROR_STOP=1 -c \
  "UPDATE subscription_entitlements SET max_backups=${old_max_backups} WHERE subscription_id=${subscription_id};" >/tmp/phase16-restore-backup-limit.out

backup_id="$(db_value "SELECT id FROM backups WHERE status='active' ORDER BY id DESC LIMIT 1")"
if [[ -n "${backup_id}" ]]; then
  cli restore "${backup_id}" --yes >/tmp/phase16-restore.out
fi

cli agent ping | grep -Fq 'agent connected'
if multipass exec "${VM_NAME}" -- env NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock /usr/local/bin/panelctl agent ping >/tmp/phase16-peer.out 2>&1; then
  echo 'non-panel user reached the agent RPC socket' >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo -u postgres dropdb --if-exists nakpanel_cli_bootstrap
sudo -u postgres createdb -O nakpanel nakpanel_cli_bootstrap
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel_cli_bootstrap?host=/var/run/postgresql&sslmode=disable' \
  go run github.com/riverqueue/river/cmd/river@v0.19.0 migrate-up --line main --database-url 'postgres:///nakpanel_cli_bootstrap?host=/var/run/postgresql&sslmode=disable'
sudo -u nakpanel env DB_DSN='postgres:///nakpanel_cli_bootstrap?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo -u postgres psql -d nakpanel_cli_bootstrap -v ON_ERROR_STOP=1 <<'SQL'
UPDATE subscriptions SET customer_user_id=NULL WHERE customer_user_id IN (SELECT id FROM users WHERE role='admin' AND login_disabled=false);
UPDATE customers SET login_user_id=NULL WHERE login_user_id IN (SELECT id FROM users WHERE role='admin' AND login_disabled=false);
DELETE FROM users WHERE role='admin' AND login_disabled=false;
SQL
sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel_cli_bootstrap?host=/var/run/postgresql&sslmode=disable' \
  panelctl --actor bootstrap-verifier create-admin --email recovery-admin@nakpanel.test --password 'RecoveryAdmin!2026'
sudo systemctl stop nakpanel.service
sudo rm -rf /tmp/nakpanel-phase16-tls
sudo install -d -o nakpanel -g nakpanel -m 0700 /tmp/nakpanel-phase16-tls
sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel_cli_bootstrap?host=/var/run/postgresql&sslmode=disable' \
  NAKPANEL_TLS_DIR=/tmp/nakpanel-phase16-tls nohup /usr/local/bin/nakpanel-panel >/tmp/nakpanel-phase16-panel.log 2>&1 &
echo $! | sudo tee /tmp/nakpanel-phase16-panel.pid >/dev/null
REMOTE

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
ready=0
for _ in $(seq 1 60); do
  if curl -sk --fail "https://${VM_IP}:7443/healthz" >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" != "1" ]]; then
  multipass exec "${VM_NAME}" -- sudo cat /tmp/nakpanel-phase16-panel.log >&2 || true
  echo 'isolated bootstrap panel did not become healthy' >&2
  exit 1
fi
curl -sk --fail -c "${tmpdir}/cookies" -L \
  -d 'email=recovery-admin@nakpanel.test' -d 'password=RecoveryAdmin!2026' \
  "https://${VM_IP}:7443/login" | grep -Fq 'Home'
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel_cli_bootstrap?host=/var/run/postgresql&sslmode=disable' \
  panelctl --actor bootstrap-verifier session list --user recovery-admin@nakpanel.test | grep -Fq recovery-admin@nakpanel.test
sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel_cli_bootstrap?host=/var/run/postgresql&sslmode=disable' \
  panelctl --actor bootstrap-verifier session revoke-user recovery-admin@nakpanel.test --yes
sudo kill "$(cat /tmp/nakpanel-phase16-panel.pid)" || true
sudo systemctl start nakpanel.service
REMOTE

[[ "$(db_value "SELECT COUNT(*) FROM audit_events WHERE actor_label='phase16-verifier'")" -ge 5 ]]
echo "Phase 16 operator CLI verification passed for ${VM_NAME} (${VM_IP})."
