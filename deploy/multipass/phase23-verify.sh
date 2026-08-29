#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase23 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase22-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
fail(){ echo "phase23: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
panel_ready=0
for _ in $(seq 1 60); do
  if curl -skf -o /dev/null "https://${VM_IP}:7443/login"; then
    panel_ready=1
    break
  fi
  sleep 2
done
[[ "${panel_ready}" == "1" ]] || fail "panel is not reachable"
curl -sk --fail -c "${tmpdir}/admin.cookies" -L -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"
site_id="$(db "SELECT id FROM sites WHERE desired_status='active' ORDER BY id LIMIT 1")"
subscription_id="$(db "SELECT subscription_id FROM sites WHERE id=${site_id}")"
domain="$(db "SELECT domain FROM sites WHERE id=${site_id}")"
db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(jsonb_set(COALESCE(hosting_policy,'{}'::jsonb),'{permissions,scheduled_tasks}','true'::jsonb,true),'{permissions,logs}','true'::jsonb,true),'{resources,max_scheduled_tasks}','5'::jsonb,true) WHERE subscription_id=${subscription_id}" >/dev/null
db "DELETE FROM scheduled_task_runs WHERE task_id IN (SELECT id FROM scheduled_tasks WHERE name='phase23-now'); DELETE FROM scheduled_tasks WHERE name='phase23-now';" >/dev/null
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "site_id=${site_id}" -d 'name=phase23-now' -d 'kind=command' -d 'schedule=0,15,30,45 * * * *' -d 'timezone=UTC' \
  --data-urlencode 'command=printf phase23-ok' -d 'working_directory=.' -d 'timeout_seconds=30' -d 'enabled=true' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/scheduled-tasks" -o /dev/null
task_id="$(db "SELECT id FROM scheduled_tasks WHERE name='phase23-now'")"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "site_id=${site_id}" "https://${VM_IP}:7443/subscriptions/${subscription_id}/scheduled-tasks/${task_id}/run" -o /dev/null
[[ "$(db "SELECT status FROM scheduled_task_runs WHERE task_id=${task_id} ORDER BY id DESC LIMIT 1")" == "succeeded" ]] || fail "Run Now did not record a successful task run"
[[ "$(db "SELECT output FROM scheduled_task_runs WHERE task_id=${task_id} ORDER BY id DESC LIMIT 1")" == *phase23-ok* ]] || fail "bounded task output was not stored"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/logs/data?source=nginx_error&limit=50&byte_limit=4096" -o "${tmpdir}/log.json"
grep -Fq '"source":"nginx_error"' "${tmpdir}/log.json" || fail "bounded log API failed"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/statistics" -o "${tmpdir}/statistics.html"
grep -Fq 'subscription-wide quota context' "${tmpdir}/statistics.html" || fail "statistics workspace is missing quota context"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
go test ./internal/control/quota ./internal/agent/ops -run 'Scheduled|SiteLog|Usage' -count=1
REMOTE

echo "Phase 23 logs, statistics, and scheduled tasks verification passed for ${VM_NAME} (${VM_IP})."
