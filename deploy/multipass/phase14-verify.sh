#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase13-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC}"
make build
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo -u nakpanel env PATH="\${PATH}" HOME=/var/lib/nakpanel \
  DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

db_value() {
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}

wait_for_job() {
  local kind="$1"
  for _ in $(seq 1 60); do
    [[ "$(db_value "SELECT COUNT(*) FROM river_job WHERE kind='${kind}' AND queue='maintenance'")" -gt 0 ]] && return 0
    sleep 1
  done
  echo "maintenance job ${kind} was not observed" >&2
  exit 1
}

schema="$(db_value "SELECT (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='sites' AND column_name='tls_auto_renew')||':'||(SELECT COUNT(*) FROM information_schema.columns WHERE table_name='backups' AND column_name='scheduled_for')||':'||(SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name='login_disabled')")"
[[ "${schema}" == "1:1:1" ]] || { echo "Phase 14 schema is incomplete: ${schema}" >&2; exit 1; }
[[ "$(db_value "SELECT login_disabled FROM users WHERE email='scheduler@nakpanel.internal'")" == "t" ]] || { echo 'scheduler identity can log in' >&2; exit 1; }

wait_for_job maintenance_renew_certs
wait_for_job maintenance_reconcile

curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin.html"
site_id="$(db_value "SELECT id FROM sites ORDER BY id LIMIT 1")"
if [[ -n "${site_id}" ]]; then
  status="$(curl -sk -o /dev/null -w '%{http_code}' -b "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    -d 'tls_auto_renew=false' "https://${VM_IP}:7443/sites/${site_id}/tls-auto-renew")"
  [[ "${status}" == "303" ]] || { echo "TLS auto-renew update returned ${status}" >&2; exit 1; }
  [[ "$(db_value "SELECT tls_auto_renew FROM sites WHERE id=${site_id}")" == "f" ]] || exit 1
  curl -sk -o /dev/null -b "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    -d 'tls_auto_renew=true' "https://${VM_IP}:7443/sites/${site_id}/tls-auto-renew"
fi

multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC}"
go test ./internal/agent/ops ./internal/control/maintenance ./internal/control/provision
REMOTE

echo "Phase 14 operational sweeps verification passed for ${VM_NAME} (${VM_IP})."
