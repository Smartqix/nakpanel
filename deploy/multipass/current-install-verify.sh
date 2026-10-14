#!/usr/bin/env bash
# Bootstrap the current stack, not historical UI/token contracts.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
require_nakpanel_vm_name "${VM_NAME}"
ensure_vm 4 6G 48G
sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${NAKPANEL_REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
cd "$1"
if ! id nakpanel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi
chown -R nakpanel:nakpanel "$1"
timeout 45m deploy/install/install.sh --yes --allow-downgrade --force
systemctl is-active --quiet nakpanel nakpanel-agent nginx postgresql mariadb named stalwart-mail
/usr/local/bin/panelctl version
nginx -t
named-checkconf
sshd -t
REMOTE
VM_IP="$(vm_ip)"
test -n "${VM_IP}"
curl -skf --connect-timeout 5 --max-time 30 "https://${VM_IP}:7443/healthz" >/dev/null
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
base="https://${VM_IP}:7443"
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
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
# The modern native gates need an explicit migrated-runtime/mail/database
# baseline. Create it through product routes, not historical phase fixtures.
subscription_id="$(db "SELECT s.id FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE c.email='admin@nakpanel.test' AND s.status='active' ORDER BY s.id LIMIT 1")"
[[ "${subscription_id}" =~ ^[0-9]+$ ]]
site_id="$(db "SELECT id FROM sites WHERE domain='current-bootstrap.test'")"
if [[ -z "${site_id}" ]]; then
  post sites -d "subscription_id=${subscription_id}" -d domain=current-bootstrap.test -d php_version=8.3 -d issue_certificate=false
  site_id="$(db "SELECT id FROM sites WHERE domain='current-bootstrap.test'")"
fi
[[ "${site_id}" =~ ^[0-9]+$ ]]
wait_for "SELECT status||':'||php_version FROM sites WHERE id=${site_id}" active:8.3
if [[ "$(db "SELECT count(*) FROM dns_zones WHERE site_id=${site_id}")" == 0 ]]; then
  post dns -d domain=current-bootstrap.test -d "address=${VM_IP}" -d "site_id=${site_id}"
fi
wait_for "SELECT status FROM dns_zones WHERE site_id=${site_id}" active
test -n "$(dig +short "@${VM_IP}" current-bootstrap.test A)"
database_id="$(db "SELECT id FROM databases WHERE db_name='np_current_bootstrap'")"
if [[ -z "${database_id}" ]]; then
  post databases -d "subscription_id=${subscription_id}" -d "site_id=${site_id}" \
    -d db_name=np_current_bootstrap -d db_user=npu_current_bootstrap -d 'password=NakpanelBootstrap_2026'
  database_id="$(db "SELECT id FROM databases WHERE db_name='np_current_bootstrap'")"
fi
[[ "${database_id}" =~ ^[0-9]+$ ]]
wait_for "SELECT status FROM databases WHERE id=${database_id}" active
echo "Current installation verified on ${VM_NAME} (${VM_IP})."
