#!/usr/bin/env bash
# Exact, newly-created lab fixtures only. This is not a production reset tool.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
require_nakpanel_vm_name "${VM_NAME}"
if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != 1 ]]; then
  "${SCRIPT_DIR}/phase34-verify.sh"
fi
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
fail(){ echo "domain-removal: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){
  local value=""
  for _ in $(seq 1 180); do value="$(db "$1")"; [[ "${value}" == "$2" ]] && return; sleep 2; done
  fail "database wait failed: expected $2, observed ${value:-empty}"
}
VM_IP="$(vm_ip)"
base="https://${VM_IP}:7443"
curl -skfL --max-time 30 -c "${tmpdir}/cookies" -d email=admin@nakpanel.test \
  -d 'password=NakpanelAdmin!2026' "${base}/login" -o "${tmpdir}/login.html"
grep -q 'data-np-role="admin"' "${tmpdir}/login.html" || fail 'administrator login failed'
post(){
  local path="$1" code; shift
  code="$(curl -sk --max-time 30 -b "${tmpdir}/cookies" -c "${tmpdir}/cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/cookies")" "$@" \
    -o "${tmpdir}/response" -w '%{http_code}' "${base}/${path}")"
  [[ "${code}" == 303 || "${code}" == 202 ]] || { cat "${tmpdir}/response" >&2; fail "${path}: ${code}"; }
}
get_json(){ curl -skf --max-time 30 -b "${tmpdir}/cookies" -H 'Accept: application/json' "${base}/$1"; }
create_site(){
  post sites -d "subscription_id=${subscription_id}" -d "domain=$1" -d php_version=8.4 -d issue_certificate=false
  SITE_ID="$(db "SELECT id FROM sites WHERE subscription_id=${subscription_id} AND domain='$1'")"
  [[ "${SITE_ID}" =~ ^[0-9]+$ ]] || fail 'created site ID missing'
  wait_for "SELECT status FROM sites WHERE id=${SITE_ID}" active
}
remove_site(){
  local id="$1" domain="$2" selected="${3:-}" code request approval
  get_json "sites/${id}/removal/preview" > "${tmpdir}/preview.json"
  [[ "$(jq -r .allowed "${tmpdir}/preview.json")" == true ]] || fail 'fixture removal blocked'
  request="$(jq -r .request_id "${tmpdir}/preview.json")"; approval="$(jq -r .approval "${tmpdir}/preview.json")"
  code="$(curl -sk --max-time 30 -b "${tmpdir}/cookies" -H 'X-Nakpanel-SPA: true' \
    -d "request_id=${request}" --data-urlencode "approval=${approval}" -d "confirm_domain=${domain}" \
    -d acknowledge_permanent=true -o /dev/null -w '%{http_code}' "${base}/sites/${id}/remove")"
  [[ "${code}" == 403 ]] || fail 'removal without CSRF was accepted'
  local args=(-d "request_id=${request}" --data-urlencode "approval=${approval}" -d "confirm_domain=${domain}" -d acknowledge_permanent=true -d include_children=true)
  [[ -z "${selected}" ]] || args+=(-d "delete_database_ids=${selected}")
  post "sites/${id}/remove" -H 'X-Nakpanel-SPA: true' "${args[@]}"
  operation_id="$(jq -r .operation_id "${tmpdir}/response")"
  [[ "${operation_id}" =~ ^[0-9]+$ ]] || fail 'operation ID missing'
}
observe(){
  for _ in $(seq 1 180); do
    get_json "site-removals/${operation_id}/status" > "${tmpdir}/status.json"
    local state; state="$(jq -r .state "${tmpdir}/status.json")"
    if [[ "${state}" == "$1" ]]; then return; fi
    [[ "$(jq -r .redirect "${tmpdir}/status.json")" == '' ]] || fail 'redirect before completed'
    [[ "${state}" != failed || "$1" == failed ]] || { cat "${tmpdir}/status.json" >&2; fail 'removal failed'; }
    sleep 2
  done
  fail 'operation did not converge'
}
run_id="$(date +%s)-$$"
plan="Removal ${run_id}"
post plans -d plan_id=0 -d "name=${plan}" -d lifecycle_status=active -d change_reason=RemovalQA \
  -d disk_mb=-1 -d bandwidth_mb=-1 -d max_sites=4 -d max_subdomains=5 -d max_databases=5 \
  -d max_mailboxes=0 -d max_backups=5 -d backup_storage_mb=-1 -d site_disk_quota_mb=-1 \
  -d php_allowlist=8.4 -d php_versions=8.4 -d default_php_version=8.4 -d php_max_children=2 \
  -d php_memory_mb=256 -d hosting_enabled=true -d allow_backups=true -d allow_dns=true -d allow_tls=true \
  -d overuse_policy=block -d validity_days=-1
plan_id="$(db "SELECT id FROM plans WHERE name='${plan}' AND reseller_id IS NULL")"
post customers -d "customer_email=removal-${run_id}@nakpanel.test" -d "customer_name=Removal ${run_id}" -d enable_login=false
customer_id="$(db "SELECT id FROM customers WHERE email='removal-${run_id}@nakpanel.test'")"
post subscriptions -d customer_mode=existing -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d "subscription_name=Removal ${run_id}"
subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id}")"
wait_for "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" in_sync
primary="primary-${run_id}.test"; addon="addon-${run_id}.test"; sibling="sibling-${run_id}.test"
create_site "${primary}"; primary_id="${SITE_ID}"
[[ "$(db "SELECT primary_site_id FROM subscriptions WHERE id=${subscription_id}")" == "${primary_id}" ]] || fail 'primary identity missing'
get_json "sites/${primary_id}/removal/preview" > "${tmpdir}/primary.json"
[[ "$(jq -r .allowed "${tmpdir}/primary.json")" == false ]] || fail 'primary removal offered'
create_site "${sibling}"; sibling_id="${SITE_ID}"
create_site "${addon}"; addon_id="${SITE_ID}"
post "sites/${addon_id}/subdomains" -d label=child -d issue_certificate=false
child_id="$(db "SELECT id FROM sites WHERE parent_site_id=${addon_id}")"
wait_for "SELECT status FROM sites WHERE id=${child_id}" active
post databases -d "subscription_id=${subscription_id}" -d "site_id=${addon_id}" -d "db_name=removal_${run_id//-/_}" -d 'password=NakpanelRemoval!2026'
database_id="$(db "SELECT id FROM databases WHERE site_id=${addon_id}")"
wait_for "SELECT status FROM databases WHERE id=${database_id}" active
post backups -d "subscription_id=${subscription_id}" -d "domain=${addon}"
backup_id="$(db "SELECT id FROM backups WHERE site_id=${addon_id} ORDER BY id DESC LIMIT 1")"
wait_for "SELECT status FROM backups WHERE id=${backup_id}" active
username="$(db "SELECT username FROM sites WHERE id=${addon_id}")"
stale_id="${addon_id}"
remove_site "${addon_id}" "${addon}"
observe completed
redirect="$(jq -r .redirect "${tmpdir}/status.json")"
[[ "${redirect}" == /subscriptions/* ]] || fail 'unsafe completion redirect'
[[ "$(db "SELECT count(*) FROM sites WHERE id IN (${addon_id},${child_id})")" == 0 ]] || fail 'selected tree still exists'
[[ "$(db "SELECT count(*) FROM databases WHERE id=${database_id} AND site_id IS NULL AND status='active'")" == 1 ]] || fail 'default database retention failed'
[[ "$(db "SELECT count(*) FROM backups WHERE id=${backup_id} AND site_id IS NULL AND status='active'")" == 1 ]] || fail 'default backup retention failed'
curl -skf --max-time 120 -b "${tmpdir}/cookies" "${base}/backups/${backup_id}/download" -o "${tmpdir}/retained.tar.gz"
tar -tzf "${tmpdir}/retained.tar.gz" >/dev/null || fail 'retained backup is unusable'
[[ "$(db "SELECT count(*) FROM sites WHERE id=${sibling_id} AND status='active'")" == 1 ]] || fail 'sibling changed'
create_site "${addon}"; replacement_id="${SITE_ID}"
[[ "${replacement_id}" != "${stale_id}" ]] || fail 'replacement reused the old ID'
# Replay the stale native RPC as the allowed panel UID; it must fail before dispatch.
multipass exec "${VM_NAME}" -- sudo -u nakpanel python3 - "${stale_id}" "${subscription_id}" "${customer_id}" "${username}" "${addon}" <<'PY'
import json,socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect('/run/nakpanel/agent.sock')
data=dict(site_id=int(sys.argv[1]),subscription_id=int(sys.argv[2]),username=sys.argv[4],domain=sys.argv[5],php_version='8.4')
s.sendall((json.dumps(dict(op='create_site',id='removal-stale-native',data=data))+'\n').encode())
result=json.loads(s.makefile().read()); assert not result['ok'] and ('removed' in result.get('error','') or 'retired' in result.get('error','')),result
PY
curl -sf --max-time 20 -H "Host: ${addon}" "http://${VM_IP}/" >/dev/null || fail 'stale RPC harmed the replacement'
# A fixture-only symlink blocks cleanup; retry keeps the same durable scope.
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${addon}" <<'REMOTE'
set -euo pipefail
path="/home/$1/domains/$2"
mv "${path}" "${path}.removal-qa"
ln -s "${path}.removal-qa" "${path}"
REMOTE
remove_site "${replacement_id}" "${addon}"
observe failed
[[ "$(jq -r .redirect "${tmpdir}/status.json")" == '' ]] || fail 'failed removal redirected'
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${addon}" <<'REMOTE'
set -euo pipefail
path="/home/$1/domains/$2"
test -L "${path}"; unlink "${path}"; mv "${path}.removal-qa" "${path}"
REMOTE
post "site-removals/${operation_id}/retry" -H 'X-Nakpanel-SPA: true' -d retry=true
observe completed
curl -skfL --max-time 30 -c "${tmpdir}/client.cookies" -d email=client@nakpanel.test -d 'password=NakpanelClient!2026' "${base}/login" >/dev/null
code="$(curl -sk --max-time 30 -b "${tmpdir}/client.cookies" -o /dev/null -w '%{http_code}' "${base}/site-removals/${operation_id}/status")"
[[ "${code}" == 404 ]] || fail 'cross-customer operation revealed'
multipass exec "${VM_NAME}" -- sudo nginx -t
multipass exec "${VM_NAME}" -- sudo named-checkconf
multipass exec "${VM_NAME}" -- sudo sshd -t
echo "Domain removal acceptance passed on ${VM_NAME}: retained database ${database_id}, backup ${backup_id}; primary ${primary_id} and sibling ${sibling_id} preserved."
