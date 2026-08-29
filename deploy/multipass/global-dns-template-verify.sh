#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "global DNS template verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM:-nakpanel-lab}"

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
fail(){ echo "global DNS template: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){ local query="$1" expected="$2" value=""; for _ in $(seq 1 90); do value="$(db "${query}")"; [[ "${value}" == "${expected}" ]] && return 0; sleep 2; done; fail "got ${value}, want ${expected}: ${query}"; }

for _ in $(seq 1 60); do
  curl -skf -o /dev/null "https://${VM_IP}:7443/login" && break
  sleep 2
done
curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/tools-settings/reauthenticate" >/dev/null

curl -sk --fail -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/tools-settings/dns" -o "${tmpdir}/dns-settings.html"
for marker in 'Zone Records Template' 'SOA Template' 'Transfer Restrictions' 'Synchronization History'; do
  grep -Fq "${marker}" "${tmpdir}/dns-settings.html" || fail "DNS Settings omitted ${marker}"
done

state_revision="$(db "SELECT optimistic_revision FROM dns_template_state WHERE singleton")"
marker="verify-$(date +%s)"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "expected_revision=${state_revision}" -d 'host_template=_nakpanel-template' \
  -d 'record_type=TXT' -d "value_template=${marker}" -d 'scope=all' \
  -d 'priority=0' -d 'weight=0' -d 'port=0' -d 'ttl=300' \
  "https://${VM_IP}:7443/tools-settings/dns/template/records" -o /dev/null

template_revision="$(db "SELECT revision.revision FROM dns_template_state state JOIN dns_template_revisions revision ON revision.id=state.active_revision_id WHERE state.singleton")"
[[ "$(db "SELECT count(*) FROM dns_template_records record JOIN dns_template_state state ON state.active_revision_id=record.revision_id WHERE record.host_template='_nakpanel-template' AND record.value_template='${marker}'")" == "1" ]] ||
  fail "new immutable template revision was not persisted"

zone_id="$(db "SELECT id FROM dns_zones WHERE mode='primary' ORDER BY id LIMIT 1")"
if [[ -n "${zone_id}" ]]; then
  custom_before="$(db "SELECT count(*) FROM dns_records WHERE zone_id=${zone_id} AND origin='custom'")"
  curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
    -d 'scope=all' "https://${VM_IP}:7443/tools-settings/dns/sync/preview" -o /dev/null -D "${tmpdir}/preview.headers"
  location="$(awk 'BEGIN{IGNORECASE=1} /^location:/{gsub(/\r/,""); print $2}' "${tmpdir}/preview.headers" | tail -1)"
  run_id="${location##*run=}"
  run_id="${run_id%%&*}"
  token="$(db "SELECT preview_token FROM dns_template_sync_runs WHERE id=${run_id}")"
  curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
    -d "preview_token=${token}" --data-urlencode 'confirmation=APPLY DNS TEMPLATE' \
    "https://${VM_IP}:7443/tools-settings/dns/sync/${run_id}/apply" -o /dev/null
  wait_for "SELECT status IN ('active','partial') FROM dns_template_sync_runs WHERE id=${run_id}" "t"
  [[ "$(db "SELECT count(*) FROM dns_records WHERE zone_id=${zone_id} AND origin='custom'")" == "${custom_before}" ]] ||
    fail "safe synchronization removed a custom DNS record"
  [[ "$(db "SELECT count(*) FROM dns_records WHERE zone_id=${zone_id} AND host='_nakpanel-template' AND value='${marker}'")" == "1" ]] ||
    fail "template marker was not expanded into the zone"
fi

# Remove verifier-owned template records through the public versioned API, then
# synchronize their removal. This keeps repeated acceptance runs from changing
# the administrator's real template or leaving test records in live zones.
for _ in $(seq 1 20); do
  record_id="$(db "SELECT record.id FROM dns_template_records record JOIN dns_template_state state ON state.active_revision_id=record.revision_id WHERE record.host_template='_nakpanel-template' AND record.value_template LIKE 'verify-%' ORDER BY record.id LIMIT 1")"
  [[ -n "${record_id}" ]] || break
  state_revision="$(db "SELECT optimistic_revision FROM dns_template_state WHERE singleton")"
  curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
    -d "expected_revision=${state_revision}" \
    "https://${VM_IP}:7443/tools-settings/dns/template/records/${record_id}/delete" -o /dev/null
done
[[ "$(db "SELECT count(*) FROM dns_template_records record JOIN dns_template_state state ON state.active_revision_id=record.revision_id WHERE record.host_template='_nakpanel-template' AND record.value_template LIKE 'verify-%'")" == "0" ]] ||
  fail "verifier template records were not cleaned up"

curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d 'scope=all' "https://${VM_IP}:7443/tools-settings/dns/sync/preview" -o /dev/null -D "${tmpdir}/cleanup.headers"
location="$(awk 'BEGIN{IGNORECASE=1} /^location:/{gsub(/\r/,""); print $2}' "${tmpdir}/cleanup.headers" | tail -1)"
cleanup_run_id="${location##*run=}"
cleanup_run_id="${cleanup_run_id%%&*}"
cleanup_token="$(db "SELECT preview_token FROM dns_template_sync_runs WHERE id=${cleanup_run_id}")"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "preview_token=${cleanup_token}" --data-urlencode 'confirmation=APPLY DNS TEMPLATE' \
  "https://${VM_IP}:7443/tools-settings/dns/sync/${cleanup_run_id}/apply" -o /dev/null
wait_for "SELECT status IN ('active','partial') FROM dns_template_sync_runs WHERE id=${cleanup_run_id}" "t"
[[ "$(db "SELECT count(*) FROM dns_records WHERE host='_nakpanel-template' AND value LIKE 'verify-%'")" == "0" ]] ||
  fail "verifier records remained in a synchronized zone"
if [[ -n "${zone_id}" ]]; then
  [[ "$(db "SELECT count(*) FROM dns_records WHERE zone_id=${zone_id} AND origin='custom'")" == "${custom_before}" ]] ||
    fail "cleanup synchronization removed a custom DNS record"
fi
template_revision="$(db "SELECT revision.revision FROM dns_template_state state JOIN dns_template_revisions revision ON revision.id=state.active_revision_id WHERE state.singleton")"

multipass_exec_short "${VM_NAME}" -- sudo named-checkconf
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet named.service
[[ "${template_revision}" =~ ^[0-9]+$ ]] || fail "template revision is not numeric"
echo "Global DNS template verification passed for ${VM_NAME} (${VM_IP}), template revision ${template_revision}."
