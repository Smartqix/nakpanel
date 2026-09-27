#!/usr/bin/env bash
# Phase 31 production service-plan gate. The verifier exercises lifecycle,
# live capability validation, immutable revisions, change preview, synchronized
# subscription compliance, and non-destructive limit recovery on nakpanel-lab.
set -euo pipefail
trap 'status=$?; echo "phase31 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
PHASE31_COMPLETE=0

fail(){ echo "phase31: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${SCRIPT_DIR}/phase30-verify.sh"
fi

require_nakpanel_vm_name "${VM_NAME}"
for tool in curl python3; do
  command -v "${tool}" >/dev/null 2>&1 || fail "host prerequisite ${tool} is not installed"
done

tmpdir="$(mktemp -d)"
cleanup_phase31(){
  local status=$?
  if [[ "${PHASE31_COMPLETE}" != "1" && "${status}" -eq 0 ]]; then
    status=1
  fi
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup_phase31 EXIT

wait_for(){
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 120); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "${label}: got ${value:-empty}, want ${expected}"
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

post_expect(){
  local expected="$1" label="$2" endpoint="$3"
  shift 3
  local status
  status="$(curl --connect-timeout 5 --max-time 30 -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -b "${tmpdir}/admin.cookies" -c "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "${expected}" ]] || {
    echo "${label} returned HTTP ${status}, want ${expected}" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  }
}

set_plan_form(){
  local plan_id="$1" name="$2" lifecycle="$3" max_sites="$4" php_version="$5" reason="$6"
  local disk_mb="${7:-2048}" overuse_policy="${8:-block}"
  plan_form=(
    -d "plan_id=${plan_id}" -d "name=${name}" -d 'description=Phase 31 production contract acceptance'
    -d "lifecycle_status=${lifecycle}" -d "change_reason=${reason}"
    -d "disk_mb=${disk_mb}" -d "max_sites=${max_sites}" -d 'max_databases=2' -d 'bandwidth_mb=-1'
    -d 'max_mailboxes=0' -d 'backup_retention_days=7' -d 'max_backups=4'
    -d 'backup_storage_mb=2048' -d 'site_disk_quota_mb=512'
    -d "php_allowlist=${php_version}" -d "php_versions=${php_version}" -d "default_php_version=${php_version}"
    -d 'php_max_children=3' -d 'php_memory_mb=256' -d 'hosting_enabled=true'
    -d 'allow_tls=true' -d 'allow_backups=true' -d 'allow_php_settings=true'
    -d 'allow_dns=true' -d 'allow_logs=true' -d 'php_opcache_enabled=true'
    -d 'php_log_errors=true' -d "overuse_policy=${overuse_policy}"
    -d 'disk_warning_percent=80' -d 'traffic_warning_percent=80'
    -d 'max_subdomains=0' -d 'max_domain_aliases=0' -d 'max_ftp_accounts=0'
    -d 'validity_days=-1'
  )
}

echo "phase31: install the current plan-contract build"
sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
src="$1"
cd "${src}"
timeout 45m deploy/install/install.sh --yes --allow-downgrade --force
systemctl is-active --quiet nakpanel.service
systemctl is-active --quiet nakpanel-agent.service
test "$(sha256sum bin/panel | awk '{print $1}')" = "$(sha256sum /usr/local/bin/nakpanel-panel | awk '{print $1}')"
REMOTE

VM_IP="$(vm_ip)"
[[ -n "${VM_IP}" ]] || fail "could not determine ${VM_NAME} IPv4 address"
for _ in $(seq 1 120); do
  curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null && break
  sleep 2
done
curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/healthz" >/dev/null || fail "current panel is not healthy"

schema_contract="$(db "SELECT (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='plan_revisions') || ':' || (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='plans' AND column_name IN ('lifecycle_status','last_validated_at','readiness_error')) || ':' || (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='subscriptions' AND column_name IN ('compliance_status','compliance_error','compliance_checked_at'))")"
[[ "${schema_contract}" == '1:3:3' ]] || fail "Phase 31 schema contract is incomplete: ${schema_contract}"

curl --connect-timeout 5 --max-time 30 -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" -o "${tmpdir}/admin.html"
grep -q 'data-np-role="admin"' "${tmpdir}/admin.html" || fail "admin login failed"

curl --connect-timeout 5 --max-time 30 -skf -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/service-plans/new" -o "${tmpdir}/editor.html"
for marker in 'Plan contract' 'Resources' 'Services' 'Customer Permissions' 'Defaults' 'Advanced' 'data-np-enforcement' 'Runtime readiness'; do
  grep -Fq "${marker}" "${tmpdir}/editor.html" || fail "plan editor is missing ${marker}"
done
curl --connect-timeout 5 --max-time 30 -skf "https://${VM_IP}:7443/assets/app.js" -o "${tmpdir}/app.js"
grep -Fq 'Plan preview failed' "${tmpdir}/app.js" || fail "plan preview enhancement is missing"

run_id="$(date +%s)"
draft_name="Phase31 Future ${run_id}"
active_name="Phase31 Production ${run_id}"

echo "phase31: prove draft lifecycle and fail-closed activation"
set_plan_form 0 "${draft_name}" draft 1 9.9 'Future runtime draft'
post_as phase31-draft plans "${plan_form[@]}"
draft_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND name='${draft_name}'")"
[[ "${draft_id}" =~ ^[0-9]+$ ]] || fail "draft plan was not saved"
[[ "$(db "SELECT lifecycle_status||':'||is_active::text FROM plans WHERE id=${draft_id}")" == 'draft:false' ]] || fail "draft lifecycle was not persisted"
post_expect 400 phase31-invalid-activation plans/status -d "plan_id=${draft_id}" -d 'lifecycle_status=active'
grep -Fqi 'cannot activate plan' "${tmpdir}/phase31-invalid-activation.out" || fail "activation rejection is unclear"
[[ "$(db "SELECT lifecycle_status FROM plans WHERE id=${draft_id}")" == 'draft' ]] || fail "failed activation changed draft lifecycle"
[[ -n "$(db "SELECT readiness_error FROM plans WHERE id=${draft_id}")" ]] || fail "failed readiness was not recorded"
curl --connect-timeout 5 --max-time 30 -skf -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/subscriptions/new" -o "${tmpdir}/subscription-new.html"
if grep -Fq ">${draft_name}</option>" "${tmpdir}/subscription-new.html"; then
  fail "draft plan is assignable"
fi

echo "phase31: create a ready plan and immutable initial revision"
set_plan_form 0 "${active_name}" active 2 8.4 'Initial production activation'
post_as phase31-active plans "${plan_form[@]}"
plan_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND name='${active_name}'")"
[[ "${plan_id}" =~ ^[0-9]+$ ]] || fail "active plan was not saved"
readiness="$(db "SELECT lifecycle_status||':'||(last_validated_at IS NOT NULL)::text||':'||(readiness_error='')::text FROM plans WHERE id=${plan_id}")"
[[ "${readiness}" == 'active:true:true' ]] || fail "active plan readiness is invalid: ${readiness}"
revision_contract="$(db "SELECT COUNT(*)||':'||MIN(revision)||':'||MIN(length(definition_hash)) FROM plan_revisions WHERE plan_id=${plan_id}")"
[[ "${revision_contract}" == '1:1:64' ]] || fail "initial revision contract is invalid: ${revision_contract}"
if multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -v ON_ERROR_STOP=1 -d nakpanel \
  -c "UPDATE plan_revisions SET change_reason='tampered' WHERE plan_id=${plan_id}" >/dev/null 2>&1; then
  fail "immutable plan revision accepted an update"
fi

post_as phase31-customer customers -d "customer_email=phase31-${run_id}@nakpanel.test" \
  -d "customer_name=Phase Thirty One ${run_id}" -d 'company=Nakpanel Acceptance'
customer_id="$(db "SELECT id FROM customers WHERE reseller_id IS NULL AND email='phase31-${run_id}@nakpanel.test'")"
post_as phase31-subscription subscriptions -d 'customer_mode=existing' -d "customer_id=${customer_id}" \
  -d "plan_id=${plan_id}" -d "subscription_name=Phase31 Contract ${run_id}"
subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='Phase31 Contract ${run_id}'")"
wait_for 'initial entitlement synchronization' "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" 'in_sync'
domain="phase31-${run_id}.test"
post_as phase31-site sites -d "subscription_id=${subscription_id}" -d "domain=${domain}"
site_id="$(db "SELECT id FROM sites WHERE domain='${domain}'")"
wait_for 'contract site provisioning' "SELECT status FROM sites WHERE id=${site_id}" 'active'

echo "phase31: preview and apply a non-destructive over-limit revision"
set_plan_form "${plan_id}" "${active_name}" active 0 8.4 'Lower site limit acceptance'
post_expect 200 phase31-preview plans/preview -H 'X-Nakpanel-SPA: true' "${plan_form[@]}"
python3 - "${tmpdir}/phase31-preview.out" "${subscription_id}" <<'PY'
import json, sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
preview = payload["preview"]
assert payload["ok"] is True
assert any(change["path"] == "resources.max_sites" and change["enforcement"] == "hard_limit" for change in preview["changes"]), preview
impact = next(item for item in preview["subscription_impacts"] if item["subscription_id"] == int(sys.argv[2]))
assert any(value.startswith("sites 1/0") for value in impact["violations"]), impact
assert any("no resources will be deleted" in value for value in preview["warnings"]), preview
assert preview["allowed"] is True, preview
PY
post_as phase31-lower-limit plans "${plan_form[@]}"
wait_for 'over-limit synchronization' "SELECT sync_status||':'||compliance_status FROM subscriptions WHERE id=${subscription_id}" 'in_sync:over_limit'
compliance_error="$(db "SELECT compliance_error FROM subscriptions WHERE id=${subscription_id}")"
[[ "${compliance_error}" == *'sites 1/0'* ]] || fail "compliance error lacks the exceeded resource: ${compliance_error}"
[[ "$(db "SELECT status FROM sites WHERE id=${site_id}")" == 'active' ]] || fail "plan synchronization deleted or suspended the existing site"

echo "phase31: refresh measured usage and restore compliance"
multipass_exec_short "${VM_NAME}" -- sudo systemctl restart nakpanel
wait_for 'fresh usage collection' "SELECT COALESCE(is_complete,false)::text FROM subscription_usage_current WHERE subscription_id=${subscription_id}" 'true'
set_plan_form "${plan_id}" "${active_name}" active 2 8.4 'Restore compliant site limit'
post_as phase31-restore-limit plans "${plan_form[@]}"
wait_for 'compliance recovery' "SELECT sync_status||':'||compliance_status||':'||(compliance_error='')::text FROM subscriptions WHERE id=${subscription_id}" 'in_sync:compliant:true'

echo "phase31: prove background measurement refreshes compliance"
set_plan_form "${plan_id}" "${active_name}" active 2 8.4 'Enable measured compliance acceptance' 16 normal
post_as phase31-measured-limit plans "${plan_form[@]}"
wait_for 'measured-limit synchronization' "SELECT sync_status||':'||compliance_status FROM subscriptions WHERE id=${subscription_id}" 'in_sync:compliant'
document_root="$(db "SELECT document_root FROM sites WHERE id=${site_id}")"
multipass_exec_short "${VM_NAME}" -- sudo dd if=/dev/zero of="${document_root}/phase31-measured.bin" bs=1M count=20 status=none
multipass_exec_short "${VM_NAME}" -- sudo systemctl restart nakpanel
wait_for 'measured over-limit compliance' "SELECT compliance_status FROM subscriptions WHERE id=${subscription_id}" 'over_limit'
measured_error="$(db "SELECT compliance_error FROM subscriptions WHERE id=${subscription_id}")"
[[ "${measured_error}" == *'disk '*'/16 MB'* ]] || fail "measured compliance error is incomplete: ${measured_error}"
[[ "$(db "SELECT status FROM sites WHERE id=${site_id}")" == 'active' ]] || fail "normal overuse policy suspended the site"
multipass_exec_short "${VM_NAME}" -- sudo rm -f "${document_root}/phase31-measured.bin"
multipass_exec_short "${VM_NAME}" -- sudo systemctl restart nakpanel
wait_for 'measured compliance recovery' "SELECT compliance_status||':'||(compliance_error='')::text FROM subscriptions WHERE id=${subscription_id}" 'compliant:true'

revision_count="$(db "SELECT COUNT(*) FROM plan_revisions WHERE plan_id=${plan_id}")"
[[ "${revision_count}" -ge 4 ]] || fail "revision history is incomplete: ${revision_count}"
distinct_hashes="$(db "SELECT COUNT(DISTINCT definition_hash) FROM plan_revisions WHERE plan_id=${plan_id}")"
[[ "${distinct_hashes}" == "${revision_count}" ]] || fail "revision hashes are not unique: ${distinct_hashes}/${revision_count}"

curl --connect-timeout 5 --max-time 30 -skf -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/service-plans/${plan_id}" -o "${tmpdir}/plan.html"
grep -Fq 'Revision history' "${tmpdir}/plan.html" || fail "revision history is missing from plan detail"
grep -Fq 'Immutable plan contract records' "${tmpdir}/plan.html" || fail "revision immutability is not explained"
curl --connect-timeout 5 --max-time 30 -skf -b "${tmpdir}/admin.cookies" \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}" -o "${tmpdir}/subscription.html"
grep -Fqi 'compliant' "${tmpdir}/subscription.html" || fail "subscription compliance is not visible"

PHASE31_COMPLETE=1
echo "Phase 31 production service-plan verification passed for ${VM_NAME} (${VM_IP})."
