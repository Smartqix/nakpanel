#!/usr/bin/env bash
# Actual FastCGI requests and Roundcube login/send/read; CLI php -m is not
# sufficient evidence that the internal web applications work.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
[[ $# -le 1 && ( "${1:-}" == '' || "${1:-}" == --roundcube-only ) ]] || { echo 'internal-tools: expected optional --roundcube-only' >&2; exit 1; }
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
internal_tools_stage=preflight
echo 'internal-tools stage=preflight' || :
# Reject malformed local input before any guest identity, staging or IP call.
if [[ -n "${NAKPANEL_CELL_REPORT_DIR:-}" && -f "${NAKPANEL_CELL_REPORT_DIR}/phase29-fixtures.tsv" ]]; then
  IFS=$'\t' read -r site_id mailbox <"${NAKPANEL_CELL_REPORT_DIR}/phase29-fixtures.tsv"
else
  : "${NAKPANEL_INTERNAL_TOOLS_SITE_ID:?phase29 site fixture is required}"
  : "${NAKPANEL_INTERNAL_TOOLS_MAILBOX:?phase29 mailbox fixture is required}"
  site_id="${NAKPANEL_INTERNAL_TOOLS_SITE_ID}"
  mailbox="${NAKPANEL_INTERNAL_TOOLS_MAILBOX}"
fi
[[ "${site_id}" =~ ^[0-9]+$ && "${mailbox}" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || { echo 'internal-tools: invalid mail fixture' >&2; exit 1; }
domain="${mailbox#*@}"
assert_current_vm_identity
assert_qualification_bundle_staged
VM_IP="$(vm_ip)"
base="https://${VM_IP}:7443"
tmpdir="$(mktemp -d)"
trap 'status=$?; printf "internal-tools exit=%s stage=%s\n" "${status}" "${internal_tools_stage}" || :; rm -rf "${tmpdir}"; exit "${status}"' EXIT
verify_roundcube_send_read() {
  internal_tools_stage=roundcube-runtime-before
  echo 'internal-tools stage=roundcube-runtime-before' || :
  : "${NAKPANEL_RELEASE_BUNDLE:?Roundcube proof requires the selected signed bundle}"
  : "${NAKPANEL_RUN_TOKEN:?Roundcube proof requires an explicit owned run}"
  local receipt_path="${NAKPANEL_INTERNAL_TOOLS_RECEIPT:-${NAKPANEL_CELL_REPORT_DIR:+${NAKPANEL_CELL_REPORT_DIR}/roundcube-send-read.json}}"
  [[ "${receipt_path}" == /* && ! -e "${receipt_path}" && ! -L "${receipt_path}" ]] || { echo 'internal-tools: choose a fresh absolute Roundcube receipt path in an owned case' >&2; return 1; }
  local receipt_parent workflow_dir
  receipt_parent="$(dirname "${receipt_path}")"
  (umask 077; mkdir -p "${receipt_parent}")
  workflow_dir="$(mktemp -d "${receipt_parent}/.roundcube-flow.XXXXXXXX")"
  assert_current_vm_identity
  (umask 077; assert_qualification_installed_release >"${workflow_dir}/installed-before.txt")
  multipass_exec_short "${VM_NAME}" -- sudo cat /etc/stalwart/tls/cert.pem >"${tmpdir}/stalwart-ca.pem"
  (umask 077; printf '%s' "${NAKPANEL_INTERNAL_TOOLS_PASSWORD:-Phase29Mail!2026}" >"${tmpdir}/roundcube-password")
  internal_tools_stage=roundcube-flow
  echo 'internal-tools stage=roundcube-flow' || :
  python3 "${SCRIPT_DIR}/roundcube-send-read.py" --base-url "http://${VM_IP}" --host "webmail.${domain}" \
    --mailbox "${mailbox}" --password-file "${tmpdir}/roundcube-password" \
    --imap-ca-file "${tmpdir}/stalwart-ca.pem" --receipt-dir "${workflow_dir}"
  internal_tools_stage=roundcube-runtime-after
  echo 'internal-tools stage=roundcube-runtime-after' || :
  assert_current_vm_identity
  (umask 077; assert_qualification_installed_release >"${workflow_dir}/installed-after.txt")
  internal_tools_stage=roundcube-enrich
  echo 'internal-tools stage=roundcube-enrich' || :
  python3 "${SCRIPT_DIR}/roundcube-send-read.py" enrich --raw-dir "${workflow_dir}" \
    --manifest "${NAKPANEL_RELEASE_BUNDLE}/manifest.json" --before-proof "${workflow_dir}/installed-before.txt" \
    --after-proof "${workflow_dir}/installed-after.txt" --output "${receipt_path}" --wrapper "${SCRIPT_DIR}/internal-tools-verify.sh" \
    --source-vm "${VM_NAME}" --run-token "${NAKPANEL_RUN_TOKEN}" --release "${IMAGE}" \
    --architecture "${NAKPANEL_MULTIPASS_ARCH}" --profile "${NAKPANEL_QUALIFICATION_PROFILE}" \
    --php-provider "${NAKPANEL_QUALIFICATION_PHP_PROVIDER}" --app-version "${NAKPANEL_RELEASE_VERSION}"
}
if [[ "${1:-}" == --roundcube-only ]]; then
  # Supplement an already qualified runtime without configuring webmail,
  # changing fixtures, or running the independent database-manager workflow.
  verify_roundcube_send_read
  internal_tools_stage=complete
  echo 'internal-tools stage=complete' || :
  exit 0
fi
internal_tools_stage=admin-login
echo 'internal-tools stage=admin-login' || :
curl -skfL --max-time 30 -c "${tmpdir}/admin.cookies" -d email=admin@nakpanel.test -d 'password=NakpanelAdmin!2026' "${base}/login" -o "${tmpdir}/admin.html"
grep -q 'data-np-role="admin"' "${tmpdir}/admin.html"
internal_tools_stage=webmail-configure
echo 'internal-tools stage=webmail-configure' || :
code="$(curl -sk --max-time 30 -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" -d "domain=${domain}" -o "${tmpdir}/configure.html" -w '%{http_code}' "${base}/webmail")"
[[ "${code}" == 303 || "${code}" == 202 ]] || { echo 'internal-tools: webmail configuration returned an unexpected status' >&2; exit 1; }
internal_tools_stage=webmail-readiness
echo 'internal-tools stage=webmail-readiness' || :
ready=0
for _ in $(seq 1 120); do
  state="$(multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "SELECT status FROM webmail_hosts WHERE hostname='webmail.${domain}'")"
  if [[ "${state}" == active ]]; then ready=1; break; fi
  sleep 2
done
[[ "${ready}" == 1 ]] || { echo 'internal-tools: webmail did not become active' >&2; exit 1; }
# Login renders and processes PHP through the nginx FPM socket, then uses
# Stalwart IMAP. The same application must compose/send a unique self-mail
# and render its exact received body. An uncertain send is never retried.
verify_roundcube_send_read
echo 'PASS internal PHP FastCGI + Roundcube login/send/read + Stalwart delivery'
if [[ "${NAKPANEL_VERIFY_DATABASE_MANAGER:-0}" == 1 ]]; then
  internal_tools_stage=database-manager-install
  echo 'internal-tools stage=database-manager-install' || :
  assert_current_vm_identity
  tool_assets="${NAKPANEL_GUEST_RELEASE_DIR:-${NAKPANEL_REMOTE_SRC}}"
  multipass exec "${VM_NAME}" -- sudo bash -se -- "${tool_assets}" <<'DBMANAGER'
set -euo pipefail
timeout 45m "$1/deploy/install/database-manager-install.sh" --yes
systemctl is-active --quiet nakpanel-database-manager
code=$(curl -sS --max-time 10 -o /dev/null -w "%{http_code}" http://127.0.0.1:9082/__nakpanel_health)
test "$code" = 204
DBMANAGER
  # The browser suite covers restricted signon, SQL operations, upload,
  # password rotation, session revocation and tenant boundary controls.
  internal_tools_stage=database-manager-browser
  echo 'internal-tools stage=database-manager-browser' || :
  NAKPANEL_TEST_BASE_URL="${base}" NAKPANEL_TEST_SITE_ID="${site_id}" \
    NAKPANEL_TEST_RESULT="${tmpdir}/database-browser.json" node "${SCRIPT_DIR}/database-workspace-browser-smoke.cjs"
  echo 'PASS database manager FastCGI + restricted browser workflow'
else
  echo 'Database manager optional browser qualification NOT_REQUESTED (set NAKPANEL_VERIFY_DATABASE_MANAGER=1)'
fi
internal_tools_stage=complete
echo 'internal-tools stage=complete' || :
