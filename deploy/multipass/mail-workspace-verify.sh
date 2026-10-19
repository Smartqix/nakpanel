#!/usr/bin/env bash
# Fresh synthetic Mail UI objects and real trusted TLS delivery on this owned guest.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
assert_current_vm_identity
assert_qualification_bundle_staged
: "${NAKPANEL_CELL_REPORT_DIR:?cell evidence directory is required}"
IFS=$'\t' read -r site_id mailbox <"${NAKPANEL_CELL_REPORT_DIR}/phase29-fixtures.tsv"
[[ "${site_id}" =~ ^[1-9][0-9]*$ && "${mailbox}" == *@*.test ]]
VM_IP="$(vm_ip)"
customer_id="$(multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo -u postgres psql -Atqd nakpanel -c "SELECT subscription.customer_id FROM sites site JOIN subscriptions subscription ON subscription.id=site.subscription_id WHERE site.id=${site_id}")"
[[ "${customer_id}" =~ ^[1-9][0-9]*$ ]]
umask 077
tmpdir="$(mktemp -d)"
chmod 700 "${tmpdir}"
state="${tmpdir}/mail-state.json"
cleanup_done=0
cleanup() {
  local status=$?
  trap - EXIT
  if [[ "${cleanup_done}" != 1 && -f "${state}" ]]; then
    NAKPANEL_QA_STAGE=cleanup node "${SCRIPT_DIR}/mail-workspace-live-verify.cjs" || true
  fi
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup EXIT
printf '%s' 'NakpanelAdmin!2026' >"${tmpdir}/admin-password"
export NAKPANEL_QA_URL="https://${VM_IP}:7443" NAKPANEL_QA_SITE_ID="${site_id}"
export NAKPANEL_QA_GUEST_IP="${VM_IP}" NAKPANEL_QA_IGNORE_HTTPS_ERRORS=1
export NAKPANEL_QA_SUPPORT_CUSTOMER_ID="${customer_id}" NAKPANEL_QA_MAIL_STATE="${state}"
export NAKPANEL_QA_EMAIL=admin@nakpanel.test NAKPANEL_QA_PASSWORD_FILE="${tmpdir}/admin-password"
node --version
NAKPANEL_QA_STAGE=prepare node "${SCRIPT_DIR}/mail-workspace-live-verify.cjs"
assert_current_vm_identity
# The installed self-signed Stalwart certificate is the explicit trust anchor.
# Connect inside the guest using its matching hostname; TLS verification stays on.
multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo env NAKPANEL_QA_MAIL_CA_FILE=/etc/stalwart/tls/cert.pem \
  bash -c 'export NAKPANEL_QA_MAIL_HOST="$(hostname -f)"; exec python3 "$1"' _ \
  "${NAKPANEL_REMOTE_SRC}/deploy/multipass/mail-workspace-protocol-verify.py" <"${state}"
NAKPANEL_QA_STAGE=scope node "${SCRIPT_DIR}/mail-workspace-live-verify.cjs"
NAKPANEL_QA_STAGE=cleanup node "${SCRIPT_DIR}/mail-workspace-live-verify.cjs"
cleanup_done=1
# HTTPS popup handoff requires a separately configured public webmail TLS hostname.
# The required internal-tools gate independently proves real Roundcube login.
echo 'PASS Mail browser CRUD, rotated-password denial, alias delivery, IMAP and SMTP TLS/STARTTLS, unrelated-customer isolation'
