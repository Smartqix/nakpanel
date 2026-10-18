#!/usr/bin/env bash
# Actual FastCGI requests and Roundcube authentication; CLI php -m is not
# sufficient evidence that the internal web applications work.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
assert_current_vm_identity
VM_IP="$(vm_ip)"
base="https://${VM_IP}:7443"
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
if [[ -n "${NAKPANEL_CELL_REPORT_DIR:-}" && -f "${NAKPANEL_CELL_REPORT_DIR}/phase29-fixtures.tsv" ]]; then
  IFS=$'\t' read -r site_id mailbox <"${NAKPANEL_CELL_REPORT_DIR}/phase29-fixtures.tsv"
else
  : "${NAKPANEL_INTERNAL_TOOLS_SITE_ID:?phase29 site fixture is required}"
  : "${NAKPANEL_INTERNAL_TOOLS_MAILBOX:?phase29 mailbox fixture is required}"
  site_id="${NAKPANEL_INTERNAL_TOOLS_SITE_ID}"
  mailbox="${NAKPANEL_INTERNAL_TOOLS_MAILBOX}"
fi
[[ "${site_id}" =~ ^[0-9]+$ && "${mailbox}" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]]
domain="${mailbox#*@}"
curl -skfL --max-time 30 -c "${tmpdir}/admin.cookies" -d email=admin@nakpanel.test -d 'password=NakpanelAdmin!2026' "${base}/login" -o "${tmpdir}/admin.html"
grep -q 'data-np-role="admin"' "${tmpdir}/admin.html"
code="$(curl -sk --max-time 30 -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" -d "domain=${domain}" -o "${tmpdir}/configure.html" -w '%{http_code}' "${base}/webmail")"
[[ "${code}" == 303 || "${code}" == 202 ]]
ready=0
for _ in $(seq 1 120); do
  state="$(multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "SELECT status FROM webmail_hosts WHERE hostname='webmail.${domain}'")"
  if [[ "${state}" == active ]]; then ready=1; break; fi
  sleep 2
done
[[ "${ready}" == 1 ]]
# Login renders and processes PHP through the nginx FPM socket, then uses
# Stalwart IMAP. A static file or broken PHP runtime cannot pass this check.
curl -sf --max-time 30 -c "${tmpdir}/roundcube.cookies" -H "Host: webmail.${domain}" "http://${VM_IP}/?_task=login" -o "${tmpdir}/login.html"
rc_token="$(python3 - "${tmpdir}/login.html" <<'PY'
from html.parser import HTMLParser
import sys
class Parser(HTMLParser):
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='input' and a.get('name')=='_token': print(a['value'])
Parser().feed(open(sys.argv[1]).read())
PY
)"
[[ -n "${rc_token}" ]]
curl -sS --max-time 30 -D "${tmpdir}/headers" -o "${tmpdir}/mail.html" -b "${tmpdir}/roundcube.cookies" -c "${tmpdir}/roundcube.cookies" -H "Host: webmail.${domain}" \
  --data-urlencode "_token=${rc_token}" --data-urlencode "_user=${mailbox}" --data-urlencode "_pass=${NAKPANEL_INTERNAL_TOOLS_PASSWORD:-Phase29Mail!2026}" \
  -d _task=login -d _action=login -d _timezone=UTC -d _url= "http://${VM_IP}/?_task=login"
grep -iq 'location: .*_task=mail' "${tmpdir}/headers"
echo 'PASS internal PHP FastCGI + Roundcube login + Stalwart IMAP'
if [[ "${NAKPANEL_VERIFY_DATABASE_MANAGER:-0}" == 1 ]]; then
  assert_current_vm_identity
  multipass exec "${VM_NAME}" -- sudo bash -se -- "${NAKPANEL_REMOTE_SRC}" <<'DBMANAGER'
set -euo pipefail
timeout 45m "$1/deploy/install/database-manager-install.sh" --yes
systemctl is-active --quiet nakpanel-database-manager
code=$(curl -sS --max-time 10 -o /dev/null -w "%{http_code}" http://127.0.0.1:9082/__nakpanel_health)
test "$code" = 204
DBMANAGER
  # The browser suite covers restricted signon, SQL operations, upload,
  # password rotation, session revocation and tenant boundary controls.
  NAKPANEL_TEST_BASE_URL="${base}" NAKPANEL_TEST_SITE_ID="${site_id}" \
    NAKPANEL_TEST_RESULT="${tmpdir}/database-browser.json" node "${SCRIPT_DIR}/database-workspace-browser-smoke.cjs"
  echo 'PASS database manager FastCGI + restricted browser workflow'
else
  echo 'Database manager optional browser qualification NOT_REQUESTED (set NAKPANEL_VERIFY_DATABASE_MANAGER=1)'
fi
