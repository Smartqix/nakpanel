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
# The opt-in fixture explicitly activates the new key/group/dropin. The
# standalone installer deliberately leaves this operator action separate.
python3 - <<'MANAGER_READY'
import http.client,json,os,stat,subprocess,sys,time
def manager_remaining(deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise ValueError('post-maintenance service/DB-manager readiness timed out')
    return remaining

def manager_key(deadline):
    manager_remaining(deadline)
    try:
        fd=os.open('/etc/nakpanel/database-manager.key',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o137 or info.st_size>4096:
                raise ValueError('database-manager key metadata invalid')
            data=os.read(fd,4097)
        finally:os.close(fd)
        key=data.strip().decode('ascii')
    except (OSError,UnicodeError):
        raise ValueError('database-manager private key unavailable') from None
    manager_remaining(deadline)
    if not 32<=len(key)<=4096 or len(data)!=info.st_size or any(ord(c)<32 or ord(c)>126 for c in key):
        raise ValueError('database-manager key format invalid')
    return key

def manager_bridge():
    try:
        info=os.lstat('/run/nakpanel-db-manager/bridge.sock')
    except OSError:return None
    return {'socket':stat.S_ISSOCK(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'mode':oct(stat.S_IMODE(info.st_mode))}

def manager_http(deadline):
    key=manager_key(deadline)
    connection=http.client.HTTPConnection('127.0.0.1',9082,timeout=min(2,manager_remaining(deadline)))
    response=None
    try:
        connection.request('GET','/__nakpanel_health',headers={'X-Nakpanel-Manager-Key':key})
        remaining=manager_remaining(deadline)
        if connection.sock is not None:connection.sock.settimeout(min(2,remaining))
        response=connection.getresponse()
        manager_remaining(deadline)
        return {'status':response.status,'transport':'connected'}
    except ConnectionRefusedError:
        manager_remaining(deadline);return {'status':None,'transport':'refused'}
    except (TimeoutError,OSError,http.client.HTTPException):
        manager_remaining(deadline);return {'status':None,'transport':'unavailable'}
    finally:
        cleanup_failed=False
        try:
            if response is not None:
                try:response.close()
                except (OSError,http.client.HTTPException):cleanup_failed=True
        finally:
            try:connection.close()
            except (OSError,http.client.HTTPException):cleanup_failed=True
        if cleanup_failed:raise ValueError('database-manager connection cleanup failed') from None

def main():
    deadline=time.monotonic()+120
    last={'units':{},'bridge':None,'http_status':None,'transport':None}
    failure='readiness-timeout'
    try:
        restart=subprocess.run(['systemctl','restart','nakpanel.service'],capture_output=True,timeout=min(30,manager_remaining(deadline)))
        manager_remaining(deadline)
        if restart.returncode:raise ValueError('restart-failed')
        while True:
            ready=True
            for unit in ('nakpanel-database-manager.service','nakpanel-database-manager-http.service'):
                result=subprocess.run(['systemctl','show','--property=ActiveState,SubState,Result,ExecMainStatus',unit],capture_output=True,text=True,timeout=min(5,manager_remaining(deadline)))
                manager_remaining(deadline)
                values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
                projected={}
                for key,allowed in [('ActiveState',{'active','inactive','activating','deactivating','failed','reloading'}),('SubState',{'running','dead','exited','start','auto-restart','failed'}),('Result',{'success','exit-code','signal','timeout','start-limit-hit','resources'})]:
                    value=values.get(key);projected[key]=value if value in allowed else None
                code=values.get('ExecMainStatus','');projected['ExecMainStatus']=int(code) if code.isascii() and code.isdecimal() and len(code)<=3 else None
                last['units'][unit]=projected
                ready=(result.returncode==0 and projected['ActiveState']=='active') and ready
            last['bridge']=manager_bridge();manager_remaining(deadline)
            ready=ready and last['bridge'] is not None and last['bridge']['socket']
            if ready:
                checked=manager_http(deadline);last['http_status']=checked['status'];last['transport']=checked['transport']
                ready=checked['status']==204
            manager_remaining(deadline)
            if ready:
                print('PASS database manager authenticated FastCGI readiness')
                return 0
            time.sleep(min(1,manager_remaining(deadline)))
    except subprocess.TimeoutExpired:failure='command-timeout'
    except Exception as error:
        # Never publish exception messages: a key/file/HTTP parser may contain
        # private bytes. Only these fixed classifications leave the guest.
        codes={'restart-failed':'restart-failed',
               'post-maintenance service/DB-manager readiness timed out':'readiness-timeout',
               'database-manager private key unavailable':'private-key-unavailable',
               'database-manager key metadata invalid':'private-key-unavailable',
               'database-manager key format invalid':'private-key-unavailable',
               'database-manager connection cleanup failed':'transport-cleanup-failed'}
        failure=codes.get(str(error),'probe-unavailable') if type(error) is ValueError else 'probe-unavailable'
    last.update(schema='nakpanel-database-manager-readiness-v1',success=False,error_code=failure)
    last['listener_reachable']=True if last['http_status'] is not None else False if last['transport']=='refused' else None
    print(json.dumps(last,sort_keys=True,separators=(',',':')),file=sys.stderr)
    return 1

sys.exit(main())
MANAGER_READY
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
