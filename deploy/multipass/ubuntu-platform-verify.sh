#!/usr/bin/env bash
# One native release/architecture cell. Every gate produces evidence; any
# failure leaves the owned VM and its report available for diagnosis.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
init_qualification_run
: "${NAKPANEL_RELEASE_BUNDLE:?set the architecture-compatible signed release bundle}"
: "${NAKPANEL_RELEASE_PUBLIC_KEY:?set the out-of-band release public key}"
: "${NAKPANEL_RELEASE_VERSION:?set the expected application release version}"
[[ "$(multipass_host_arch)" == "${NAKPANEL_MULTIPASS_ARCH}" ]] || { echo 'native runner architecture mismatch' >&2; exit 1; }
export NAKPANEL_CELL_REPORT_DIR="${NAKPANEL_CELL_REPORT_DIR:-${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}/reports/${NAKPANEL_MULTIPASS_IMAGE}-${NAKPANEL_MULTIPASS_ARCH}}"
# Never append evidence to an old run or overwrite a prior result.
mkdir "${NAKPANEL_CELL_REPORT_DIR}" 2>/dev/null || { mkdir -p "$(dirname "${NAKPANEL_CELL_REPORT_DIR}")"; mkdir "${NAKPANEL_CELL_REPORT_DIR}"; }
chmod 700 "${NAKPANEL_CELL_REPORT_DIR}"
python3 - "${NAKPANEL_CELL_REPORT_DIR}/run.env" <<'PY'
import os,shlex,sys
# Explicit nonsecret configuration only; never dump the runner environment.
names=['NAKPANEL_RUN_TOKEN','NAKPANEL_MULTIPASS_VM','NAKPANEL_MULTIPASS_SOURCE_VM',
 'NAKPANEL_MULTIPASS_DR_VM','NAKPANEL_MULTIPASS_IMAGE','NAKPANEL_MULTIPASS_ARCH',
 'NAKPANEL_REMOTE_SRC','NAKPANEL_GUEST_QUALIFICATION_ROOT','NAKPANEL_GUEST_RELEASE_DIR',
 'NAKPANEL_GUEST_RELEASE_PUBLIC_KEY','NAKPANEL_RELEASE_BUNDLE','NAKPANEL_RELEASE_PUBLIC_KEY',
 'NAKPANEL_RELEASE_VERSION','NAKPANEL_RELEASE_ALLOW_DEVELOPMENT',
 'NAKPANEL_QUALIFICATION_PHP_PROVIDER','NAKPANEL_CELL_REPORT_DIR','NAKPANEL_OWNERSHIP_DIR',
 'NAKPANEL_MULTIPASS_IMAGE_SOURCE','NAKPANEL_MULTIPASS_IMAGE_SHA256','NAKPANEL_HOSTED_GUEST_FIRMWARE_POLICY',
 'NAKPANEL_QUALIFICATION_VM_CPUS',
 'NAKPANEL_QUALIFICATION_VM_MEMORY','NAKPANEL_QUALIFICATION_VM_DISK',
 'NAKPANEL_QUALIFICATION_DR_CPUS','NAKPANEL_QUALIFICATION_DR_MEMORY','NAKPANEL_QUALIFICATION_DR_DISK',
 'NAKPANEL_VERIFY_DATABASE_MANAGER','NAKPANEL_REMOVAL_BROWSER_SMOKE','PLAYWRIGHT_MODULE','NODE_PATH']
with os.fdopen(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as target:
 for name in names:
  if name in os.environ:target.write('export '+name+'='+shlex.quote(os.environ[name])+'\n')
PY
results="${NAKPANEL_CELL_REPORT_DIR}/gates.tsv"
: >"${results}"
complete=0
finish() {
  local status=$?
  trap - EXIT
  if [[ "${status}" != 0 ]]; then
    # Collection is read-only, requires ownership, and cannot turn a failure
    # into success. Never collect secrets or an unrestricted environment.
    if assert_current_vm_identity >"${NAKPANEL_CELL_REPORT_DIR}/failure-identity.log" 2>&1; then
      multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -c 'systemctl --failed --no-pager; journalctl -b -p err --no-pager -n 100' >"${NAKPANEL_CELL_REPORT_DIR}/failure-system.log" 2>&1 || true
    fi
  fi
  python3 - "${results}" "${complete}" "${status}" <<'PY'
import json, os, pathlib, sys
rows=[line.rstrip('\n').split('\t') for line in open(sys.argv[1])]
expected=['bundle','fresh-install','inventory','phase28','valkey-platform','security','phase29','phase30','phase31','phase32','internal-tools','mail-workspace','phase33','phase34','domain-removal','release-artifacts']
passed=sys.argv[2]=='1' and sys.argv[3]=='0' and [r[0] for r in rows]==expected and all(r[1]=='PASS' for r in rows)
release=os.environ['NAKPANEL_MULTIPASS_IMAGE']; development=os.environ.get('NAKPANEL_RELEASE_ALLOW_DEVELOPMENT')=='1'
report=dict(schema_version=1,qualification_scope="CURRENT_VERSION_ONLY",excluded_gates=["real-upgrade"],release=release,architecture=os.environ['NAKPANEL_MULTIPASS_ARCH'],run_token=os.environ['NAKPANEL_RUN_TOKEN'],source_vm=os.environ['NAKPANEL_MULTIPASS_VM'],dr_vm=os.environ['NAKPANEL_MULTIPASS_DR_VM'],qualification_passed=passed,promotion_eligible=passed and not development,signature_class='development' if development else 'production',php_contract=os.environ['NAKPANEL_PHP_VERSIONS'].split(','),profile=os.environ['NAKPANEL_QUALIFICATION_PROFILE'],php_provider=os.environ['NAKPANEL_QUALIFICATION_PHP_PROVIDER'],full_php_parity=os.environ['NAKPANEL_PHP_VERSIONS']=='8.5,8.4,8.3',features=dict(native_php=os.environ['NAKPANEL_PHP_VERSIONS'].split(','),rootless_oci_required=True,rootful_valkey_required=True,webmail_required=True,database_manager_requested=os.environ.get('NAKPANEL_VERIFY_DATABASE_MANAGER')=='1',current_version_application_recovery_required=True),gates=[dict(name=r[0],status=r[1],exit_code=int(r[2])) for r in rows],pending_gates=[g for g in expected if g not in [r[0] for r in rows]])
image_records=pathlib.Path(os.environ['NAKPANEL_OWNERSHIP_DIR'],os.environ['NAKPANEL_RUN_TOKEN']).glob('*.image.json')
report['requested_image']=dict(expected_release=release,source=os.environ.get('NAKPANEL_MULTIPASS_IMAGE_SOURCE') or release,sha256=os.environ.get('NAKPANEL_MULTIPASS_IMAGE_SHA256') or None)
report['launch_images']=[dict(vm=path.name.removesuffix('.image.json'),**json.loads(path.read_text())) for path in image_records]
report['environment_exclusions']=[json.loads(path.read_text()) for path in pathlib.Path(os.environ['NAKPANEL_OWNERSHIP_DIR'],os.environ['NAKPANEL_RUN_TOKEN'],'firmware').glob('*.json')]
pathlib.Path(os.environ['NAKPANEL_CELL_REPORT_DIR'],'report.json').write_text(json.dumps(report,indent=2)+'\n')
PY
  echo "Cell evidence: ${NAKPANEL_CELL_REPORT_DIR}"
  exit "${status}"
}
trap finish EXIT
run_gate() {
  local name="$1" status=0; shift
  echo "ubuntu-platform: ${name}"
  "$@" >"${NAKPANEL_CELL_REPORT_DIR}/${name}.log" 2>&1 || status=$?
  if [[ "${status}" == 0 ]]; then
    printf '%s\tPASS\t0\n' "${name}" >>"${results}"
  else
    printf '%s\tFAIL\t%s\n' "${name}" "${status}" >>"${results}"
    tail -n 50 "${NAKPANEL_CELL_REPORT_DIR}/${name}.log" >&2
    exit "${status}"
  fi
}
verify_args=(--bundle "${NAKPANEL_RELEASE_BUNDLE}" --public-key "${NAKPANEL_RELEASE_PUBLIC_KEY}" --version "${NAKPANEL_RELEASE_VERSION}" --architecture "${NAKPANEL_MULTIPASS_ARCH}")
if [[ "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" == 1 ]]; then verify_args+=(--allow-development); fi
run_gate bundle python3 "${ROOT_DIR}/deploy/release/verify.py" "${verify_args[@]}"
cp "${NAKPANEL_RELEASE_BUNDLE}/manifest.json" "${NAKPANEL_CELL_REPORT_DIR}/release-manifest.json"
# Refuse a populated guest: fresh means that this invocation owns its launch.
if multipass info "${NAKPANEL_MULTIPASS_VM}" >/dev/null 2>&1; then echo 'fresh qualification requires a new source VM' >&2; exit 1; fi
run_gate fresh-install "${SCRIPT_DIR}/current-install-verify.sh"
inventory() {
  assert_current_vm_identity
  git -C "${ROOT_DIR}" rev-parse HEAD
  git -C "${ROOT_DIR}" status --porcelain
  if [[ -f "${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}/${NAKPANEL_MULTIPASS_VM}.image.json" ]]; then cat "${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}/${NAKPANEL_MULTIPASS_VM}.image.json"; fi
  multipass version
  multipass info "${NAKPANEL_MULTIPASS_VM}" --format json
  multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -c '
set -euo pipefail
cat /etc/os-release
uname -a
dpkg --print-architecture
dpkg-query -W
apt-cache policy
/usr/local/go/bin/go version
composer --version
wp --version --allow-root
stalwart-mail --version
podman --version
dpkg-query -W -f="\${binary:Package}\n" | xargs apt-cache policy
find /etc/apt/sources.list.d -type f -maxdepth 1 -exec cat {} +
file /usr/local/bin/nakpanel-panel /usr/local/bin/nakpanel-agent /usr/local/bin/panelctl /usr/local/bin/stalwart-mail /usr/bin/podman /usr/lib/nakpanel/slirp4netns /usr/bin/goaccess /usr/sbin/nginx /usr/sbin/named /usr/sbin/php-fpm*
systemctl is-system-running
systemctl --failed --no-pager
findmnt --target /home
assert_inventory_user_quota() {
  local quota_state
  quota_state="$(quotaon -p "$(findmnt -n -o TARGET --target /home)" 2>&1 || true)"
  printf "%s\n" "$quota_state"
  grep -Eq "user quota .* is on" <<<"$quota_state"
}
assert_inventory_user_quota
'
}
run_gate inventory inventory
for gate in phase28 valkey-platform security phase29 phase30 phase31 phase32 internal-tools mail-workspace phase33 phase34 domain-removal; do
  if [[ "${gate}" == internal-tools ]]; then
    run_gate "${gate}" env NAKPANEL_SKIP_PRIOR_PHASES=1 python3 "${SCRIPT_DIR}/roundcube-send-read.py" execute-canonical
  else
    run_gate "${gate}" env NAKPANEL_SKIP_PRIOR_PHASES=1 "${SCRIPT_DIR}/${gate}-verify.sh"
  fi
done
signed_artifacts() {
  assert_current_vm_identity
  assert_qualification_installed_release
}
run_gate release-artifacts signed_artifacts
complete=1
