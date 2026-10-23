#!/usr/bin/env bash
# Phase 29 reliability gate: populated in-place upgrade with automatic
# rollback drills, reboot-and-reconcile, production security (throttle, TOTP,
# fail2ban, staged firewall), and full disaster recovery onto a fresh VM from
# an encrypted server backup.
set -euo pipefail
umask 077
trap 'status=$?; echo "phase29 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
DR_VM_NAME="${NAKPANEL_MULTIPASS_DR_VM:-${NAKPANEL_MULTIPASS_VM}-dr}"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
# Reject collisions before prior phases, sync or any destructive helper.
assert_distinct_vm_names "${VM_NAME}" "${DR_VM_NAME}"
assert_current_vm_identity
assert_qualification_bundle_staged
export NAKPANEL_MULTIPASS_SOURCE_VM="${VM_NAME}"

fail(){ echo "phase29: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
cli(){ multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' NAKPANEL_AGENT_SOCKET='/run/nakpanel/agent.sock' NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' panelctl --actor phase29 "$@"; }
assert_no_failed_units() {
  local vm="$1" label="$2" failed unit ignored
  assert_vm_identity "${vm}" "${IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}" || return "$?"
  failed="$(multipass_exec_short "${vm}" -- sudo systemctl --failed --no-legend --plain --no-pager | tr -d '\r')" || {
    fail "unable to query failed systemd units for ${label}: ${vm}"; return 1;
  }
  if [[ -n "${failed//[[:space:]]/}" ]]; then
    while read -r unit ignored; do
      [[ -n "${unit}" ]] || continue
      echo "phase29: ${label}: ${vm}: ${unit} failure details" >&2
      multipass_exec_short "${vm}" -- sudo systemctl show --no-pager --property=Result,ExecMainCode,ExecMainStatus -- "${unit}" >&2 || true
      multipass_exec_short "${vm}" -- sudo journalctl -b --no-pager -n 80 --unit="${unit}" >&2 || true
    done <<<"${failed}"
    fail "${label} has failed systemd units: ${failed}"
  fi
}
imap_canary() {
  local target_vm="$1" mode="$2"
  assert_vm_identity "${target_vm}" "${IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}" || return "$?"
  python3 "${SCRIPT_DIR}/phase29-imap-canary.py" remote "${target_vm}" "${mode}" "${mailbox_address}" 'Phase29Mail!2026'
}
wait_for() {
  local query="$1" expected="$2" value=""
  for _ in $(seq 1 120); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "got ${value}, want ${expected}: ${query}"
}

# quotaon may exit 1 because unrelated group/project quota classes are off.
# Inspect the actual filesystem's user-quota state without repairing anything.
assert_phase29_user_quota() {
  local mountpoint state
  mountpoint="$(findmnt -n -o TARGET --target /home)" || return "$?"
  [[ -n "${mountpoint}" ]] || return 1
  state="$(quotaon -p "${mountpoint}" 2>/dev/null || true)"
  printf '%s\n' "${state}"
  grep -Eq 'user quota .* is on' <<<"${state}"
}

reconcile_phase29_after_reboot() {
  local output run_id
  output="$(cli reconcile --system)" || return "$?"
  run_id="$(printf '%s\n' "${output}" | tr -d '\r' | sed -nE 's/^System reconciliation queued \(run ([1-9][0-9]*)\)\.$/\1/p')"
  [[ "${run_id}" =~ ^[1-9][0-9]*$ ]] || { echo 'reconciliation request did not return one valid run ID' >&2; return 1; }
  wait_for "SELECT status FROM reconciliation_runs WHERE id=${run_id}" active
}

# Same-platform restore can warn if its convenience reconciliation enqueue
# fails. Demand a new, explicitly acknowledged DR run and observe only its ID.
reconcile_phase29_dr() {
  (
    VM_NAME="${DR_VM_NAME}"
    export NAKPANEL_MULTIPASS_VM="${DR_VM_NAME}"
    assert_current_vm_identity || exit "$?"
    reconcile_phase29_after_reboot
  )
}

# Mirrors challengeCSRFToken() in the panel. `command -v` is required: a
# missing binary inside $( ) aborts the whole script under pipefail, so an
# if-empty fallback would never be reached.
challenge_csrf_for() {
  if command -v shasum >/dev/null 2>&1; then
    printf 'nakpanel-csrf-2fa-v1:%s' "$1" | shasum -a 256 | awk '{print $1}'
  else
    printf 'nakpanel-csrf-2fa-v1:%s' "$1" | sha256sum | awk '{print $1}'
  fi
}

# Enqueue quickly, then poll the durable backup row. Holding a Multipass exec
# channel open while panelctl waits can leave the host transport stuck even
# after the guest process and River job have completed.
create_server_backup(){
  local output backup_id status last_error
  output="$(cli backup-server run --destination phase29-local)" || {
    printf '%s\n' "${output}" >&2
    return 1
  }
  backup_id="$(sed -nE 's/^Server backup ([0-9]+) queued.*/\1/p' <<<"${output}")"
  [[ "${backup_id}" =~ ^[0-9]+$ ]] || {
    echo "could not parse queued server backup ID: ${output}" >&2
    return 1
  }
  for _ in $(seq 1 1350); do
    status="$(db "SELECT status FROM server_backups WHERE id=${backup_id}")"
    case "${status}" in
      active)
        echo "${backup_id}"
        return 0
        ;;
      failed|delete_failed)
        last_error="$(db "SELECT last_error FROM server_backups WHERE id=${backup_id}")"
        echo "server backup ${backup_id} failed: ${last_error}" >&2
        return 1
        ;;
    esac
    sleep 2
  done
  echo "server backup ${backup_id} did not finish within 45 minutes (status ${status:-unknown})" >&2
  return 1
}
# Synthetic version/migration fault injection is additional coverage. A signed
# qualification keeps its primary/DR binaries immutable and runs those drills
# only on a separate, freshly bootstrapped owned companion.
run_phase29_signed_fault_companion() {
  local companion="${VM_NAME}-fault" report_root report_dir result
  if multipass info "${companion}" >/dev/null 2>&1; then
    echo "phase29: existing fault companion retained; choose a fresh owned run: ${companion}" >&2
    return 1
  fi
  report_root="${NAKPANEL_CELL_REPORT_DIR:-${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}}/phase29-additional-fault-drills"
  mkdir -p "${report_root}" || return 1
  chmod 0700 "${report_root}" || return 1
  report_dir="$(mktemp -d "${report_root}/attempt.XXXXXXXX")" || return 1
  printf 'additional-synthetic-fault-drills\t%s\t%s\n' "${companion}" "${NAKPANEL_RELEASE_VERSION:-selected}" >"${report_dir}/identity.tsv"
  if (
    export NAKPANEL_MULTIPASS_VM="${companion}"
    export NAKPANEL_MULTIPASS_SOURCE_VM="${companion}"
    export NAKPANEL_MULTIPASS_DR_VM="${companion}-dr"
    export NAKPANEL_CELL_REPORT_DIR="${report_dir}"
    export NAKPANEL_INSTALL_ONLY=0
    export NAKPANEL_RELEASE_BUNDLE NAKPANEL_RELEASE_PUBLIC_KEY NAKPANEL_RELEASE_VERSION NAKPANEL_RELEASE_ALLOW_DEVELOPMENT
    export NAKPANEL_QUALIFICATION_VM_CPUS="${NAKPANEL_QUALIFICATION_DR_CPUS:-2}"
    export NAKPANEL_QUALIFICATION_VM_MEMORY="${NAKPANEL_QUALIFICATION_DR_MEMORY:-3G}"
    export NAKPANEL_QUALIFICATION_VM_DISK="${NAKPANEL_QUALIFICATION_DR_DISK:-32G}"
    "${SCRIPT_DIR}/current-install-verify.sh" >"${report_dir}/bootstrap.log" 2>&1 || exit "$?"
    # This explicit additional drill is the sole signed-flow exception allowed
    # to build mutated synthetic versions. Its readable/writable source lives
    # outside the private signed qualification parent, only on this companion.
    unset NAKPANEL_RELEASE_BUNDLE NAKPANEL_RELEASE_PUBLIC_KEY NAKPANEL_RELEASE_VERSION NAKPANEL_RELEASE_ALLOW_DEVELOPMENT NAKPANEL_RELEASE_LEGACY_INSTALLER
    export NAKPANEL_REMOTE_SRC=/tmp/nakpanel-phase29-fault-src
    export NAKPANEL_PHASE29_FAULT_DRILLS_ONLY=1
    export NAKPANEL_PHASE29_FAULT_COMPANION_VM="${companion}"
    export NAKPANEL_SKIP_PRIOR_PHASES=1
    "${SCRIPT_DIR}/phase29-verify.sh" >"${report_dir}/fault-drills.log" 2>&1
  ); then
    if destroy_owned_vm "${companion}" "${NAKPANEL_RUN_TOKEN}"; then
      printf 'PASS\tadditional-synthetic-fault-drills\t%s\n' "${companion}" >"${report_dir}/result.tsv"
      echo "phase29: additional synthetic fault drills passed; evidence ${report_dir}"
      return 0
    fi
    result=1
    printf 'FAIL\tcompanion-reclaim\t%s\n' "${companion}" >"${report_dir}/result.tsv"
  else
    result=$?
    printf 'FAIL\tadditional-synthetic-fault-drills\t%s\t%s\n' "${companion}" "${result}" >"${report_dir}/result.tsv"
  fi
  echo "phase29: fault companion failed; retaining ${companion} and evidence ${report_dir}" >&2
  return "${result}"
}

install_phase29_fresh_dr() {
  destroy_vm "${DR_VM_NAME}" || return "$?"
  if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
    (
      export NAKPANEL_MULTIPASS_VM="${DR_VM_NAME}"
      export NAKPANEL_INSTALL_ONLY=1
      export NAKPANEL_RELEASE_BUNDLE NAKPANEL_RELEASE_PUBLIC_KEY NAKPANEL_RELEASE_VERSION NAKPANEL_RELEASE_ALLOW_DEVELOPMENT
      # Exact selected signed artifacts, private administrator bootstrap and
      # services health, with no tenant fixtures before archive restoration.
      "${SCRIPT_DIR}/current-install-verify.sh"
    )
  else
    (
      export NAKPANEL_MULTIPASS_VM="${DR_VM_NAME}"
      ensure_vm 2 3G 16G || exit "$?"
      sync_repo "${ROOT_DIR}" || exit "$?"
    ) || return "$?"
    multipass transfer "${tmpdir}/panel" "${DR_VM_NAME}:/tmp/panel" || return "$?"
    multipass transfer "${tmpdir}/agent" "${DR_VM_NAME}:/tmp/agent" || return "$?"
    multipass transfer "${tmpdir}/panelctl" "${DR_VM_NAME}:/tmp/panelctl" || return "$?"

    # Fresh install with the lab's binaries (29.0.2), then restore the archive.
    multipass exec "${DR_VM_NAME}" -- sudo bash -se -- "${REMOTE_SRC}" "${NAKPANEL_QUALIFICATION_PHP_PROVIDER}" <<'REMOTE'
set -euo pipefail
src="$1"
echo '29.0.2' > "${src}/VERSION"
install -d -m 0755 /tmp/nakpanel-bin
for artifact in panel agent panelctl; do
  install -m 0755 "/tmp/${artifact}" "/tmp/nakpanel-bin/${artifact}"
done
cd "${src}"
args=(--fresh --bin-dir /tmp/nakpanel-bin --yes)
args+=(--php-provider "$2")
umask 077
admin_password_file="$(mktemp /root/nakpanel-qualification-admin.XXXXXXXX)"
trap 'rm -f "${admin_password_file}"' EXIT
printf '%s' 'NakpanelAdmin!2026' >"${admin_password_file}"
args+=(--admin-email admin@nakpanel.test --admin-password-file "${admin_password_file}")
deploy/install/install.sh "${args[@]}"
REMOTE
  fi
}

restore_entrypoint(){ # runs ON the DR VM via multipass exec
  multipass exec "${DR_VM_NAME}" -- sudo env NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json \
    panelctl --actor phase29-restore restore-server \
    --archive /tmp/phase29-archive.nkbk --backup-key-file /tmp/phase29-backup.key --yes
}

if [[ "${NAKPANEL_PHASE29_FAULT_DRILLS_ONLY:-0}" == 1 ]]; then
  [[ "${VM_NAME}" == *-fault && "${NAKPANEL_PHASE29_FAULT_COMPANION_VM:-}" == "${VM_NAME}" && -z "${NAKPANEL_RELEASE_BUNDLE:-}" ]] \
    || fail "raw synthetic drills require the explicit owned fault companion"
fi

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${SCRIPT_DIR}/phase28-verify.sh"
fi

require_nakpanel_vm_name "${DR_VM_NAME}"
for tool in python3 dig curl; do
  command -v "${tool}" >/dev/null 2>&1 || fail "host prerequisite ${tool} is not installed"
done
sync_repo "${ROOT_DIR}"
if [[ "${NAKPANEL_PHASE29_FAULT_DRILLS_ONLY:-0}" == 1 ]]; then
  multipass_exec_short "${VM_NAME}" -- sudo chown -R nakpanel:nakpanel "${REMOTE_SRC}"
fi

VM_IP="$(vm_ip)"
BASE_URL="https://${VM_IP}:7443"
tmpdir="$(mktemp -d)"
# The DR leg brings up a second VM; it must be reclaimed even when the gate
# fails, or a 16 GB VM leaks on every failed run.
cleanup_phase29() {
  local status=$?
  rm -rf "${tmpdir}"
  if [[ "${status}" -ne 0 ]] && multipass info "${DR_VM_NAME}" >/dev/null 2>&1; then
    echo "phase29: gate failed; leaving ${DR_VM_NAME} for inspection (delete with: multipass delete --purge ${DR_VM_NAME})" >&2
  fi
  exit "${status}"
}
trap cleanup_phase29 EXIT

PHASE29_EXPECTED_VERSION=29.0.2
if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
  PHASE29_EXPECTED_VERSION="${NAKPANEL_RELEASE_VERSION:?signed phase29 requires an exact version}"
  assert_qualification_installed_release "${VM_NAME}"
  run_phase29_signed_fault_companion || fail "mandatory additional signed-bootstrap fault companion failed"
fi

admin_login(){ # JAR-NAME
  curl -sk --fail -c "${tmpdir}/$1" -L -d 'email=admin@nakpanel.test' \
    -d 'password=NakpanelAdmin!2026' "${BASE_URL}/login" -o "${tmpdir}/$1.html"
}
is_admin_workspace(){ # HTML-FILE
  grep -q 'data-np-role="admin"' "$1" && grep -q 'action="/logout"' "$1"
}
assert_admin_workspace(){ # HTML-FILE LABEL
  is_admin_workspace "$1" || fail "$2 did not reach the authenticated admin workspace"
}

# ---------------------------------------------------------------------------
echo "phase29: leg 1 - populated in-place upgrade with rollback drills"
# ---------------------------------------------------------------------------

for _ in $(seq 1 60); do curl -skf "${BASE_URL}/healthz" >/dev/null && break; sleep 2; done

site_id="$(db "SELECT site.id FROM sites site
JOIN subscriptions subscription ON subscription.id=site.subscription_id AND subscription.status='active'
JOIN customers customer ON customer.id=subscription.customer_id AND customer.status='active'
JOIN subscription_entitlements entitlement ON entitlement.subscription_id=subscription.id
WHERE site.desired_status='active'
  AND entitlement.max_mailboxes <> 0
  AND COALESCE((entitlement.hosting_policy#>>'{permissions,mail}')::boolean,false)
  AND COALESCE((entitlement.hosting_policy#>>'{mail,enabled}')::boolean,false)
ORDER BY site.id LIMIT 1")"
[[ "${site_id}" =~ ^[0-9]+$ ]] || fail "site fixture is unavailable"
subscription_id="$(db "SELECT subscription_id FROM sites WHERE id=${site_id}")"
domain="$(db "SELECT domain FROM sites WHERE id=${site_id}")"
username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")"
canary_db="$(db "SELECT db_name FROM databases WHERE engine='mariadb' AND status='active' ORDER BY id LIMIT 1")"
[[ -n "${canary_db}" ]] || fail "mariadb fixture database is unavailable"

# Populate durable canaries the upgrade, reboot, and DR legs all assert on.
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${domain}" "${canary_db}" <<'REMOTE'
set -euo pipefail
username="$1"; domain="$2"; canary_db="$3"
docroot="/home/${username}/domains/${domain}/public_html"
test -d "${docroot}"
printf 'phase29-docroot-canary\n' >"${docroot}/phase29-canary.txt"
chown "${username}:${username}" "${docroot}/phase29-canary.txt"
mariadb "${canary_db}" -e "CREATE TABLE IF NOT EXISTS phase29_canary (v TEXT); DELETE FROM phase29_canary; INSERT INTO phase29_canary VALUES ('phase29-mariadb-canary')"
REMOTE

# A mailbox with a known password proves mail auth works after DR. Earlier
# phase gates may already have consumed every mailbox allowed by this
# subscription, so prefer an existing owned mailbox and update it in place.
cli mail enable "${domain}" >/dev/null \
  || fail "could not enable mail for the phase29 fixture domain"
mailbox_local="$(db "SELECT mailbox.local_part
FROM mailboxes mailbox
JOIN mail_domains mail_domain ON mail_domain.id=mailbox.mail_domain_id
JOIN sites site ON site.id=${site_id} AND lower(site.domain)=lower(mail_domain.domain)
WHERE mail_domain.subscription_id=${subscription_id}
ORDER BY CASE WHEN lower(mailbox.local_part)='phase29' THEN 0 ELSE 1 END, mailbox.id
LIMIT 1")"
[[ -n "${mailbox_local}" ]] || mailbox_local="phase29"
mailbox_address="${mailbox_local}@${domain}"
if [[ -n "${NAKPANEL_CELL_REPORT_DIR:-}" ]]; then
  printf '%s\t%s\n' "${site_id}" "${mailbox_address}" >"${NAKPANEL_CELL_REPORT_DIR}/phase29-fixtures.tsv"
fi
mailbox_output="$(cli mail add "${mailbox_address}" --password 'Phase29Mail!2026' 2>&1)" \
  || fail "could not provision the phase29 mailbox fixture: ${mailbox_output}"
grep -qi "created\|saved" <<<"${mailbox_output}" \
  || fail "unexpected phase29 mailbox result: ${mailbox_output}"

# Store a real message through Stalwart IMAP before the server archive. Auth
# alone cannot prove that mailbox contents survived restore.
imap_canary "${VM_NAME}" seed || fail "authenticated IMAP canary seed failed"


assert_baseline(){ # LABEL TARGET-IP EXPECTED-VERSION
  local label="$1" ip="$2" version="$3" body canary_reachable=false
  body="$(curl -skf "https://${ip}:7443/healthz")"
  [[ "$(printf '%s\n' "${body}" | head -n1)" == "ok" ]] || fail "${label}: healthz is not ok"
  if [[ -n "${version}" ]]; then
    grep -q "^version=${version//./\\.}" <<<"${body}" || fail "${label}: healthz version is not ${version}: ${body}"
  fi
  for _ in $(seq 1 60); do
    if curl -s --fail --resolve "${domain}:80:${ip}" "http://${domain}/phase29-canary.txt" -o "${tmpdir}/canary.txt"; then
      canary_reachable=true
      break
    fi
    sleep 2
  done
  [[ "${canary_reachable}" == "true" ]] || fail "${label}: docroot canary is unreachable"
  grep -q 'phase29-docroot-canary' "${tmpdir}/canary.txt" || fail "${label}: docroot canary content changed"
  dig +short "@${ip}" "${domain}" A >"${tmpdir}/dig.txt" || true
  [[ -s "${tmpdir}/dig.txt" ]] || fail "${label}: DNS did not answer for ${domain}"
}
assert_mariadb_canary(){ # LABEL VM
  local label="$1" target="$2" value
  value="$(multipass_exec_short "${target}" -- sudo mariadb -N -B "${canary_db}" -e "SELECT v FROM phase29_canary" | tr -d '\r')"
  [[ "${value}" == "phase29-mariadb-canary" ]] || fail "${label}: mariadb canary is ${value}"
}

roundcube_canary(){
  run_qualification_roundcube_canary "$1" "$2" "${mailbox_address}"
}

assert_baseline "pre-upgrade" "${VM_IP}" ""
assert_mariadb_canary "pre-upgrade" "${VM_NAME}"

if [[ -z "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
run_installer() { # EXTRA-ENV... (returns installer exit status)
  local installer_result=0
  multipass exec "${VM_NAME}" -- sudo env "$@" bash -c \
    "cd '${REMOTE_SRC}' && deploy/install/install.sh --yes" \
    > "${tmpdir}/install.log" 2>&1 || installer_result=$?
  if [[ -n "${NAKPANEL_CELL_REPORT_DIR:-}" ]]; then
    # Expected fault failures must retain their real cause too: cleanup removes
    # tmpdir, and a missing rollback marker alone cannot identify a failure.
    python3 - "${tmpdir}/install.log" "${NAKPANEL_CELL_REPORT_DIR}" "${installer_result}" <<'PYINSTALLDIAG' || return "$?"
import json, pathlib, re, sys, tempfile
with open(sys.argv[1], 'rb') as source:
    source.seek(0, 2)
    source.seek(max(0, source.tell() - 65536))
    text = source.read().decode('utf-8', errors='replace')
for secret in ('NakpanelAdmin!2026', 'Phase29Mail!2026'):
    text = text.replace(secret, '[synthetic-secret]')
text = re.sub(r'(?i)\b(password|token|secret|api_key)\s*[=:]\s*\S+', r'\1=[redacted]', text)
text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
text = text.encode('utf-8')[-65536:].decode('utf-8', errors='ignore')
root = pathlib.Path(sys.argv[2]) / 'installer-attempts'
root.mkdir(mode=0o700, parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', prefix='attempt.', suffix='.json', dir=root, delete=False) as receipt:
    json.dump(dict(exit_code=int(sys.argv[3]), log=text), receipt)
    receipt.write('\n')
print('phase29: retained installer diagnostic ' + receipt.name, file=sys.stderr)
PYINSTALLDIAG
  fi
  return "${installer_result}"
}
set_remote_version(){
  multipass_exec_short "${VM_NAME}" -- sudo bash -c "echo '$1' > '${REMOTE_SRC}/VERSION' && chown --reference='${REMOTE_SRC}/go.mod' '${REMOTE_SRC}/VERSION'"
}
installed_version(){ multipass_exec_short "${VM_NAME}" -- /usr/local/bin/panelctl version | tr -d '\r'; }

# Clean populated upgrade to 29.0.1.
set_remote_version "29.0.1"
run_installer NAKPANEL_INSTALL_FAULT= || { cat "${tmpdir}/install.log" >&2; fail "upgrade to 29.0.1 failed"; }
grep -q "upgraded to 29.0.1" "${tmpdir}/install.log" || fail "installer did not report the upgrade"
multipass_exec_short "${VM_NAME}" -- sudo bash -c 'ls -1d /var/lib/nakpanel/upgrade-backups/29.0.1-*' >/dev/null \
  || fail "pre-upgrade backup set is missing"
multipass_exec_short "${VM_NAME}" -- sudo grep -q 'previous_version=' /etc/nakpanel/version \
  || fail "/etc/nakpanel/version is missing previous_version"
for _ in $(seq 1 60); do curl -skf "${BASE_URL}/healthz" | grep -q '^version=29\.0\.1' && break; sleep 2; done
assert_baseline "post-upgrade" "${VM_IP}" "29.0.1"
assert_mariadb_canary "post-upgrade" "${VM_NAME}"

# Skip-if-same must exit 0 quickly without touching services.
run_installer NAKPANEL_INSTALL_FAULT= || { cat "${tmpdir}/install.log" >&2; fail "same-version rerun failed"; }
grep -q "already installed" "${tmpdir}/install.log" || fail "same-version rerun did not short-circuit"

# Downgrades are refused.
set_remote_version "29.0.0"
if run_installer NAKPANEL_INSTALL_FAULT=; then
  fail "downgrade to 29.0.0 was not refused"
fi
grep -q "refusing downgrade" "${tmpdir}/install.log" || fail "downgrade refusal message missing"

# Rollback drill A: a failure before migrations restores the old install.
set_remote_version "29.0.2"
if run_installer NAKPANEL_INSTALL_FAULT=before-migrate; then
  fail "pre-migration fault did not fail the installer"
fi
grep -q "previous installation restored" "${tmpdir}/install.log" || fail "pre-migration rollback message missing"
[[ "$(installed_version)" == 29.0.1* ]] || fail "drill A left panelctl at $(installed_version)"
for _ in $(seq 1 60); do curl -skf "${BASE_URL}/healthz" | grep -q '^version=29\.0\.1' && break; sleep 2; done
assert_baseline "drill-a" "${VM_IP}" "29.0.1"

# Rollback drill B: a post-migration health failure restores the database
# from the pre-upgrade dump automatically.
goose_before="$(db "SELECT COALESCE(max(version_id),0) FROM goose_db_version")"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
src="$1"
cat > "${src}/migrations/20991231000001_phase29_drill.sql" <<'SQL'
-- +goose Up
CREATE TABLE phase29_drill_canary (id INT PRIMARY KEY);
-- +goose Down
DROP TABLE IF EXISTS phase29_drill_canary;
SQL
chown --reference="${src}/go.mod" "${src}/migrations/20991231000001_phase29_drill.sql"
REMOTE
if run_installer NAKPANEL_INSTALL_FAULT=unhealthy-panel; then
  fail "unhealthy-panel fault did not fail the installer"
fi
grep -q "restoring database from pre-upgrade dump" "${tmpdir}/install.log" || fail "post-migration rollback message missing"
multipass_exec_short "${VM_NAME}" -- sudo rm -f "${REMOTE_SRC}/migrations/20991231000001_phase29_drill.sql"
[[ "$(db "SELECT count(*) FROM information_schema.tables WHERE table_name='phase29_drill_canary'")" == "0" ]] \
  || fail "drill migration survived the automatic database rollback"
[[ "$(db "SELECT COALESCE(max(version_id),0) FROM goose_db_version")" == "${goose_before}" ]] \
  || fail "goose version was not restored by the rollback"
for _ in $(seq 1 90); do curl -skf "${BASE_URL}/healthz" | grep -q '^version=29\.0\.1' && break; sleep 2; done
assert_baseline "drill-b" "${VM_IP}" "29.0.1"
assert_mariadb_canary "drill-b" "${VM_NAME}"

# Final clean upgrade so the gate continues on the newest version.
run_installer NAKPANEL_INSTALL_FAULT= || { cat "${tmpdir}/install.log" >&2; fail "final upgrade to 29.0.2 failed"; }
for _ in $(seq 1 60); do curl -skf "${BASE_URL}/healthz" | grep -q '^version=29\.0\.2' && break; sleep 2; done
assert_baseline "final-upgrade" "${VM_IP}" "29.0.2"

fi
if [[ "${NAKPANEL_PHASE29_FAULT_DRILLS_ONLY:-0}" == 1 ]]; then
  echo "Phase 29 additional synthetic fault drills passed on ${VM_NAME} (${VM_IP})."
  exit 0
fi

# ---------------------------------------------------------------------------
echo "phase29: leg 2 - production security (throttle, fail2ban, TOTP, firewall)"
# ---------------------------------------------------------------------------

# Durable login throttle: repeated failures produce 429 and survive a panel
# restart because the counters live in PostgreSQL. Use VM loopback for this
# application-level drill: Fail2ban deliberately has a lower network threshold
# and would otherwise ban the verifier host before the panel reaches ten.
throttle_root="${NAKPANEL_CELL_REPORT_DIR:-${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}}/phase29-login-throttle"
mkdir -p "${throttle_root}"
chmod 0700 "${throttle_root}"
throttle_dir="$(mktemp -d "${throttle_root}/attempt.XXXXXXXX")"
echo "phase29: private login throttle diagnostics ${throttle_dir}"
python3 "${SCRIPT_DIR}/phase29-login-throttle.py" snapshot "${VM_NAME}" "${throttle_dir}" before
for ordinal in $(seq 1 10); do
  if ! python3 "${SCRIPT_DIR}/phase29-login-throttle.py" request "${VM_NAME}" "${throttle_dir}" wrong --ordinal "${ordinal}" --credential wrong >/dev/null; then
    python3 "${SCRIPT_DIR}/phase29-login-throttle.py" snapshot "${VM_NAME}" "${throttle_dir}" transport-failure
    python3 "${SCRIPT_DIR}/phase29-login-throttle.py" diagnostic "${VM_NAME}" "${throttle_dir}" transport-failure
    fail "login throttle wrong-password transport failed at ordinal ${ordinal}; request is never replayed"
  fi
done
python3 "${SCRIPT_DIR}/phase29-login-throttle.py" snapshot "${VM_NAME}" "${throttle_dir}" after-ten
if ! throttled="$(python3 "${SCRIPT_DIR}/phase29-login-throttle.py" request "${VM_NAME}" "${throttle_dir}" threshold --ordinal 11 --credential correct)"; then
  python3 "${SCRIPT_DIR}/phase29-login-throttle.py" diagnostic "${VM_NAME}" "${throttle_dir}" threshold
  fail "login throttle threshold transport failed; request is never replayed"
fi
python3 "${SCRIPT_DIR}/phase29-login-throttle.py" snapshot "${VM_NAME}" "${throttle_dir}" after-threshold
if [[ "${throttled}" != "429" ]]; then
  python3 "${SCRIPT_DIR}/phase29-login-throttle.py" diagnostic "${VM_NAME}" "${throttle_dir}" threshold
  fail "login throttle did not engage (got ${throttled})"
fi
multipass_exec_short "${VM_NAME}" -- sudo systemctl restart nakpanel.service
for _ in $(seq 1 60); do curl -skf "${BASE_URL}/healthz" >/dev/null && break; sleep 2; done
if ! throttled="$(python3 "${SCRIPT_DIR}/phase29-login-throttle.py" request "${VM_NAME}" "${throttle_dir}" post-restart --ordinal 12 --credential correct)"; then
  python3 "${SCRIPT_DIR}/phase29-login-throttle.py" diagnostic "${VM_NAME}" "${throttle_dir}" post-restart
  fail "login throttle post-restart transport failed; request is never replayed"
fi
python3 "${SCRIPT_DIR}/phase29-login-throttle.py" snapshot "${VM_NAME}" "${throttle_dir}" after-restart
if [[ "${throttled}" != "429" ]]; then
  python3 "${SCRIPT_DIR}/phase29-login-throttle.py" diagnostic "${VM_NAME}" "${throttle_dir}" post-restart
  fail "login throttle did not survive a panel restart (got ${throttled})"
fi
cli user unlock admin@nakpanel.test >/dev/null
admin_login admin.cookies || fail "login after unlock failed"
assert_admin_workspace "${tmpdir}/admin.cookies.html" "unlocked admin login"
admin_csrf="$(csrf_token "${tmpdir}/admin.cookies")"

# Failed logins reach journald in the fail2ban filter format.
multipass_exec_short "${VM_NAME}" -- sudo journalctl -u nakpanel.service --since '-15 min' --no-pager \
  | grep -q 'nakpanel-auth: login failed for' || fail "journald is missing the nakpanel-auth failure line"

# Fail2ban is installed, running, and the panel jail is live.
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet fail2ban || fail "fail2ban is not active"
multipass_exec_short "${VM_NAME}" -- sudo fail2ban-client status nakpanel-login >/dev/null || fail "nakpanel-login jail is missing"
multipass_exec_short "${VM_NAME}" -- sudo fail2ban-client set nakpanel-login banip 203.0.113.99 >/dev/null
# Security mutations are step-up gated; refresh the recent-auth window first.
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -d "password=NakpanelAdmin!2026" -d "csrf_token=${admin_csrf}" \
  "${BASE_URL}/tools-settings/reauthenticate" -o /dev/null \
  || fail "step-up reauthentication failed"
curl -sk --fail -b "${tmpdir}/admin.cookies" "${BASE_URL}/tools-settings/security/bans" -o "${tmpdir}/bans.json"
grep -q '203.0.113.99' "${tmpdir}/bans.json" || fail "panel bans endpoint does not list the banned address"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -H 'Content-Type: application/json' -d '{"jail_id":"nakpanel-login","address":"203.0.113.99"}' \
  "${BASE_URL}/tools-settings/security/bans/unban" -o "${tmpdir}/unban.json"
grep -q '"ok":true' "${tmpdir}/unban.json" || fail "panel unban failed: $(cat "${tmpdir}/unban.json")"
curl -sk --fail -b "${tmpdir}/admin.cookies" "${BASE_URL}/tools-settings/security/bans" -o "${tmpdir}/bans2.json"
if grep -q '203.0.113.99' "${tmpdir}/bans2.json"; then fail "address is still banned after panel unban"; fi

# Security status advertises the Phase 29 mutation capabilities.
curl -sk --fail -b "${tmpdir}/admin.cookies" "${BASE_URL}/tools-settings/security/status" -o "${tmpdir}/security.json"
grep -q '"firewall_mutation":true' "${tmpdir}/security.json" || fail "firewall mutation capability is not advertised"
grep -q '"fail2ban_mutation":true' "${tmpdir}/security.json" || fail "fail2ban mutation capability is not advertised"

# Staged firewall: stage an additional accept rule, observe the pending
# confirmation window, then revert; the managed table must return to its
# previous state while SSH and the panel stay reachable throughout.
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -d "password=NakpanelAdmin!2026" -d "csrf_token=${admin_csrf}" \
  "${BASE_URL}/tools-settings/reauthenticate" -o /dev/null || fail "step-up reauthentication failed"
stage_status="$(curl -sk -o "${tmpdir}/stage.json" -w '%{http_code}' -b "${tmpdir}/admin.cookies" \
  -H "X-Nakpanel-CSRF: ${admin_csrf}" -H 'Content-Type: application/json' \
  -d '{"policy":{"revision":1,"firewall":{"enabled":true,"default_inbound":"accept","rules":[{"id":"phase29-open","name":"phase29","enabled":true,"direction":"inbound","action":"accept","protocol":"tcp","ports":[8081],"order":1}]},"fail2ban":{"enabled":false},"ssh":{"permit_root_login":false,"password_authentication":false,"public_key_authentication":false,"allow_tcp_forwarding":false,"port":22},"tls":{"profile":""}}}' \
  "${BASE_URL}/tools-settings/security/firewall")"
[[ "${stage_status}" == "202" ]] || fail "firewall stage returned ${stage_status}: $(cat "${tmpdir}/stage.json")"
stage_operation="$(python3 -c "import json,sys; print(json.load(open('${tmpdir}/stage.json'))['operation_id'])")"
wait_for "SELECT status FROM server_operations WHERE operation_id='${stage_operation}'" "awaiting_confirmation"
multipass_exec_short "${VM_NAME}" -- sudo nft list table inet nakpanel | grep -q 'phase29-open' \
  || fail "staged firewall rule is not active"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -d "password=NakpanelAdmin!2026" -d "csrf_token=${admin_csrf}" \
  "${BASE_URL}/tools-settings/reauthenticate" -o /dev/null || fail "step-up reauthentication failed"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -H 'Content-Type: application/json' -d "{\"operation_id\":\"${stage_operation}\"}" \
  "${BASE_URL}/tools-settings/security/firewall/revert" -o "${tmpdir}/revert.json"
grep -q '"ok":true' "${tmpdir}/revert.json" || fail "firewall revert failed: $(cat "${tmpdir}/revert.json")"
if multipass_exec_short "${VM_NAME}" -- sudo nft list table inet nakpanel 2>/dev/null | grep -q 'phase29-open'; then
  fail "reverted firewall rule is still active"
fi
curl -skf "${BASE_URL}/healthz" >/dev/null || fail "panel became unreachable during the firewall drill"

# TOTP: enroll the admin, prove password-only login stops minting sessions,
# sign in with a computed code, reject replay, use a recovery code once, then
# restore password-only access through operator recovery.
totp_code(){ # BASE32-SECRET [STEP-OFFSET]
  python3 - "$1" "${2:-0}" <<'PY'
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1].replace(" ", "").upper()
secret += "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret)
step = int(time.time() // 30) + int(sys.argv[2])
digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
value = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000
print(f"{value:06d}")
PY
}
wait_for_next_totp_window(){
  local initial_step current_step
  initial_step=$(( $(date +%s) / 30 ))
  for _ in $(seq 1 35); do
    current_step=$(( $(date +%s) / 30 ))
    if (( current_step > initial_step )); then
      return 0
    fi
    sleep 1
  done
  fail "TOTP counter did not advance after activation"
}
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -X POST "${BASE_URL}/account/2fa/setup" -o "${tmpdir}/setup.html"
totp_secret="$(python3 -c "import re,sys; m=re.search(r'<pre>([A-Z2-7 ]+)</pre>', open('${tmpdir}/setup.html').read()); print(m.group(1) if m else '')")"
[[ -n "${totp_secret}" ]] || fail "TOTP setup page did not expose the secret"
grep -q 'data:image/png;base64,' "${tmpdir}/setup.html" || fail "TOTP setup page has no QR code"
activation_code="$(totp_code "${totp_secret}")"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${admin_csrf}" \
  -d "code=${activation_code}" "${BASE_URL}/account/2fa/activate" -o "${tmpdir}/activated.html"
grep -q 'Two-factor authentication is active' "${tmpdir}/activated.html" || fail "TOTP activation failed"
recovery_code="$(python3 -c "import re; m=re.findall(r'[A-Z0-9]{5}-[A-Z0-9]{5}', open('${tmpdir}/activated.html').read()); print(m[0] if m else '')")"
[[ -n "${recovery_code}" ]] || fail "activation did not show recovery codes"

# Activation consumes the current TOTP counter. Waiting for the next window is
# required before login because replay protection correctly rejects reuse of
# the activation code's counter.
wait_for_next_totp_window

# Password-only login now redirects to the challenge without a session.
redirect_target="$(curl -sk -c "${tmpdir}/2fa.cookies" -o /dev/null -w '%{redirect_url}' \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "${BASE_URL}/login")"
case "${redirect_target}" in
  */login/2fa*) ;;
  *) fail "TOTP-enabled login did not redirect to the challenge (got ${redirect_target})" ;;
esac
if awk '$6=="nakpanel_session"{found=1} END{exit found?0:1}' "${tmpdir}/2fa.cookies"; then
  fail "a session cookie was minted before the second factor"
fi
challenge_cookie="$(awk '$6=="nakpanel_challenge"{value=$7} END{print value}' "${tmpdir}/2fa.cookies")"
[[ -n "${challenge_cookie}" ]] || fail "challenge cookie is missing"
challenge_csrf="$(challenge_csrf_for "${challenge_cookie}")"
# The challenge POST enforces its own CSRF derivation.
no_csrf_status="$(curl -sk -b "${tmpdir}/2fa.cookies" -o /dev/null -w '%{http_code}' \
  -d "code=$(totp_code "${totp_secret}")" "${BASE_URL}/login/2fa")"
[[ "${no_csrf_status}" == "403" ]] || fail "challenge POST without CSRF returned ${no_csrf_status}"
login_code="$(totp_code "${totp_secret}")"
curl -sk --fail -b "${tmpdir}/2fa.cookies" -c "${tmpdir}/2fa.cookies" -L \
  -d "code=${login_code}" -d "csrf_token=${challenge_csrf}" "${BASE_URL}/login/2fa" -o "${tmpdir}/2fa-done.html"
assert_admin_workspace "${tmpdir}/2fa-done.html" "TOTP login"

# Replaying the same code on a fresh challenge is rejected.
curl -sk -c "${tmpdir}/replay.cookies" -o /dev/null \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "${BASE_URL}/login"
replay_cookie="$(awk '$6=="nakpanel_challenge"{value=$7} END{print value}' "${tmpdir}/replay.cookies")"
replay_csrf="$(challenge_csrf_for "${replay_cookie}")"
curl -sk -b "${tmpdir}/replay.cookies" -c "${tmpdir}/replay.cookies" -L \
  -d "code=${login_code}" -d "csrf_token=${replay_csrf}" "${BASE_URL}/login/2fa" -o "${tmpdir}/replay.html"
if is_admin_workspace "${tmpdir}/replay.html"; then fail "a replayed TOTP code was accepted"; fi

# A recovery code works exactly once.
curl -sk --fail -b "${tmpdir}/replay.cookies" -c "${tmpdir}/replay.cookies" -L \
  -d "recovery_code=${recovery_code}" -d "csrf_token=${replay_csrf}" "${BASE_URL}/login/2fa" -o "${tmpdir}/recovery.html"
assert_admin_workspace "${tmpdir}/recovery.html" "recovery-code login"

# Operator recovery restores password-only login.
cli user disable-2fa admin@nakpanel.test --yes >/dev/null
admin_login admin.cookies || fail "password-only login after disable-2fa failed"
assert_admin_workspace "${tmpdir}/admin.cookies.html" "post-recovery login"
admin_csrf="$(csrf_token "${tmpdir}/admin.cookies")"

# ---------------------------------------------------------------------------
echo "phase29: leg 3 - reboot and reconcile"
# ---------------------------------------------------------------------------

multipass restart "${VM_NAME}"
wait_for_cloud_init
VM_IP="$(vm_ip)"
BASE_URL="https://${VM_IP}:7443"
# Observe persistence before reconcile or any repair. A lost quota mount is a
# product failure; repairing it here would turn a broken reboot into a pass.
multipass exec "${VM_NAME}" -- sudo bash -se <<'REMOTE'
set -euo pipefail
findmnt --target /home
systemctl --failed --no-legend --plain --no-pager
REMOTE
multipass_exec_short "${VM_NAME}" -- sudo bash -c "$(declare -f assert_phase29_user_quota); assert_phase29_user_quota"
for _ in $(seq 1 90); do curl -skf "${BASE_URL}/healthz" >/dev/null && break; sleep 2; done
for service in nakpanel nakpanel-agent nginx mariadb named stalwart-mail fail2ban; do
  multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "${service}" \
    || fail "service ${service} is not active after reboot"
done
reconcile_phase29_after_reboot || fail "the requested post-reboot reconciliation did not converge"
assert_no_failed_units "${VM_NAME}" "post-reboot deployment"
assert_baseline "post-reboot" "${VM_IP}" "${PHASE29_EXPECTED_VERSION}"
assert_mariadb_canary "post-reboot" "${VM_NAME}"
admin_login admin-reboot.cookies || fail "post-reboot login failed"
assert_admin_workspace "${tmpdir}/admin-reboot.cookies.html" "post-reboot login"

# ---------------------------------------------------------------------------
echo "phase29: leg 4 - disaster recovery onto a fresh VM"
# ---------------------------------------------------------------------------

# The server archive and all later recovery checks must still describe the
# exact selected release, never the companion's synthetic drill binaries.
assert_qualification_installed_release "${VM_NAME}"

# --force so a rerun on the same VM re-keys instead of aborting; destination
# add is an upsert. Both must be re-runnable or the gate cannot be retried.
roundcube_canary "${VM_NAME}" seed
backup_key="$(cli backup-server key init --force | grep -o 'nkbk1-[A-Z2-7]*' | head -1)"
[[ -n "${backup_key}" ]] || fail "backup key init did not print the key"
cli backup-server destination add --name phase29-local --kind local --retention-count 3 >/dev/null
cli backup-server destination test phase29-local >/dev/null
create_server_backup >/dev/null || fail "server backup did not complete"
archive_name="$(db "SELECT archive_name FROM server_backups WHERE status='active' ORDER BY id DESC LIMIT 1")"
[[ -n "${archive_name}" ]] || fail "no verified server backup was recorded"
[[ "$(db "SELECT verified_at IS NOT NULL FROM server_backups WHERE status='active' ORDER BY id DESC LIMIT 1")" == "t" ]] \
  || fail "server backup was not verified"

multipass exec "${VM_NAME}" -- sudo bash -se -- "${archive_name}" "${NAKPANEL_RELEASE_BUNDLE:+1}" <<'REMOTE'
set -euo pipefail
install -m 0644 "/var/lib/nakpanel/server-backups/${1}" /tmp/phase29-archive.nkbk
if [[ "$2" != 1 ]]; then
  install -d -m 0755 /tmp/nakpanel-bin
  install -m 0755 /usr/local/bin/nakpanel-panel /tmp/nakpanel-bin/panel
  install -m 0755 /usr/local/bin/nakpanel-agent /tmp/nakpanel-bin/agent
  install -m 0755 /usr/local/bin/panelctl /tmp/nakpanel-bin/panelctl
fi
REMOTE
multipass transfer "${VM_NAME}:/tmp/phase29-archive.nkbk" "${tmpdir}/phase29-archive.nkbk"
if [[ -z "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
  multipass transfer "${VM_NAME}:/tmp/nakpanel-bin/panel" "${tmpdir}/panel"
  multipass transfer "${VM_NAME}:/tmp/nakpanel-bin/agent" "${tmpdir}/agent"
  multipass transfer "${VM_NAME}:/tmp/nakpanel-bin/panelctl" "${tmpdir}/panelctl"
fi
printf '%s\n' "${backup_key}" >"${tmpdir}/phase29-backup.key"

install_phase29_fresh_dr || fail "fresh disaster-recovery installation failed"
multipass transfer "${tmpdir}/phase29-archive.nkbk" "${DR_VM_NAME}:/tmp/phase29-archive.nkbk"
multipass transfer "${tmpdir}/phase29-backup.key" "${DR_VM_NAME}:/tmp/phase29-backup.key"
restore_entrypoint || fail "restore-server failed on the DR VM"
assert_qualification_installed_release "${DR_VM_NAME}"

DR_IP="$(multipass info "${DR_VM_NAME}" | awk '/IPv4/{print $2; exit}')"
[[ -n "${DR_IP}" ]] || fail "could not determine DR VM address"
for _ in $(seq 1 90); do curl -skf "https://${DR_IP}:7443/healthz" >/dev/null && break; sleep 2; done
assert_baseline "disaster-recovery" "${DR_IP}" "${PHASE29_EXPECTED_VERSION}"
assert_mariadb_canary "disaster-recovery" "${DR_VM_NAME}"
roundcube_canary "${DR_VM_NAME}" assert
curl -sk --fail -c "${tmpdir}/dr.cookies" -L -d 'email=admin@nakpanel.test' \
  -d 'password=NakpanelAdmin!2026' "https://${DR_IP}:7443/login" -o "${tmpdir}/dr-login.html"
assert_admin_workspace "${tmpdir}/dr-login.html" "restored admin credentials"
multipass_exec_short "${DR_VM_NAME}" -- sudo systemctl is-active --quiet stalwart-mail \
  || fail "stalwart-mail is not active on the DR VM"
multipass_exec_short "${DR_VM_NAME}" -- sudo named-checkconf || fail "named configuration is invalid on the DR VM"
multipass_exec_short "${DR_VM_NAME}" -- sudo test -d /var/lib/nakpanel/certs || fail "certificate store missing on the DR VM"
imap_canary "${DR_VM_NAME}" assert >/dev/null || fail "restored mailbox IMAP login failed"
reconcile_phase29_dr || fail "the requested fresh DR reconciliation did not converge"
assert_no_failed_units "${DR_VM_NAME}" "disaster-recovery deployment"

# A second boot catches restore-time repairs that were never made durable.
multipass restart "${DR_VM_NAME}"
wait_for_cloud_init "${DR_VM_NAME}"
assert_vm_identity "${DR_VM_NAME}" "${IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}"
DR_IP="$(multipass info "${DR_VM_NAME}" | awk '/IPv4/{print $2; exit}')"
for _ in $(seq 1 90); do curl -skf "https://${DR_IP}:7443/healthz" >/dev/null && break; sleep 2; done
assert_qualification_installed_release "${DR_VM_NAME}"
assert_baseline "disaster-recovery second reboot" "${DR_IP}" "${PHASE29_EXPECTED_VERSION}"
assert_mariadb_canary "disaster-recovery second reboot" "${DR_VM_NAME}"
roundcube_canary "${DR_VM_NAME}" assert
imap_canary "${DR_VM_NAME}" assert >/dev/null || fail "second reboot mailbox IMAP canary failed"
assert_no_failed_units "${DR_VM_NAME}" "disaster-recovery second reboot"
multipass_exec_short "${DR_VM_NAME}" -- sudo bash -c "$(declare -f assert_phase29_user_quota); assert_phase29_user_quota"

destroy_vm "${DR_VM_NAME}"

echo "Phase 29 production reliability verification passed on ${VM_NAME} (${VM_IP})."
