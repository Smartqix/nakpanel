#!/usr/bin/env bash
# Long-running soak harness for the 30-60 day reliability window (docs/SOAK.md).
#
#   ./deploy/multipass/soak-verify.sh --init   # launch + install + populate once
#   ./deploy/multipass/soak-verify.sh          # non-destructive health sweep
#
# Each endurance run has its own explicit host/guest ownership identity.
# Never supply its run.env to disposable qualification cleanup. Historical
# nakpanel-soak and nakpanel-lab names remain protected by common.sh.
set -euo pipefail
trap 'status=$?; echo "soak verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
SOAK_VM="${NAKPANEL_SOAK_VM:-nakpanel-soak}"
SOAK_LOG_DIR="${NAKPANEL_SOAK_LOG_DIR:-${HOME}/.nakpanel-soak}"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"

fail(){ echo "soak: $*" >&2; exit 1; }
require_nakpanel_vm_name "${SOAK_VM}"
mkdir -p "${SOAK_LOG_DIR}"
chmod 700 "${SOAK_LOG_DIR}"

soak_exec(){ multipass_exec_short "${SOAK_VM}" -- "$@"; }
soak_db(){ soak_exec sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }

if [[ "${1:-}" == "--init" ]]; then
  # Use the exact authenticated candidate selected for native qualification.
  # Reject missing/invalid artifacts before touching a VM.
  : "${NAKPANEL_RELEASE_BUNDLE:?soak initialization requires a signed current release bundle}"
  : "${NAKPANEL_RELEASE_PUBLIC_KEY:?soak initialization requires its out-of-band public key}"
  : "${NAKPANEL_RELEASE_VERSION:?soak initialization requires an exact version}"
  [[ "${NAKPANEL_RELEASE_LEGACY_INSTALLER:-0}" == 0 ]] || fail "historical installers cannot initialize a current soak"
  case "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" in 0|1) ;; *) fail "development opt-in must be 0 or 1";; esac
  verify_args=(--bundle "${NAKPANEL_RELEASE_BUNDLE}" --public-key "${NAKPANEL_RELEASE_PUBLIC_KEY}" --version "${NAKPANEL_RELEASE_VERSION}" --architecture "${NAKPANEL_MULTIPASS_ARCH}")
  if [[ "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" == 1 ]]; then verify_args+=(--allow-development); fi
  python3 "${ROOT_DIR}/deploy/release/verify.py" "${verify_args[@]}"
  # Owned endurance environments never claim the historical protected name.
  if [[ -n "${NAKPANEL_SOAK_VM:-}" ]]; then export NAKPANEL_MULTIPASS_VM="${NAKPANEL_SOAK_VM}"; fi
  init_qualification_run
  SOAK_VM="${NAKPANEL_MULTIPASS_VM}"
  SOAK_LOG_DIR="${NAKPANEL_SOAK_LOG_DIR:-${HOME}/.nakpanel-soak/${NAKPANEL_MULTIPASS_IMAGE}-${NAKPANEL_MULTIPASS_ARCH}-${NAKPANEL_RUN_TOKEN}}"
  for evidence in run.env backup-key.txt initial-release-manifest.json initial-release-public.pem; do
    [[ ! -e "${SOAK_LOG_DIR}/${evidence}" && ! -L "${SOAK_LOG_DIR}/${evidence}" ]] || fail "soak evidence already exists; choose a fresh log directory"
  done
  mkdir -p "${SOAK_LOG_DIR}"
  chmod 700 "${SOAK_LOG_DIR}"
  if multipass info "${SOAK_VM}" >/dev/null 2>&1; then fail "owned soak initialization requires a fresh unique name"; fi
  # Reuse the canonical fresh installer and product fixture verifier. It
  # stages the signed bundle, supplies a private root administrator password
  # file, verifies seed-login lockdown, and proves site/DB/DNS/TLS operation.
  export NAKPANEL_QUALIFICATION_VM_CPUS="${NAKPANEL_QUALIFICATION_VM_CPUS:-2}"
  export NAKPANEL_QUALIFICATION_VM_MEMORY="${NAKPANEL_QUALIFICATION_VM_MEMORY:-3G}"
  export NAKPANEL_QUALIFICATION_VM_DISK="${NAKPANEL_QUALIFICATION_VM_DISK:-32G}"
  (umask 077; printf 'export NAKPANEL_SOAK_LOG_DIR=%q NAKPANEL_SOAK_VM=%q NAKPANEL_MULTIPASS_VM=%q NAKPANEL_MULTIPASS_SOURCE_VM=%q NAKPANEL_MULTIPASS_DR_VM=%q NAKPANEL_MULTIPASS_IMAGE=%q NAKPANEL_MULTIPASS_ARCH=%q NAKPANEL_RUN_TOKEN=%q NAKPANEL_OWNERSHIP_DIR=%q NAKPANEL_QUALIFICATION_PHP_PROVIDER=%q\n' "${SOAK_LOG_DIR}" "${SOAK_VM}" "${SOAK_VM}" "${NAKPANEL_MULTIPASS_SOURCE_VM}" "${NAKPANEL_MULTIPASS_DR_VM}" "${NAKPANEL_MULTIPASS_IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}" "${NAKPANEL_OWNERSHIP_DIR}" "${NAKPANEL_QUALIFICATION_PHP_PROVIDER}" >"${SOAK_LOG_DIR}/run.env")
  cp "${NAKPANEL_RELEASE_BUNDLE}/manifest.json" "${SOAK_LOG_DIR}/initial-release-manifest.json"
  cp "${NAKPANEL_RELEASE_PUBLIC_KEY}" "${SOAK_LOG_DIR}/initial-release-public.pem"
  "${SCRIPT_DIR}/current-install-verify.sh"
  assert_current_vm_identity
  # A daily scheduled local server backup exercises the whole backup pipeline
  # for the entire soak window.
  # The archive key is the single secret that makes backups restorable: write
  # it 0600 and never echo it to stdout (CI logs, terminal scrollback).
  (
    umask 077
    backup_key_output="$(soak_exec sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
      NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' \
      panelctl --actor soak backup-server key init)"
    # The CLI also prints custody instructions. Persist only the encoded key
    # so --backup-key-file can consume it directly during the final DR drill.
    backup_archive_key="$(printf '%s\n' "${backup_key_output}" | tr -d '\r' | awk '/^nkbk1-/ { print }')"
    [[ "${backup_archive_key}" =~ ^nkbk1-[A-Z2-7]{52}$ ]] || fail "backup key initialization did not return one valid archive key"
    printf '%s\n' "${backup_archive_key}" >"${SOAK_LOG_DIR}/backup-key.txt"
  )
  chmod 600 "${SOAK_LOG_DIR}/backup-key.txt"
  soak_exec sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
    NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' \
    panelctl --actor soak backup-server destination add --name soak-local --kind local --retention-count 7 --schedule '* * * * *'
  # Verify the scheduler itself creates and verifies an archive. A manual
  # backup cannot stand in for this evidence. Then retain the daily schedule.
  scheduled_ready=0
  for _ in $(seq 1 180); do
    scheduled="$(soak_db "SELECT count(*) FROM server_backups backup JOIN server_backup_destinations destination ON destination.id=backup.destination_id WHERE destination.name='soak-local' AND backup.scheduled AND backup.status='active' AND backup.verified_at IS NOT NULL")"
    if [[ "${scheduled}" =~ ^[0-9]+$ && "${scheduled}" -gt 0 ]]; then scheduled_ready=1; break; fi
    sleep 5
  done
  [[ "${scheduled_ready}" == 1 ]] || fail "scheduler did not create a real verified backup within 15 minutes"
  soak_exec sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
    NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' \
    panelctl --actor soak backup-server destination update --name soak-local --kind local --retention-count 7 --schedule '0 2 * * *'
  printf '%s scheduler-created verified backup observed\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${SOAK_LOG_DIR}/soak.log"
  echo "Source ${SOAK_LOG_DIR}/run.env before subsequent sweeps. Soak VM ${SOAK_VM} initialized. Store ${SOAK_LOG_DIR}/backup-key.txt safely and schedule this script per docs/SOAK.md."
  exit 0
fi

assert_vm_identity "${SOAK_VM}" "${NAKPANEL_MULTIPASS_IMAGE}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN:-}"
multipass info "${SOAK_VM}" >/dev/null 2>&1 || fail "${SOAK_VM} does not exist; run --init first"
SOAK_IP="$(multipass info "${SOAK_VM}" | awk '/IPv4/{print $2; exit}')"
[[ -n "${SOAK_IP}" ]] || fail "could not determine ${SOAK_VM} address"

issues=""
NEWLINE='
'
note(){ issues="${issues}${NEWLINE}  - $*"; }

# 1. Panel health and version.
health="$(curl -skf --max-time 10 "https://${SOAK_IP}:7443/healthz" || true)"
[[ "$(printf '%s\n' "${health}" | head -n1)" == "ok" ]] || note "healthz is not ok: ${health}"
version_line="$(printf '%s\n' "${health}" | sed -n 's/^version=//p')"

# 2. No failed systemd units.
failed_units="$(soak_exec sudo systemctl --failed --no-legend --plain | tr -d '\r' | awk '{print $1}' | tr '\n' ' ')"
[[ -z "${failed_units// /}" ]] || note "failed systemd units: ${failed_units}"

# 3. Stuck or discarded River jobs.
stuck_jobs="$(soak_db "SELECT count(*) FROM river_job WHERE state IN ('retryable','discarded')")"
[[ "${stuck_jobs}" =~ ^[0-9]+$ ]] || stuck_jobs="unknown"
[[ "${stuck_jobs}" == "0" ]] || note "${stuck_jobs} retryable/discarded River jobs"

# 4. Disk usage headroom.
disk_used="$(soak_exec df --output=pcent / | tail -1 | tr -dc '0-9')"
[[ "${disk_used:-100}" -lt 85 ]] || note "root filesystem is ${disk_used}% full"

# 5. Panel certificate validity.
soak_exec sudo openssl x509 -checkend 604800 -noout -in /var/lib/nakpanel/tls/panel.crt >/dev/null \
  || note "panel certificate expires within 7 days"

# 6. Newest verified server backup is fresh (a daily schedule allows 26h).
backup_age="$(soak_db "SELECT COALESCE(EXTRACT(EPOCH FROM now()-max(completed_at))::bigint, 999999) FROM server_backups WHERE status='active' AND scheduled AND verified_at IS NOT NULL")"
[[ "${backup_age}" =~ ^[0-9]+$ ]] || backup_age=999999
[[ "${backup_age}" -lt 93600 ]] || note "newest verified server backup is ${backup_age}s old"

# 7. Reconciliation freshness: observe the exact run committed by this CLI
# request. A concurrent newer run must never stand in for its convergence.
if reconcile_output="$(soak_exec sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  panelctl --actor soak reconcile --system)"; then
  reconcile_run="$(printf '%s\n' "${reconcile_output}" | tr -d '\r' | sed -nE 's/^System reconciliation queued \(run ([1-9][0-9]*)\)\.$/\1/p')"
  if [[ "${reconcile_run}" =~ ^[1-9][0-9]*$ ]]; then
    reconcile_status=""
    for _ in $(seq 1 90); do
      reconcile_status="$(soak_db "SELECT status FROM reconciliation_runs WHERE id=${reconcile_run}")"
      [[ "${reconcile_status}" == "active" ]] && break
      sleep 2
    done
    [[ "${reconcile_status}" == "active" ]] || note "reconciliation run ${reconcile_run} is ${reconcile_status}"
  else
    note "reconciliation request did not return one valid run ID"
  fi
else
  note "could not queue reconciliation"
fi

# 8. Fail2ban and journald auth pipeline.
soak_exec sudo systemctl is-active --quiet fail2ban || note "fail2ban is not active"

stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ -z "${issues}" ]]; then
  echo "${stamp} OK version=${version_line} disk=${disk_used}% backup_age=${backup_age}s" >>"${SOAK_LOG_DIR}/soak.log"
  echo "Soak sweep passed for ${SOAK_VM} (${SOAK_IP}); version ${version_line}."
else
  echo "${stamp} ISSUES${issues}" >>"${SOAK_LOG_DIR}/soak.log"
  printf 'Soak sweep found issues on %s (%s):%b\n' "${SOAK_VM}" "${SOAK_IP}" "${issues}" >&2
  exit 1
fi
