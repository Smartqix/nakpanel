#!/usr/bin/env bash
# Long-running soak harness for the 30-60 day reliability window (docs/SOAK.md).
#
#   ./deploy/multipass/soak-verify.sh --init   # launch + install + populate once
#   ./deploy/multipass/soak-verify.sh          # non-destructive health sweep
#
# The soak VM is deliberately outside NAKPANEL_MULTIPASS_VM and is NEVER in
# the legacy destroy list: deployment-verify.sh and the phase chain must not
# be able to purge it.
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
  if multipass info "${SOAK_VM}" >/dev/null 2>&1; then
    fail "${SOAK_VM} already exists; delete it manually before re-initializing"
  fi
  multipass launch --name "${SOAK_VM}" --cpus 2 --memory 3G --disk 20G "${NAKPANEL_MULTIPASS_IMAGE}"
  (
    export NAKPANEL_MULTIPASS_VM="${SOAK_VM}"
    wait_for_cloud_init
    sync_repo "${ROOT_DIR}"
  )
  multipass exec "${SOAK_VM}" -- sudo bash -se -- "${REMOTE_SRC}" <<'REMOTE'
set -euo pipefail
cd "$1"
deploy/install/install.sh --yes
REMOTE
  # A daily scheduled local server backup exercises the whole backup pipeline
  # for the entire soak window.
  # The archive key is the single secret that makes backups restorable: write
  # it 0600 and never echo it to stdout (CI logs, terminal scrollback).
  ( umask 077; soak_exec sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
    NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' \
    panelctl --actor soak backup-server key init >"${SOAK_LOG_DIR}/backup-key.txt" )
  chmod 600 "${SOAK_LOG_DIR}/backup-key.txt"
  soak_exec sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
    NAKPANEL_SECRET_KEY_FILE='/etc/nakpanel/secret-keys.json' \
    panelctl --actor soak backup-server destination add --name soak-local --kind local --retention-count 7
  echo "Soak VM ${SOAK_VM} initialized. Store ${SOAK_LOG_DIR}/backup-key.txt safely and schedule this script per docs/SOAK.md."
  exit 0
fi

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
backup_age="$(soak_db "SELECT COALESCE(EXTRACT(EPOCH FROM now()-max(completed_at))::bigint, 999999) FROM server_backups WHERE status='active'")"
[[ "${backup_age}" =~ ^[0-9]+$ ]] || backup_age=999999
[[ "${backup_age}" -lt 93600 ]] || note "newest verified server backup is ${backup_age}s old"

# 7. Reconciliation freshness: queue a run and require convergence.
soak_exec sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  panelctl --actor soak reconcile --system >/dev/null || note "could not queue reconciliation"
reconcile_run="$(soak_db "SELECT COALESCE(MAX(id),0) FROM reconciliation_runs")"
reconcile_status=""
for _ in $(seq 1 90); do
  reconcile_status="$(soak_db "SELECT status FROM reconciliation_runs WHERE id=${reconcile_run}")"
  [[ "${reconcile_status}" == "active" ]] && break
  sleep 2
done
[[ "${reconcile_status}" == "active" ]] || note "reconciliation run ${reconcile_run} is ${reconcile_status}"

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
