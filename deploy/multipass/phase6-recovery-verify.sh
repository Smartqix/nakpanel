#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase5-ui-verify.sh"

VM_IP="$(multipass info "${VM_NAME}" | awk '/IPv4/{print $2; exit}')"
if [[ -z "${VM_IP}" ]]; then
  echo "could not determine ${VM_NAME} IPv4 address" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "${needle}" "${file}"; then
    echo "${file} is missing expected text: ${needle}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq -- "${needle}" "${file}"; then
    echo "${file} contains unexpected text: ${needle}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE kind IN ('create_site', 'create_database', 'issue_cert')
  AND args->>'domain' = 'phase6-retry.test';
DELETE FROM sites WHERE domain = 'phase6-retry.test' OR username = 'npretry';
SQL
sudo rm -f /etc/nginx/sites-enabled/phase6-retry.test.conf /etc/nginx/sites-available/phase6-retry.test.conf
sudo rm -f /etc/php/8.3/fpm/pool.d/nakpanel-npretry-phase6-retry-test.conf
sudo rm -rf /home/npretry
sudo systemctl reload nginx || true
sudo systemctl reload php8.3-fpm || true
sudo systemctl restart nakpanel.service
sudo systemctl is-active --quiet nakpanel.service
REMOTE

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'

site_status="$(curl -sk -o "${tmpdir}/site-create.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -d 'username=npretry' \
  -d 'domain=phase6-retry.test' \
  -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${site_status}" != "303" ]]; then
  echo "Phase 6 setup site create returned HTTP ${site_status}" >&2
  cat "${tmpdir}/site-create.out" >&2
  exit 1
fi

job_id="$(multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 60); do
  id="$(sudo -u postgres psql -d nakpanel -tAc "SELECT id FROM river_job WHERE kind = 'create_site' AND args->>'domain' = 'phase6-retry.test' ORDER BY id DESC LIMIT 1")"
  if [[ -n "${id}" ]]; then
    echo "${id}"
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, kind, state, args FROM river_job WHERE kind = 'create_site' ORDER BY id DESC LIMIT 10" >&2
echo "phase6 retry setup job was not created" >&2
exit 1
REMOTE
)"
job_id="$(echo "${job_id}" | tr -d '[:space:]')"

multipass exec "${VM_NAME}" -- bash -se "${job_id}" <<'REMOTE'
set -euo pipefail
job_id="$1"
for _ in $(seq 1 60); do
  state="$(sudo -u postgres psql -d nakpanel -tAc "SELECT state::text FROM river_job WHERE id = ${job_id}")"
  if [[ "$(echo "${state}" | tr -d '[:space:]')" == "completed" ]]; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, kind, state, attempt, max_attempts, errors FROM river_job WHERE id = ${job_id}" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200 >&2 || true
echo "phase6 retry setup job ${job_id} did not complete before forced retry scenario" >&2
exit 1
REMOTE

multipass exec "${VM_NAME}" -- bash -se "${job_id}" <<'REMOTE'
set -euo pipefail
job_id="$1"
updated="$(
  sudo -u postgres psql -d nakpanel -tAc "
    UPDATE river_job
    SET
      state = 'discarded',
      attempt = max_attempts,
      finalized_at = now(),
      errors = ARRAY[jsonb_build_object('at', now(), 'attempt', max_attempts, 'error', 'phase6 synthetic failure')]::jsonb[]
    WHERE id = ${job_id}
    RETURNING id
  "
)"
if [[ "$(echo "${updated}" | tr -d '[:space:]')" != "${job_id}" ]]; then
  echo "could not force phase6 job ${job_id} into discarded state" >&2
  exit 1
fi
REMOTE

previous_max_attempts="$(multipass exec "${VM_NAME}" -- bash -se "${job_id}" <<'REMOTE'
set -euo pipefail
job_id="$1"
sudo -u postgres psql -d nakpanel -tAc "SELECT max_attempts FROM river_job WHERE id = ${job_id}"
REMOTE
)"
previous_max_attempts="$(echo "${previous_max_attempts}" | tr -d '[:space:]')"

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/" > "${tmpdir}/admin-discarded.html"
assert_contains "${tmpdir}/admin-discarded.html" 'phase6-retry.test'
assert_contains "${tmpdir}/admin-discarded.html" 'discarded'
assert_contains "${tmpdir}/admin-discarded.html" 'phase6 synthetic failure'
assert_contains "${tmpdir}/admin-discarded.html" 'action="/jobs/retry"'
assert_contains "${tmpdir}/admin-discarded.html" "name=\"job_id\" value=\"${job_id}\""
assert_contains "${tmpdir}/admin-discarded.html" 'Retry job'

retry_status="$(curl -sk -o "${tmpdir}/retry.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -d "job_id=${job_id}" \
  "https://${VM_IP}:7443/jobs/retry")"
if [[ "${retry_status}" != "303" ]]; then
  echo "Phase 6 job retry returned HTTP ${retry_status}" >&2
  cat "${tmpdir}/retry.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se "${job_id}" "${previous_max_attempts}" <<'REMOTE'
set -euo pipefail
job_id="$1"
previous_max_attempts="$2"
for _ in $(seq 1 30); do
  max_attempts="$(sudo -u postgres psql -d nakpanel -tAc "SELECT max_attempts FROM river_job WHERE id = ${job_id}")"
  if [[ "$(echo "${max_attempts}" | tr -d '[:space:]')" -gt "${previous_max_attempts}" ]]; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, state, attempt, max_attempts, finalized_at FROM river_job WHERE id = ${job_id}" >&2
echo "phase6 retry did not increment exhausted job max_attempts above ${previous_max_attempts}" >&2
exit 1
REMOTE

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/?notice=job-retried" > "${tmpdir}/admin-notice.html"
assert_contains "${tmpdir}/admin-notice.html" 'Retry queued. Refresh in a moment to see the updated status.'

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_contains "${tmpdir}/client-dashboard.html" 'Client dashboard'
assert_not_contains "${tmpdir}/client-dashboard.html" 'Retry job'

client_retry_status="$(curl -sk -o "${tmpdir}/client-retry.out" -w '%{http_code}' \
  -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" \
  -d "job_id=${job_id}" \
  "https://${VM_IP}:7443/jobs/retry")"
if [[ "${client_retry_status}" != "403" ]]; then
  echo "client job retry returned HTTP ${client_retry_status}, want 403" >&2
  cat "${tmpdir}/client-retry.out" >&2
  exit 1
fi

echo "Phase 6 recovery verification passed for discarded provisioning job ${job_id} on https://${VM_IP}:7443"
