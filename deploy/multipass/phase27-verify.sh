#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase27 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

fail() {
  echo "phase27: $*" >&2
  exit 1
}

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${SCRIPT_DIR}/phase26-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo systemctl restart nakpanel
REMOTE

VM_IP="$(vm_ip)"
BASE_URL="https://${VM_IP}:7443"
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT

for _ in $(seq 1 30); do
  curl -skf "${BASE_URL}/healthz" >/dev/null && break
  sleep 1
done
curl -skf "${BASE_URL}/healthz" >/dev/null

curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  --data-urlencode "email=admin@nakpanel.test" \
  --data-urlencode "password=NakpanelAdmin!2026" \
  "${BASE_URL}/login" >/dev/null

site_id="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c \
  "SELECT id FROM sites ORDER BY id LIMIT 1")"
[[ "${site_id}" =~ ^[0-9]+$ ]] || fail "no website exists for domain workspace verification"

fetch_tab() {
  local path="$1" output="$2"
  curl -sk --fail -b "${tmpdir}/admin.cookies" "${BASE_URL}${path}" -o "${output}"
  grep -Fq "np-domain-primary-nav" "${output}" || fail "${path} is missing the shared domain navigation"
  grep -Fq "Domain tools" "${output}" || fail "${path} is missing the mobile Domain Tools drawer"
}

fetch_tab "/sites/${site_id}" "${tmpdir}/overview.html"
for marker in "Hosting overview" "Files &amp; Access" "Developer Tools" "Data &amp; Recovery"; do
  grep -Fq "${marker}" "${tmpdir}/overview.html" || fail "overview is missing ${marker}"
done

fetch_tab "/sites/${site_id}/web-server" "${tmpdir}/hosting.html"
for marker in "Performance &amp; cache" "Traffic controls" "Security &amp; access" "data-np-dirty-guard" "Reset hosting"; do
  grep -Fq "${marker}" "${tmpdir}/hosting.html" || fail "hosting workspace is missing ${marker}"
done

fetch_tab "/sites/${site_id}?tab=php" "${tmpdir}/php.html"
for marker in "Process Manager" "Resource limits" "Error handling &amp; security" "Save &amp; restart PHP" "/php-settings"; do
  grep -Fq "${marker}" "${tmpdir}/php.html" || fail "PHP workspace is missing ${marker}"
done

fetch_tab "/sites/${site_id}?tab=dns" "${tmpdir}/dns.html"
grep -Fq "data-np-dns-workspace" "${tmpdir}/dns.html" || fail "DNS filters are missing"
grep -Fq "Add DNS record" "${tmpdir}/dns.html" || fail "DNS record dialog is missing"

fetch_tab "/sites/${site_id}?tab=ssl" "${tmpdir}/ssl.html"
grep -Fq "Connection security" "${tmpdir}/ssl.html" || fail "SSL security summary is missing"

fetch_tab "/sites/${site_id}?tab=databases" "${tmpdir}/databases.html"
grep -Fq "Database allocation summary" "${tmpdir}/databases.html" || fail "database allocation summary is missing"

fetch_tab "/sites/${site_id}?tab=backups" "${tmpdir}/backups.html"
grep -Fq "Recovery points" "${tmpdir}/backups.html" || fail "backup recovery workspace is missing"

fetch_tab "/sites/${site_id}/files" "${tmpdir}/files.html"
grep -Fq "np-file-manager" "${tmpdir}/files.html" || fail "File Manager is missing"

curl -sk --fail -b "${tmpdir}/admin.cookies" "${BASE_URL}/assets/app.css" -o "${tmpdir}/app.css"
grep -Fq ".np-settings-fields" "${tmpdir}/app.css" || fail "compiled settings layout CSS is missing"
grep -Eq "@media ?\\(max-width: ?760px\\)" "${tmpdir}/app.css" || fail "mobile domain layout CSS is missing"

echo "Phase 27 Plesk-like domain workspace verification passed on ${VM_NAME} (${VM_IP})."
