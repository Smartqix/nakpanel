#!/usr/bin/env bash
set -euo pipefail

VM_NAME="${NAKPANEL_MULTIPASS_VM:-nakpanel-phase4-tls}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE:-24.04}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REMOTE_SRC="/tmp/nakpanel-src"

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass is required" >&2
  exit 1
fi

if ! multipass info "${VM_NAME}" >/dev/null 2>&1; then
  multipass launch "${IMAGE}" --name "${VM_NAME}" --cpus 2 --memory 3G --disk 16G
fi

cloud_init_done=0
for _ in $(seq 1 90); do
  if multipass exec "${VM_NAME}" -- cloud-init status 2>/dev/null | grep -q 'status: done'; then
    cloud_init_done=1
    break
  fi
  sleep 2
done

if [[ "${cloud_init_done}" != "1" ]]; then
  multipass exec "${VM_NAME}" -- cloud-init status --long || true
  echo "cloud-init did not finish in time" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- sudo rm -rf "${REMOTE_SRC}"
multipass transfer -r "${ROOT_DIR}" "${VM_NAME}:${REMOTE_SRC}"

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y ca-certificates curl postgresql postgresql-contrib nginx php8.3-fpm build-essential python3

arch="$(uname -m)"
case "${arch}" in
  x86_64) goarch="amd64" ;;
  aarch64|arm64) goarch="arm64" ;;
  *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;;
esac

if ! command -v go >/dev/null 2>&1 || ! go version | grep -Eq 'go1\.(23|24|25|26)'; then
  curl -fsSL "https://go.dev/dl/go1.23.12.linux-${goarch}.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
  sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi

export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"
if ! command -v task >/dev/null 2>&1; then
  sudo env PATH="${PATH}" GOBIN=/usr/local/bin go install github.com/go-task/task/v3/cmd/task@v3.38.0
fi

sudo systemctl enable --now postgresql
sudo systemctl enable --now nginx php8.3-fpm

if ! id nakpanel >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'nakpanel'" | grep -qx 1; then
  sudo -u postgres createuser nakpanel
fi

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'nakpanel'" | grep -qx 1; then
  sudo -u postgres createdb -O nakpanel nakpanel
fi

sudo chown -R nakpanel:nakpanel /tmp/nakpanel-src
cd /tmp/nakpanel-src

sudo -u nakpanel env \
  PATH="${PATH}" \
  HOME=/var/lib/nakpanel \
  NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  task goose:up

sudo -u nakpanel env \
  PATH="${PATH}" \
  HOME=/var/lib/nakpanel \
  NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  task river:up

sudo -u nakpanel env PATH="${PATH}" HOME=/var/lib/nakpanel task build

sudo systemctl stop nakpanel.service nakpanel-agent.service 2>/dev/null || true
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0644 deploy/systemd/nakpanel-agent.service /etc/systemd/system/nakpanel-agent.service
sudo install -m 0644 deploy/systemd/nakpanel.service /etc/systemd/system/nakpanel.service
sudo systemctl daemon-reload
sudo systemctl enable nakpanel-agent.service nakpanel.service
sudo systemctl reset-failed nakpanel-agent.service nakpanel.service 2>/dev/null || true
sudo systemctl restart nakpanel-agent.service
sudo systemctl restart nakpanel.service
sudo systemctl is-active --quiet nakpanel-agent.service
sudo systemctl is-active --quiet nakpanel.service

wait_for_tcp_listener() {
  local pattern="$1"
  local label="$2"
  for _ in $(seq 1 30); do
    if sudo ss -ltnp | grep -Eq "${pattern}"; then
      return 0
    fi
    sleep 1
  done
  sudo ss -ltnp >&2
  echo "timed out waiting for ${label}" >&2
  exit 1
}

wait_for_tcp_listener 'LISTEN.+:7443\b' 'nakpanel panel on :7443'
REMOTE

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
  if ! grep -Fq "${needle}" "${file}"; then
    echo "${file} is missing expected text: ${needle}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local needle="$2"
  if grep -Fq "${needle}" "${file}"; then
    echo "${file} contains unexpected text: ${needle}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

assert_client_dashboard() {
  local file="$1"
  assert_contains "${file}" 'Client dashboard'
  assert_contains "${file}" 'Account overview'
  assert_contains "${file}" 'Hosting account'
  assert_not_contains "${file}" 'action="/sites"'
  assert_not_contains "${file}" 'action="/databases"'
  assert_not_contains "${file}" 'action="/certificates"'
}

curl -sk --fail "https://${VM_IP}:7443/login" | grep -q 'nakpanel login'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE kind IN ('create_site', 'issue_cert')
  AND (
    args->>'domain' IN ('phase4tls.test', 'pendingtls.test')
    OR args->>'site_id' IN (
      SELECT id::text FROM sites WHERE domain IN ('phase4tls.test', 'pendingtls.test')
    )
  );
DELETE FROM sites WHERE domain IN ('phase4tls.test', 'pendingtls.test');

INSERT INTO sites (owner_user_id, username, domain, php_version, status, last_error)
SELECT id, 'nppending', 'pendingtls.test', '8.3', 'pending', ''
FROM users
WHERE email = 'admin@nakpanel.test';
SQL

sudo rm -f /etc/nginx/sites-enabled/phase4tls.test.conf /etc/nginx/sites-available/phase4tls.test.conf
sudo rm -rf /home/nptls /var/lib/nakpanel/certs/phase4tls.test
sudo systemctl reload nginx || true
REMOTE

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'

pending_cert_status="$(curl -sk -o "${tmpdir}/pending-cert.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -d 'domain=pendingtls.test' \
  -d 'issuer=local-self-signed' \
  "https://${VM_IP}:7443/certificates")"
if [[ "${pending_cert_status}" != "400" ]]; then
  echo "pending-site certificate issue returned HTTP ${pending_cert_status}, want 400" >&2
  cat "${tmpdir}/pending-cert.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

sudo -u postgres psql -d nakpanel -tAc "SELECT tls_status FROM sites WHERE domain = 'pendingtls.test'" | grep -qx 'none'
sudo -u postgres psql -d nakpanel -tAc "SELECT count(*) FROM river_job WHERE kind = 'issue_cert' AND args->>'domain' = 'pendingtls.test'" | grep -qx '0'
REMOTE

create_status="$(curl -sk -o "${tmpdir}/site-create.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -d 'username=nptls' \
  -d 'domain=phase4tls.test' \
  -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${create_status}" != "303" ]]; then
  echo "site create returned HTTP ${create_status}" >&2
  cat "${tmpdir}/site-create.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 60); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM sites WHERE domain = 'phase4tls.test'" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, domain, status, last_error FROM sites" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200 >&2 || true
echo "site did not become active" >&2
exit 1
REMOTE

cert_status="$(curl -sk -o "${tmpdir}/cert-create.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -d 'domain=phase4tls.test' \
  -d 'issuer=local-self-signed' \
  "https://${VM_IP}:7443/certificates")"
if [[ "${cert_status}" != "303" ]]; then
  echo "certificate issue returned HTTP ${cert_status}" >&2
  cat "${tmpdir}/cert-create.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 60); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT tls_status FROM sites WHERE domain = 'phase4tls.test'" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, domain, tls_status, tls_last_error FROM sites WHERE domain = 'phase4tls.test'" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200 >&2 || true
echo "site tls did not become active" >&2
exit 1
REMOTE

curl -sk --fail -H 'Host: phase4tls.test' "https://${VM_IP}/" | grep -qx 'nakpanel placeholder for phase4tls.test'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

sudo test -f /var/lib/nakpanel/certs/phase4tls.test/fullchain.pem
sudo test -f /var/lib/nakpanel/certs/phase4tls.test/privkey.pem
key_mode="$(sudo stat -c '%a' /var/lib/nakpanel/certs/phase4tls.test/privkey.pem)"
if [[ "${key_mode}" != "600" ]]; then
  echo "unexpected key mode: ${key_mode}" >&2
  exit 1
fi

sudo grep -q 'listen 443 ssl;' /etc/nginx/sites-available/phase4tls.test.conf
sudo grep -q 'ssl_certificate /var/lib/nakpanel/certs/phase4tls.test/fullchain.pem;' /etc/nginx/sites-available/phase4tls.test.conf
sudo grep -q 'ssl_certificate_key /var/lib/nakpanel/certs/phase4tls.test/privkey.pem;' /etc/nginx/sites-available/phase4tls.test.conf
sudo -u postgres psql -d nakpanel -tAc "SELECT tls_cert_path FROM sites WHERE domain = 'phase4tls.test'" | grep -qx '/var/lib/nakpanel/certs/phase4tls.test/fullchain.pem'
REMOTE

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_client_dashboard "${tmpdir}/client-dashboard.html"

client_status="$(curl -sk -o "${tmpdir}/client-cert.out" -w '%{http_code}' \
  -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" \
  -d 'domain=phase4tls.test' \
  -d 'issuer=local-self-signed' \
  "https://${VM_IP}:7443/certificates")"
if [[ "${client_status}" != "403" ]]; then
  echo "client certificate issue returned HTTP ${client_status}, want 403" >&2
  cat "${tmpdir}/client-cert.out" >&2
  exit 1
fi

echo "Phase 4 TLS verification passed for https://${VM_IP}:7443 and https://${VM_IP}/ with Host: phase4tls.test"
