#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC}"

ensure_vm 2 3G 16G
sync_repo "${ROOT_DIR}" "${REMOTE_SRC}"

multipass exec "${VM_NAME}" -- env REMOTE_SRC="${REMOTE_SRC}" bash -se <<'REMOTE'
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

sudo chown -R nakpanel:nakpanel "${REMOTE_SRC}"
cd "${REMOTE_SRC}"

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
wait_for_tcp_listener 'LISTEN.+:80\b' 'nginx on :80'
sudo ss -ltnp | tee /tmp/nakpanel-phase3-ss.txt
grep -Eq 'LISTEN.+:7443\b' /tmp/nakpanel-phase3-ss.txt
grep -Eq 'LISTEN.+:80\b' /tmp/nakpanel-phase3-ss.txt
if grep -Eq 'LISTEN.+:443\b' /tmp/nakpanel-phase3-ss.txt; then
  echo "unexpected listener on port 443" >&2
  exit 1
fi
if ss -ltnp | grep -q 'nakpanel-agent'; then
  echo "agent unexpectedly has a TCP listener" >&2
  exit 1
fi
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

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'

create_status="$(curl -sk -o "${tmpdir}/create.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
  -d 'username=npdemo' \
  -d 'domain=phase3.test' \
  -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${create_status}" != "303" ]]; then
  echo "site create returned HTTP ${create_status}" >&2
  cat "${tmpdir}/create.out" >&2
  exit 1
fi

site_ok=0
for _ in $(seq 1 60); do
  if curl -s --fail -H 'Host: phase3.test' "http://${VM_IP}/" | grep -qx 'nakpanel placeholder for phase3.test'; then
    site_ok=1
    break
  fi
  sleep 1
done
if [[ "${site_ok}" != "1" ]]; then
  echo "provisioned site did not become reachable" >&2
  multipass exec "${VM_NAME}" -- sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200 >&2 || true
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

sudo test -f /home/npdemo/public_html/index.php
owner="$(sudo stat -c '%U:%G' /home/npdemo/public_html/index.php)"
if [[ "${owner}" != "npdemo:npdemo" ]]; then
  echo "unexpected index.php owner: ${owner}" >&2
  exit 1
fi

sudo test -f /etc/nginx/sites-available/phase3.test.conf
sudo test -L /etc/nginx/sites-enabled/phase3.test.conf
sudo grep -q 'server_name phase3.test;' /etc/nginx/sites-available/phase3.test.conf
sudo grep -q 'root /home/npdemo/public_html;' /etc/nginx/sites-available/phase3.test.conf
sudo grep -q 'fastcgi_pass unix:/run/php/nakpanel-npdemo-phase3-test.sock;' /etc/nginx/sites-available/phase3.test.conf

sudo test -f /etc/php/8.3/fpm/pool.d/nakpanel-npdemo-phase3-test.conf
sudo grep -q '^user = npdemo$' /etc/php/8.3/fpm/pool.d/nakpanel-npdemo-phase3-test.conf
sudo grep -q '^group = npdemo$' /etc/php/8.3/fpm/pool.d/nakpanel-npdemo-phase3-test.conf
sudo grep -q '^listen = /run/php/nakpanel-npdemo-phase3-test.sock$' /etc/php/8.3/fpm/pool.d/nakpanel-npdemo-phase3-test.conf

sudo sha256sum /etc/nginx/sites-available/phase3.test.conf /etc/php/8.3/fpm/pool.d/nakpanel-npdemo-phase3-test.conf > /tmp/nakpanel-phase3-before.sha
REMOTE

repeat_status="$(curl -sk -o "${tmpdir}/repeat.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
  -d 'username=npdemo' \
  -d 'domain=phase3.test' \
  -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${repeat_status}" != "303" ]]; then
  echo "repeat site create returned HTTP ${repeat_status}" >&2
  cat "${tmpdir}/repeat.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

status_active=0
for _ in $(seq 1 30); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM sites WHERE domain = 'phase3.test'" | grep -qx 'active'; then
    status_active=1
    break
  fi
  sleep 1
done
if [[ "${status_active}" != "1" ]]; then
  sudo -u postgres psql -d nakpanel -c "SELECT id, domain, status, last_error FROM sites" >&2
  echo "site did not return to active after repeat create" >&2
  exit 1
fi

sudo sha256sum /etc/nginx/sites-available/phase3.test.conf /etc/php/8.3/fpm/pool.d/nakpanel-npdemo-phase3-test.conf > /tmp/nakpanel-phase3-after.sha
sudo diff -u /tmp/nakpanel-phase3-before.sha /tmp/nakpanel-phase3-after.sha

printf '<?php sleep(5); echo get_current_user();\n' | sudo tee /home/npdemo/public_html/sleep.php >/dev/null
sudo chown npdemo:npdemo /home/npdemo/public_html/sleep.php
REMOTE

curl -s -H 'Host: phase3.test' "http://${VM_IP}/sleep.php" > "${tmpdir}/sleep.out" &
sleep_pid=$!
sleep 1

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
if ! ps -eo user,args | grep 'php-fpm: pool nakpanel-npdemo-phase3-test' | grep -q '^npdemo '; then
  ps -eo user,args | grep php-fpm >&2 || true
  echo "php-fpm pool is not running as npdemo" >&2
  exit 1
fi
REMOTE

wait "${sleep_pid}"
grep -qx 'npdemo' "${tmpdir}/sleep.out"

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_client_dashboard "${tmpdir}/client-dashboard.html"

client_status="$(curl -sk -o "${tmpdir}/client-create.out" -w '%{http_code}' \
  -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/client.cookies")" \
  -d 'username=npclient' \
  -d 'domain=client-phase3.test' \
  -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${client_status}" != "403" ]]; then
  echo "client site create returned HTTP ${client_status}, want 403" >&2
  cat "${tmpdir}/client-create.out" >&2
  exit 1
fi

echo "Phase 3 Multipass verification passed for https://${VM_IP}:7443 and http://${VM_IP}/ with Host: phase3.test"
