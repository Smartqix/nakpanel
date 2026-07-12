#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
REMOTE_SRC="${NAKPANEL_REMOTE_SRC}"

ensure_vm 2 2G 12G
sync_repo "${ROOT_DIR}" "${REMOTE_SRC}"

multipass exec "${VM_NAME}" -- env REMOTE_SRC="${REMOTE_SRC}" bash -se <<'REMOTE'
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y ca-certificates curl postgresql postgresql-contrib nginx build-essential

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
sudo systemctl stop nginx

if ! id nakpanel >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi
sudo install -d -o nakpanel -g nakpanel -m 0750 /var/lib/nakpanel
sudo chown -R nakpanel:nakpanel /var/lib/nakpanel

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

sudo -u nakpanel env \
  PATH="${PATH}" \
  HOME=/var/lib/nakpanel \
  task build
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0644 deploy/systemd/nakpanel.service /etc/systemd/system/nakpanel.service
sudo systemctl daemon-reload
sudo systemctl enable nakpanel.service
sudo systemctl reset-failed nakpanel.service 2>/dev/null || true
sudo systemctl restart nakpanel.service
sudo systemctl stop nginx
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
sudo ss -ltnp | tee /tmp/nakpanel-ss.txt
grep -Eq 'LISTEN.+:7443\b' /tmp/nakpanel-ss.txt
if grep -Eq 'LISTEN.+:(80|443)\b' /tmp/nakpanel-ss.txt; then
  echo "unexpected listener on port 80 or 443" >&2
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

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_client_dashboard "${tmpdir}/client-dashboard.html"

curl -sk --fail "https://${VM_IP}:7443/healthz" | grep -qx 'ok'

plain_status="$(curl -sS --max-time 5 -o "${tmpdir}/plain.txt" -w '%{http_code}' "http://${VM_IP}:7443/login" || true)"
if [[ "${plain_status}" == "200" ]] || grep -q 'nakpanel login' "${tmpdir}/plain.txt"; then
  echo "plain HTTP exposed a usable panel response" >&2
  exit 1
fi

echo "Phase 1 Multipass verification passed for https://${VM_IP}:7443"
