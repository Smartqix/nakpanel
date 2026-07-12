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
sudo apt-get install -y ca-certificates curl postgresql postgresql-contrib nginx php8.3-fpm mariadb-server build-essential python3

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
sudo systemctl enable --now nginx php8.3-fpm mariadb

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
sudo ss -ltnp | tee /tmp/nakpanel-phase4-ss.txt
grep -Eq 'LISTEN.+:7443\b' /tmp/nakpanel-phase4-ss.txt
grep -Eq 'LISTEN.+:80\b' /tmp/nakpanel-phase4-ss.txt
if grep -Eq 'LISTEN.+:443\b' /tmp/nakpanel-phase4-ss.txt; then
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

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE kind = 'create_database'
  AND (
    args->>'db_name' = 'np_phase4'
    OR args->>'db_user' = 'np_phase4_user'
    OR args->>'database_id' IN (
      SELECT id::text FROM databases WHERE db_name = 'np_phase4' OR db_user = 'np_phase4_user'
    )
  );
DELETE FROM databases WHERE db_name = 'np_phase4' OR db_user = 'np_phase4_user';
SQL

sudo mariadb -e "DROP DATABASE IF EXISTS \`np_phase4\`; DROP USER IF EXISTS 'np_phase4_user'@'localhost';"
REMOTE

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'

create_status="$(curl -sk -o "${tmpdir}/database-create.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
  -d 'engine=mariadb' \
  -d 'db_name=np_phase4' \
  -d 'db_user=np_phase4_user' \
  "https://${VM_IP}:7443/databases")"
if [[ "${create_status}" != "303" ]]; then
  echo "database create returned HTTP ${create_status}" >&2
  cat "${tmpdir}/database-create.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

status_active=0
for _ in $(seq 1 60); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM databases WHERE db_name = 'np_phase4'" | grep -qx 'active'; then
    status_active=1
    break
  fi
  sleep 1
done
if [[ "${status_active}" != "1" ]]; then
  sudo -u postgres psql -d nakpanel -c "SELECT id, engine, db_name, db_user, status, last_error FROM databases" >&2
  sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200 >&2 || true
  echo "database did not become active" >&2
  exit 1
fi

sudo mariadb -NBe "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'np_phase4'" | grep -qx 'np_phase4'
sudo mariadb -NBe "SELECT CONCAT(User, '@', Host) FROM mysql.user WHERE User = 'np_phase4_user' AND Host = 'localhost'" | grep -qx 'np_phase4_user@localhost'
sudo mariadb -NBe "SHOW GRANTS FOR 'np_phase4_user'@'localhost'" | grep -F 'ON `np_phase4`.*'

password_present="$(sudo -u postgres psql -d nakpanel -tAc "SELECT COALESCE(bool_or(args ? 'password'), false) FROM river_job WHERE kind = 'create_database' AND args->>'db_name' = 'np_phase4'" | tr -d '[:space:]')"
if [[ "${password_present}" != "f" ]]; then
  sudo -u postgres psql -d nakpanel -c "SELECT id, kind, args FROM river_job WHERE kind = 'create_database' AND args->>'db_name' = 'np_phase4'" >&2
  echo "generated database password was not scrubbed from River job args" >&2
  exit 1
fi
REMOTE

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_client_dashboard "${tmpdir}/client-dashboard.html"

client_status="$(curl -sk -o "${tmpdir}/client-database-create.out" -w '%{http_code}' \
  -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" \
  -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/client.cookies")" \
  -d 'engine=mariadb' \
  -d 'db_name=np_client_phase4' \
  -d 'db_user=np_client_phase4_user' \
  "https://${VM_IP}:7443/databases")"
if [[ "${client_status}" != "403" ]]; then
  echo "client database create returned HTTP ${client_status}, want 403" >&2
  cat "${tmpdir}/client-database-create.out" >&2
  exit 1
fi

echo "Phase 4 MariaDB verification passed for https://${VM_IP}:7443 with database np_phase4"
