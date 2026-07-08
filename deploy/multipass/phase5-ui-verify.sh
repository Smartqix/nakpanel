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

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

REMOTE_SRC="/tmp/nakpanel-src"
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
sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE kind IN ('create_site', 'create_database', 'issue_cert')
  AND (
    args->>'domain' = 'phase5-ui.test'
    OR args->>'db_name' = 'np_phase5'
    OR args->>'db_user' = 'np_phase5_user'
    OR args->>'site_id' IN (
      SELECT id::text FROM sites WHERE domain = 'phase5-ui.test'
    )
    OR args->>'database_id' IN (
      SELECT id::text FROM databases WHERE db_name = 'np_phase5' OR db_user = 'np_phase5_user'
    )
  );
DELETE FROM sites WHERE domain = 'phase5-ui.test' OR username = 'npui';
DELETE FROM databases WHERE db_name = 'np_phase5' OR db_user = 'np_phase5_user';
UPDATE subscriptions
SET status = 'cancelled', updated_at = now()
WHERE customer_user_id = (SELECT id FROM users WHERE email = 'admin@nakpanel.test')
  AND status = 'active';
INSERT INTO subscriptions (customer_id, customer_user_id, plan_id, name, status)
SELECT c.id, u.id, p.id, 'Phase verifier unlimited', 'active'
FROM users u
JOIN customers c ON c.login_user_id = u.id
JOIN plans p ON p.name = 'Legacy Unlimited'
WHERE u.email = 'admin@nakpanel.test';
SQL

sudo mariadb -e "DROP DATABASE IF EXISTS \`np_phase5\`; DROP USER IF EXISTS 'np_phase5_user'@'localhost';"
sudo rm -f /etc/nginx/sites-enabled/phase5-ui.test.conf /etc/nginx/sites-available/phase5-ui.test.conf
sudo rm -f /etc/php/8.3/fpm/pool.d/nakpanel-npui-phase5-ui-test.conf
sudo rm -rf /home/npui
sudo systemctl reload nginx || true
sudo systemctl reload php8.3-fpm || true

sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0644 deploy/systemd/nakpanel-agent.service /etc/systemd/system/nakpanel-agent.service
sudo install -m 0644 deploy/systemd/nakpanel.service /etc/systemd/system/nakpanel.service
cd /
sudo rm -rf "${REMOTE_SRC}"
test ! -e "${REMOTE_SRC}"

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

assert_client_dashboard() {
  local file="$1"
  assert_contains "${file}" 'Client dashboard'
  assert_contains "${file}" 'Account overview'
  assert_contains "${file}" 'Hosting account'
  for form in 'action="/sites"' 'action="/databases"' 'action="/certificates"'; do
    if grep -Fq -- "${form}" "${file}"; then
      echo "client dashboard exposed admin form ${form}" >&2
      cat "${file}" >&2
      exit 1
    fi
  done
}

curl -sk --fail "https://${VM_IP}:7443/login" > "${tmpdir}/login.html"
assert_contains "${tmpdir}/login.html" 'nakpanel login'
assert_contains "${tmpdir}/login.html" 'href="/assets/app.css"'

curl -sk --fail "https://${VM_IP}:7443/assets/app.css" > "${tmpdir}/app.css"
assert_contains "${tmpdir}/app.css" '--np-bg'
assert_contains "${tmpdir}/app.css" '.np-app'
assert_contains "${tmpdir}/app.css" 'content:attr(data-label)'

multipass exec "${VM_NAME}" -- test ! -e "${REMOTE_SRC}"

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/sites"'
assert_contains "${tmpdir}/admin-dashboard.html" 'name="username"'
assert_contains "${tmpdir}/admin-dashboard.html" 'name="domain"'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/certificates"'
assert_contains "${tmpdir}/admin-dashboard.html" 'action="/databases"'
assert_contains "${tmpdir}/admin-dashboard.html" 'name="db_name"'
assert_contains "${tmpdir}/admin-dashboard.html" 'name="db_user"'

site_status="$(curl -sk -o "${tmpdir}/site-create.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -d 'username=npui' \
  -d 'domain=phase5-ui.test' \
  -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${site_status}" != "303" ]]; then
  echo "UI site create returned HTTP ${site_status}" >&2
  cat "${tmpdir}/site-create.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 60); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM sites WHERE domain = 'phase5-ui.test'" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, domain, status, last_error FROM sites WHERE domain = 'phase5-ui.test'" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200 >&2 || true
echo "phase5 UI site did not become active" >&2
exit 1
REMOTE

curl -s --fail -H 'Host: phase5-ui.test' "http://${VM_IP}/" | grep -qx 'nakpanel placeholder for phase5-ui.test'

db_status="$(curl -sk -o "${tmpdir}/database-create.out" -w '%{http_code}' \
  -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
  -d 'engine=mariadb' \
  -d 'db_name=np_phase5' \
  -d 'db_user=np_phase5_user' \
  "https://${VM_IP}:7443/databases")"
if [[ "${db_status}" != "303" ]]; then
  echo "UI database create returned HTTP ${db_status}" >&2
  cat "${tmpdir}/database-create.out" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 60); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM databases WHERE db_name = 'np_phase5'" | grep -qx 'active'; then
    break
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM databases WHERE db_name = 'np_phase5'" | grep -qx 'active'
sudo mariadb -NBe "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'np_phase5'" | grep -qx 'np_phase5'
sudo mariadb -NBe "SELECT CONCAT(User, '@', Host) FROM mysql.user WHERE User = 'np_phase5_user' AND Host = 'localhost'" | grep -qx 'np_phase5_user@localhost'
sudo mariadb -NBe "SHOW GRANTS FOR 'np_phase5_user'@'localhost'" | grep -F 'ON `np_phase5`.*'
REMOTE

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/" > "${tmpdir}/admin-after-actions.html"
assert_contains "${tmpdir}/admin-after-actions.html" 'phase5-ui.test'
assert_contains "${tmpdir}/admin-after-actions.html" 'npui'
assert_contains "${tmpdir}/admin-after-actions.html" 'np_phase5'
assert_contains "${tmpdir}/admin-after-actions.html" 'np_phase5_user'
assert_contains "${tmpdir}/admin-after-actions.html" 'data-label="Domain"'
assert_contains "${tmpdir}/admin-after-actions.html" 'data-label="Name"'
assert_contains "${tmpdir}/admin-after-actions.html" 'data-label="Created"'

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=client@nakpanel.test' \
  -d 'password=NakpanelClient!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client-dashboard.html"
assert_client_dashboard "${tmpdir}/client-dashboard.html"

client_site_status="$(curl -sk -o "${tmpdir}/client-site.out" -w '%{http_code}' \
  -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" \
  -d 'username=npclient' \
  -d 'domain=client-phase5-ui.test' \
  -d 'php_version=8.3' \
  "https://${VM_IP}:7443/sites")"
if [[ "${client_site_status}" != "403" ]]; then
  echo "client site create returned HTTP ${client_site_status}, want 403" >&2
  cat "${tmpdir}/client-site.out" >&2
  exit 1
fi

client_db_status="$(curl -sk -o "${tmpdir}/client-database.out" -w '%{http_code}' \
  -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" \
  -d 'engine=mariadb' \
  -d 'db_name=np_client_phase5' \
  -d 'db_user=np_client_phase5_user' \
  "https://${VM_IP}:7443/databases")"
if [[ "${client_db_status}" != "403" ]]; then
  echo "client database create returned HTTP ${client_db_status}, want 403" >&2
  cat "${tmpdir}/client-database.out" >&2
  exit 1
fi

client_cert_status="$(curl -sk -o "${tmpdir}/client-cert.out" -w '%{http_code}' \
  -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" \
  -d 'domain=phase5-ui.test' \
  -d 'issuer=local-self-signed' \
  "https://${VM_IP}:7443/certificates")"
if [[ "${client_cert_status}" != "403" ]]; then
  echo "client certificate issue returned HTTP ${client_cert_status}, want 403" >&2
  cat "${tmpdir}/client-cert.out" >&2
  exit 1
fi

echo "Phase 5 UI verification passed for https://${VM_IP}:7443 with embedded assets and UI-driven provisioning"
