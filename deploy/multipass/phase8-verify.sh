#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

export NAKPANEL_MULTIPASS_VM="${VM_NAME}"
export NAKPANEL_MULTIPASS_IMAGE="${IMAGE}"
"${ROOT_DIR}/deploy/multipass/phase7-verify.sh"

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

post_admin() {
  local label="$1"
  local endpoint="$2"
  shift 2
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" \
    "https://${VM_IP}:7443/${endpoint}")"
  if [[ "${status}" != "303" ]]; then
    echo "${label} returned HTTP ${status}" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
}

post_expect_quota_exceeded() {
  local label="$1"
  local endpoint="$2"
  shift 2
  local status
  status="$(curl -sk -o "${tmpdir}/${label}.out" -w '%{http_code}' \
    -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/admin.cookies")" \
    "$@" \
    "https://${VM_IP}:7443/${endpoint}")"
  if [[ "${status}" != "400" ]]; then
    echo "${label} returned HTTP ${status}, want 400" >&2
    cat "${tmpdir}/${label}.out" >&2
    exit 1
  fi
  assert_contains "${tmpdir}/${label}.out" 'quota exceeded'
}

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
quota_packages=(quota)
if apt-cache show "linux-modules-extra-$(uname -r)" >/dev/null 2>&1; then
  quota_packages+=("linux-modules-extra-$(uname -r)")
fi
sudo apt-get install -y "${quota_packages[@]}"
sudo modprobe quota_v2 >/dev/null 2>&1 || true

quota_target="$(findmnt -n -o TARGET --target /home)"
if [[ -z "${quota_target}" ]]; then
  echo "could not find filesystem for /home" >&2
  exit 1
fi
if ! findmnt -n -o OPTIONS --target /home | tr ',' '\n' | grep -qx 'usrquota'; then
  sudo mount -o remount,usrquota,grpquota "${quota_target}"
fi
quota_state="$(sudo quotaon -p "${quota_target}" 2>/dev/null || true)"
if ! grep -Eq 'user quota .* is on' <<<"${quota_state}"; then
  if ! sudo quotacheck -ugm "${quota_target}"; then
    sudo quotacheck -cugm "${quota_target}"
  fi
  sudo quotaon -uv "${quota_target}" || true
fi
quota_state="$(sudo quotaon -p "${quota_target}" 2>/dev/null || true)"
grep -Eq 'user quota .* is on' <<<"${quota_state}"

sudo -u postgres psql -d nakpanel >/dev/null <<'SQL'
DELETE FROM river_job
WHERE args::text LIKE '%phase8-quota.test%'
   OR args::text LIKE '%phase8-over.test%'
   OR args::text LIKE '%np_phase8%';
DELETE FROM backups WHERE target_name IN ('phase8-quota.test', 'phase8-over.test');
DELETE FROM databases WHERE db_name LIKE 'np_phase8%';
DELETE FROM sites WHERE domain IN ('phase8-quota.test', 'phase8-over.test');
SQL
sudo rm -f /etc/nginx/sites-enabled/phase8-quota.test.conf /etc/nginx/sites-available/phase8-quota.test.conf
sudo rm -f /etc/nginx/sites-enabled/phase8-over.test.conf /etc/nginx/sites-available/phase8-over.test.conf
sudo rm -f /etc/php/8.3/fpm/pool.d/nakpanel-npq8-phase8-quota-test.conf
sudo userdel -r npq8 >/dev/null 2>&1 || true
sudo systemctl start nginx php8.3-fpm
sudo systemctl restart nakpanel-agent.service nakpanel.service
sudo systemctl is-active --quiet nginx
sudo systemctl is-active --quiet nakpanel-agent.service
sudo systemctl is-active --quiet nakpanel.service
REMOTE

panel_ready=0
for _ in $(seq 1 60); do
  if curl -sk --fail "https://${VM_IP}:7443/healthz" >/dev/null; then
    panel_ready=1
    break
  fi
  sleep 1
done
if [[ "${panel_ready}" != "1" ]]; then
  multipass exec "${VM_NAME}" -- sudo journalctl -u nakpanel --no-pager -n 200 >&2 || true
  echo "panel did not become ready after Phase 8 setup" >&2
  exit 1
fi

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' \
  -d 'legacy=1' \
  -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin-dashboard.html"
assert_contains "${tmpdir}/admin-dashboard.html" 'Admin dashboard'

quota_state="$(multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "
SELECT u.id,
       (SELECT COUNT(*) FROM sites WHERE owner_user_id = u.id AND status <> 'failed'),
       (SELECT COUNT(*) FROM databases WHERE owner_user_id = u.id AND status <> 'failed'),
       (SELECT COUNT(*) FROM backups WHERE owner_user_id = u.id AND status <> 'failed'),
       COALESCE((SELECT SUM(size_bytes) FROM backups WHERE owner_user_id = u.id AND status = 'active'), 0)
FROM users u
WHERE u.email = 'admin@nakpanel.test'
")"
IFS='|' read -r admin_id current_sites current_databases current_backups current_backup_bytes <<<"${quota_state}"
if [[ -z "${admin_id}" ]]; then
  echo "could not find admin user id" >&2
  exit 1
fi
max_sites=$((current_sites + 1))
max_databases=$((current_databases + 1))
max_backups=$((current_backups + 1))
backup_storage_mb=$(((current_backup_bytes + 128 * 1024 * 1024 + 1024 * 1024 - 1) / (1024 * 1024)))

post_admin phase8-quota quotas \
  -d "user_id=${admin_id}" \
  -d "max_sites=${max_sites}" \
  -d "max_databases=${max_databases}" \
  -d 'storage_mb=1024' \
  -d "max_backups=${max_backups}" \
  -d "backup_storage_mb=${backup_storage_mb}" \
  -d 'site_disk_quota_mb=1' \
  -d 'php_max_children=2' \
  -d 'php_memory_mb=64'

post_admin phase8-site sites \
  -d 'username=npq8' \
  -d 'domain=phase8-quota.test' \
  -d 'php_version=8.3'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM sites WHERE domain = 'phase8-quota.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    break
  fi
  sleep 1
done
if ! sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM sites WHERE domain = 'phase8-quota.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
  sudo -u postgres psql -d nakpanel -c "SELECT id, domain, status, last_error FROM sites ORDER BY id DESC LIMIT 10" >&2
  sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
  echo "phase8 site did not become active" >&2
  exit 1
fi

username="$(sudo -u postgres psql -d nakpanel -tAc "SELECT username FROM sites WHERE domain='phase8-quota.test'" | xargs)"
docroot="$(sudo -u postgres psql -d nakpanel -tAc "SELECT document_root FROM sites WHERE domain='phase8-quota.test'" | xargs)"
pool="/etc/php/8.3/fpm/pool.d/nakpanel-${username}-phase8-quota-test.conf"
test -f "${pool}"
grep -Fq 'pm.max_children = 2' "${pool}"
grep -Fq 'php_admin_value[memory_limit] = 64M' "${pool}"

quota_target="$(findmnt -n -o TARGET --target "${docroot}")"
sudo setquota -u "${username}" 0 1024 0 0 "${quota_target}"
sudo quota -u "${username}" | tee /tmp/nakpanel-phase8-quota.txt
grep -Eq '(^|[[:space:]])1024([[:space:]]|$)' /tmp/nakpanel-phase8-quota.txt

if sudo -u "${username}" dd if=/dev/zero of="${docroot}/too-big.bin" bs=1M count=3 status=none; then
  echo "over-quota write succeeded for ${username}" >&2
  exit 1
fi
sudo rm -f "${docroot}/too-big.bin"
REMOTE

post_admin phase8-db databases \
  -d 'engine=mariadb' \
  -d 'db_name=np_phase8' \
  -d 'db_user=np_phase8_user'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM databases WHERE db_name = 'np_phase8' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, db_name, status, last_error FROM databases ORDER BY id DESC LIMIT 10" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
echo "phase8 database did not become active" >&2
exit 1
REMOTE

post_admin phase8-backup backups -d 'domain=phase8-quota.test'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
for _ in $(seq 1 90); do
  if sudo -u postgres psql -d nakpanel -tAc "SELECT status FROM backups WHERE target_name = 'phase8-quota.test' ORDER BY id DESC LIMIT 1" | grep -qx 'active'; then
    exit 0
  fi
  sleep 1
done
sudo -u postgres psql -d nakpanel -c "SELECT id, target_name, status, archive_path, last_error FROM backups ORDER BY id DESC LIMIT 10" >&2
sudo -u postgres psql -d nakpanel -c "SELECT id, kind, state, args, errors FROM river_job WHERE kind = 'create_backup' ORDER BY id DESC LIMIT 20" >&2
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 250 >&2 || true
echo "phase8 backup did not become active" >&2
exit 1
REMOTE

post_expect_quota_exceeded phase8-site-over sites \
  -d 'username=npq9' \
  -d 'domain=phase8-over.test' \
  -d 'php_version=8.3'
post_expect_quota_exceeded phase8-db-over databases \
  -d 'engine=mariadb' \
  -d 'db_name=np_phase8_over' \
  -d 'db_user=np_phase8_over_user'
post_expect_quota_exceeded phase8-backup-over backups -d 'domain=phase8-quota.test'

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/?legacy=1" > "${tmpdir}/phase8-dashboard.html"
assert_contains "${tmpdir}/phase8-dashboard.html" 'phase8-quota.test'
assert_contains "${tmpdir}/phase8-dashboard.html" '1 MB'

echo "phase8 verification passed for account quotas, PHP-FPM limits, setquota disk isolation, and over-quota rejection on https://${VM_IP}:7443"
