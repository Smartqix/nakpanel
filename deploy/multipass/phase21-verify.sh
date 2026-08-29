#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase21 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase20-verify.sh"
fi

sync_repo "${ROOT_DIR}"
VM_IP="$(vm_ip)"
multipass exec "${VM_NAME}" -- env NAKPANEL_FTPS_PUBLIC_ADDRESS="${VM_IP}" bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo env NAKPANEL_FTPS_PUBLIC_ADDRESS="${NAKPANEL_FTPS_PUBLIC_ADDRESS}" ./deploy/install/phase21-25-install.sh
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
fail(){ echo "phase21: $*" >&2; exit 1; }
db(){ multipass exec "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){ local query="$1" expected="$2" value=""; for _ in $(seq 1 90); do value="$(db "${query}")"; [[ "${value}" == "${expected}" ]] && return 0; sleep 2; done; fail "got ${value}, want ${expected}: ${query}"; }

for _ in $(seq 1 60); do curl -skf -o /dev/null "https://${VM_IP}:7443/login" && break; sleep 2; done
curl -skf -o /dev/null "https://${VM_IP}:7443/login" || fail "panel is not reachable"
curl -sk --fail -c "${tmpdir}/admin.cookies" -L -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"
site_id="$(db "SELECT id FROM sites WHERE desired_status='active' ORDER BY id LIMIT 1")"
subscription_id="$(db "SELECT subscription_id FROM sites WHERE id=${site_id}")"
domain="$(db "SELECT domain FROM sites WHERE id=${site_id}")"
[[ -n "${site_id}" && -n "${subscription_id}" && -n "${domain}" ]] || fail "an active domain fixture is required"

db "DELETE FROM ftp_accounts WHERE name='phase21ftp'; DELETE FROM sftp_access_identities WHERE subscription_id=${subscription_id} AND name='phase21'" >/dev/null
db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(COALESCE(hosting_policy,'{}'::jsonb),'{schema_version}','2'::jsonb,true),'{permissions,hosting}','true'::jsonb,true),'{permissions,sftp}','true'::jsonb,true),'{permissions,ftps}','true'::jsonb,true),'{access,ftps_enabled}','true'::jsonb,true) WHERE subscription_id=${subscription_id}" >/dev/null
db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(COALESCE(hosting_policy,'{}'::jsonb),'{resources,max_ftp_accounts}','4'::jsonb,true),'{resources,max_sftp_identities}','4'::jsonb,true) WHERE subscription_id=${subscription_id}" >/dev/null

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
rm -f /tmp/phase21-sftp /tmp/phase21-sftp.pub
ssh-keygen -q -t ed25519 -N '' -f /tmp/phase21-sftp
REMOTE
public_key="$(multipass exec "${VM_NAME}" -- cat /tmp/phase21-sftp.pub | tr -d '\r\n')"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  --data-urlencode "public_key=${public_key}" -d 'name=phase21' -d "relative_root=domains/${domain}/public_html" -d 'enabled=true' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/sftp" -o /dev/null
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "site_id=${site_id}" -d 'name=phase21ftp' --data-urlencode 'password=Phase21-FTPS!2026' -d 'enabled=true' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/ftp" -o /dev/null

wait_for "SELECT convergence_status FROM ftp_accounts WHERE name='phase21ftp'" "in_sync"
multipass exec "${VM_NAME}" -- sudo systemctl is-active --quiet nakpanel-proftpd.service || fail "Nakpanel ProFTPD is not active"
multipass exec "${VM_NAME}" -- sudo grep -Fq 'TLSRequired on' /etc/nakpanel/proftpd/proftpd.conf || fail "FTPS is not TLS-only"
multipass exec "${VM_NAME}" -- sudo grep -Fq 'LoadModule mod_tls.c' /etc/nakpanel/proftpd/proftpd.conf || fail "ProFTPD TLS module is not required"
multipass exec "${VM_NAME}" -- sudo grep -Fq 'PassivePorts 49152 49252' /etc/nakpanel/proftpd/proftpd.conf || fail "FTPS passive range drifted"
curl --silent --show-error --fail --insecure --ssl-reqd --user 'phase21ftp:Phase21-FTPS!2026' "ftp://${VM_IP}/" -o /dev/null || fail "explicit TLS FTPS login failed"
plain_response="$(multipass exec "${VM_NAME}" -- bash -c "printf 'USER phase21ftp\\r\\nPASS Phase21-FTPS!2026\\r\\nQUIT\\r\\n' | nc -w 3 127.0.0.1 21" | tr -d '\r')"
grep -Eq 'TLS|SSL|530|550' <<<"${plain_response}" || fail "plaintext FTP login was not refused"
system_username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")"
sshd_policy="/etc/ssh/sshd_config.d/90-nakpanel-${system_username}.conf"
authorized_keys="/etc/nakpanel/ssh/authorized_keys/${system_username}"
domain_anchor="/home/${system_username}/domains/${domain}"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%U:%G:%a' "/home/${system_username}/domains" | tr -d '\r')" == "root:root:711" ]] || fail "subscription domains anchor is not root-owned 0711"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%U:%G:%a' "${domain_anchor}" | tr -d '\r')" == "root:root:711" ]] || fail "domain anchor is not root-owned 0711"
if multipass_exec_short "${VM_NAME}" -- sudo -u "${system_username}" mv "${domain_anchor}" "${domain_anchor}.moved" 2>/dev/null; then
  fail "subscription account could rename the root-owned domain anchor"
fi
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
sudo env PATH="${PATH}" go test ./internal/agent/ops -run '^TestFileManagerRootDropsFilesystemIdentity$' -count=1
REMOTE
multipass exec "${VM_NAME}" -- sudo grep -Fq "ChrootDirectory /home/${system_username}" "${sshd_policy}" || fail "SFTP subscription chroot is missing"
multipass exec "${VM_NAME}" -- sudo grep -Fq 'DisableForwarding yes' "${sshd_policy}" || fail "SFTP forwarding is not disabled"
multipass exec "${VM_NAME}" -- sudo grep -Fq 'PermitTTY no' "${sshd_policy}" || fail "SFTP TTY access is not disabled"
multipass exec "${VM_NAME}" -- bash -c "test \"\$(sudo stat -c '%U:%G:%a' '${authorized_keys}')\" = root:root:600" || fail "SFTP authorized keys are not root-owned 0600"
multipass exec "${VM_NAME}" -- sudo grep -Fq "restrict,command=\"internal-sftp -d /domains/${domain}/public_html\"" "${authorized_keys}" || fail "SFTP domain start directory is not confined"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/access" -o "${tmpdir}/access.html"
grep -Fq 'Password-protected directories' "${tmpdir}/access.html" || fail "domain Access workspace is incomplete"

echo "Phase 21 domain foundation and hosting access verification passed for ${VM_NAME} (${VM_IP})."
