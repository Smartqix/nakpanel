#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase22 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase21-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

VM_IP="$(vm_ip)"
fail(){ echo "phase22: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
panel_ready=0
for _ in $(seq 1 60); do
  if curl -skf -o /dev/null "https://${VM_IP}:7443/login"; then
    panel_ready=1
    break
  fi
  sleep 2
done
[[ "${panel_ready}" == "1" ]] || fail "panel is not reachable"
curl -sk --fail -c "${tmpdir}/admin.cookies" -L -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"
site_id="$(db "SELECT id FROM sites WHERE desired_status='active' ORDER BY id LIMIT 1")"
domain="$(db "SELECT domain FROM sites WHERE id=${site_id}")"
subscription_id="$(db "SELECT subscription_id FROM sites WHERE id=${site_id}")"
db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(COALESCE(hosting_policy,'{}'::jsonb),'{permissions,php_settings}','true'::jsonb,true),'{php,fpm_max_children}','3'::jsonb,true),'{php,memory_limit_mb}','128'::jsonb,true),'{php,opcache_enabled}','true'::jsonb,true),'{php,opcache_memory_mb}','64'::jsonb,true),'{web,compression}','true'::jsonb,true),'{web,fastcgi_microcache}','true'::jsonb,true) WHERE subscription_id=${subscription_id}" >/dev/null
policy_patch='{"web":{"request_body_limit_mb":24,"compression":true,"fastcgi_microcache":true,"security_header_preset":"balanced"},"php":{"fpm_max_children":3,"memory_limit_mb":128,"opcache_enabled":true,"opcache_memory_mb":64}}'
curl -sk --fail -o /dev/null -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  --data-urlencode "policy_patch=${policy_patch}" -d 'policy_return_tab=web-server' \
  "https://${VM_IP}:7443/sites/${site_id}/policy"
for _ in $(seq 1 90); do [[ "$(db "SELECT settings_status FROM sites WHERE id=${site_id}")" == "in_sync" ]] && break; sleep 2; done
[[ "$(db "SELECT settings_status FROM sites WHERE id=${site_id}")" == "in_sync" ]] || fail "site runtime did not converge"
multipass_exec_short "${VM_NAME}" -- sudo test -f "/etc/systemd/system/nakpanel-php-fpm@${site_id}.service" || fail "dedicated PHP-FPM unit is missing"
multipass_exec_short "${VM_NAME}" -- sudo grep -Fq 'MemoryMax=' "/etc/systemd/system/nakpanel-php-fpm@${site_id}.service" || fail "PHP cgroup ceiling is missing"
multipass_exec_short "${VM_NAME}" -- sudo grep -Fq 'client_max_body_size 24m' "/etc/nginx/sites-available/${domain}.conf" || fail "typed nginx body limit was not rendered"
multipass_exec_short "${VM_NAME}" -- sudo grep -Fq 'fastcgi_cache ' "/etc/nginx/sites-available/${domain}.conf" || fail "FastCGI microcache is cosmetic"
multipass_exec_short "${VM_NAME}" -- sudo grep -Fq 'fastcgi_cache_key "$scheme$request_method$host$request_uri"' "/etc/nginx/sites-available/${domain}.conf" || fail "FastCGI microcache key is missing"
multipass_exec_short "${VM_NAME}" -- sudo grep -Fq 'fastcgi_no_cache $cookie_PHPSESSID $http_authorization' "/etc/nginx/sites-available/${domain}.conf" || fail "FastCGI authenticated-response storage guard is missing"
multipass_exec_short "${VM_NAME}" -- sudo nginx -t >/dev/null || fail "generated nginx configuration is invalid"
# Phase 29 note: the workspace copy changed with the policy-builder redesign;
# assert on the stable heading instead.
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/web-server" | grep -Fq 'Structured nginx controls' || fail "web-server workspace is missing"

echo "Phase 22 dedicated PHP and structured nginx verification passed for ${VM_NAME} (${VM_IP})."
