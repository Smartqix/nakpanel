#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase25 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase24-verify.sh"
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
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
fail(){ echo "phase25: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){ local query="$1" expected="$2" value=""; for _ in $(seq 1 120); do value="$(db "${query}")"; [[ "${value}" == "${expected}" ]] && return 0; sleep 2; done; fail "got ${value}, want ${expected}: ${query}"; }
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
subscription_id="$(db "SELECT subscription_id FROM sites WHERE desired_status='active' ORDER BY id LIMIT 1")"
site_id="$(db "SELECT id FROM sites WHERE subscription_id=${subscription_id} ORDER BY id LIMIT 1")"
username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")"
db "UPDATE settings SET valkey_capacity_mb=1024 WHERE id; UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(COALESCE(hosting_policy,'{}'::jsonb),'{permissions,valkey}','true'::jsonb,true),'{valkey,enabled}','true'::jsonb,true),'{valkey,memory_mb}','64'::jsonb,true),'{valkey,max_clients}','32'::jsonb,true),'{valkey,idle_timeout_seconds}','300'::jsonb,true),'{valkey,cpu_percent}','25'::jsonb,true),'{valkey,process_limit}','64'::jsonb,true),'{resources,valkey_memory_mb}','64'::jsonb,true) WHERE subscription_id=${subscription_id}" >/dev/null
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d 'desired_state=enabled' -d 'memory_mb=64' -d 'max_clients=32' -d 'idle_timeout_seconds=300' \
  -d 'cpu_percent=25' -d 'process_limit=64' -d 'rotate_credential=true' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/valkey" -o "${tmpdir}/credential.html"
credential="$(sed -n 's:.*<pre>\([^<]*\)</pre>.*:\1:p' "${tmpdir}/credential.html")"
[[ -n "${credential}" ]] || fail "one-time Valkey credential was not returned"
wait_for "SELECT convergence_status FROM valkey_instances WHERE subscription_id=${subscription_id}" "in_sync"
socket="/run/nakpanel/valkey/sub-${subscription_id}/valkey.sock"
multipass_exec_short "${VM_NAME}" -- sudo test -S "${socket}" || fail "Valkey Unix socket is missing"
multipass_exec_short "${VM_NAME}" -- sudo getfacl -cp /run/nakpanel | grep -Fqx "user:${username}:--x" || fail "subscription cache traversal ACL is missing"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%a %U:%G' /run/nakpanel | tr -d '\r')" == "750 root:nakpanel" ]] || fail "agent socket directory permissions changed"
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning ping | grep -Fq PONG || fail "subscription account cannot authenticate to Valkey"
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning set phase25-idempotency retained | grep -Fq OK || fail "Valkey fixture could not be written"
started_before="$(multipass_exec_short "${VM_NAME}" -- sudo podman inspect "nakpanel-valkey-sub-${subscription_id}" --format '{{.State.StartedAt}}' | tr -d '\r')"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d 'desired_state=enabled' -d 'memory_mb=64' -d 'max_clients=32' -d 'idle_timeout_seconds=300' \
  -d 'cpu_percent=25' -d 'process_limit=64' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/valkey" -o /dev/null
wait_for "SELECT convergence_status FROM valkey_instances WHERE subscription_id=${subscription_id}" "in_sync"
started_after="$(multipass_exec_short "${VM_NAME}" -- sudo podman inspect "nakpanel-valkey-sub-${subscription_id}" --format '{{.State.StartedAt}}' | tr -d '\r')"
[[ "${started_before}" == "${started_after}" ]] || fail "idempotent Valkey convergence restarted the cache"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning get phase25-idempotency | tr -d '\r')" == "retained" ]] || fail "idempotent Valkey convergence flushed cache data"
flush_output="$(multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning FLUSHALL 2>&1 || true)"
grep -Fq 'NOPERM' <<<"${flush_output}" || fail "dangerous Valkey command was not denied"
multipass_exec_short "${VM_NAME}" -- sudo podman inspect "nakpanel-valkey-sub-${subscription_id}" --format '{{.HostConfig.NetworkMode}}' | grep -Fqx none || fail "Valkey has a network namespace"
if multipass_exec_short "${VM_NAME}" -- sudo ss -ltnp | grep -E 'valkey|redis'; then
  fail "Valkey exposed a TCP listener"
fi
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/redis" -o "${tmpdir}/cache.html"
grep -Fq "${socket}" "${tmpdir}/cache.html" || fail "domain cache page does not show the subscription socket"
if grep -Fq "${credential}" "${tmpdir}/cache.html"; then fail "Valkey credential rendered after rotation"; fi

echo "Phase 25 subscription Valkey cache verification passed for ${VM_NAME} (${VM_IP})."
