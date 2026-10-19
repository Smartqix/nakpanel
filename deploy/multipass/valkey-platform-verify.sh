#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "valkey-platform verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

assert_current_vm_identity
assert_qualification_bundle_staged
VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
fail(){ echo "valkey-platform: $*" >&2; exit 1; }
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
db "UPDATE settings SET valkey_capacity_mb=1024 WHERE id;
UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(jsonb_set(
COALESCE(hosting_policy,'{}'::jsonb),
'{permissions}',COALESCE(hosting_policy->'permissions','{}'::jsonb)||jsonb_build_object('valkey',true)),
'{valkey}',jsonb_build_object('enabled',true,'memory_mb',64,'max_clients',32,'idle_timeout_seconds',300,'cpu_percent',25,'process_limit',64)),
'{resources}',COALESCE(hosting_policy->'resources','{}'::jsonb)||jsonb_build_object('valkey_memory_mb',64)) WHERE subscription_id=${subscription_id}" >/dev/null
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" -H 'Accept: application/json' -H 'X-Nakpanel-SPA: true' \
  -d 'desired_state=enabled' -d 'memory_mb=64' -d 'max_clients=32' -d 'idle_timeout_seconds=300' \
  -d 'cpu_percent=25' -d 'process_limit=64' -d 'rotate_credential=true' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/valkey" -o "${tmpdir}/credential.json"
credential="$(python3 - "${tmpdir}/credential.json" <<'PY'
import json,sys
credential=json.load(open(sys.argv[1])).get('password')
assert isinstance(credential,str) and credential, 'one-time Valkey credential missing'
print(credential)
PY
)"
[[ -n "${credential}" ]] || fail "one-time Valkey credential was not returned"
wait_for "SELECT convergence_status FROM valkey_instances WHERE subscription_id=${subscription_id}" "in_sync"
socket="/run/nakpanel/valkey/sub-${subscription_id}/valkey.sock"
multipass_exec_short "${VM_NAME}" -- sudo test -S "${socket}" || fail "Valkey Unix socket is missing"
assert_valkey_traversal() {
  multipass_exec_short "${VM_NAME}" -- sudo getfacl -cp /run/nakpanel | grep -Fqx "user:${username}:--x" || fail "subscription cache traversal ACL is missing (observed without repair)"
  [[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%a %U:%G' /run/nakpanel | tr -d '\r')" == "750 root:nakpanel" ]] || fail "agent socket directory permissions changed"
}
assert_valkey_traversal
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning ping | grep -Fq PONG || fail "subscription account cannot authenticate to Valkey"
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning set valkey-platform-idempotency retained | grep -Fq OK || fail "Valkey fixture could not be written"
started_before="$(multipass_exec_short "${VM_NAME}" -- sudo podman inspect "nakpanel-valkey-sub-${subscription_id}" --format '{{.State.StartedAt}}' | tr -d '\r')"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d 'desired_state=enabled' -d 'memory_mb=64' -d 'max_clients=32' -d 'idle_timeout_seconds=300' \
  -d 'cpu_percent=25' -d 'process_limit=64' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/valkey" -o /dev/null
wait_for "SELECT convergence_status FROM valkey_instances WHERE subscription_id=${subscription_id}" "in_sync"
started_after="$(multipass_exec_short "${VM_NAME}" -- sudo podman inspect "nakpanel-valkey-sub-${subscription_id}" --format '{{.State.StartedAt}}' | tr -d '\r')"
[[ "${started_before}" == "${started_after}" ]] || fail "idempotent Valkey convergence restarted the cache"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning get valkey-platform-idempotency | tr -d '\r')" == "retained" ]] || fail "idempotent Valkey convergence flushed cache data"
flush_output="$(multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning FLUSHALL 2>&1 || true)"
grep -Fq 'NOPERM' <<<"${flush_output}" || fail "dangerous Valkey command was not denied"
multipass_exec_short "${VM_NAME}" -- sudo podman inspect "nakpanel-valkey-sub-${subscription_id}" --format '{{.HostConfig.NetworkMode}}' | grep -Fqx none || fail "Valkey has a network namespace"
if multipass_exec_short "${VM_NAME}" -- sudo ss -ltnp | grep -E 'valkey|redis'; then
  fail "Valkey exposed a TCP listener"
fi
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/redis" -o "${tmpdir}/cache.html"
grep -Fq "${socket}" "${tmpdir}/cache.html" || fail "domain cache page does not show the subscription socket"
if grep -Fq "${credential}" "${tmpdir}/cache.html"; then fail "Valkey credential rendered after rotation"; fi

assert_valkey_boundary() {
  multipass_exec_short "${VM_NAME}" -- sudo bash -c '
set -euo pipefail
container="nakpanel-valkey-sub-$1"
pid=$(podman inspect "$container" --format "{{.State.Pid}}")
test "$pid" -gt 1
# Rootful engine, process demoted to the tenant UID and finite cgroup limits.
test "$(awk "/^Uid:/{print \$2}" /proc/"$pid"/status)" = "$(id -u "$2")"
cgroup=$(awk -F: "\$1==0 {print \$3}" /proc/"$pid"/cgroup)
# Cache maxmemory is64MiB; the existing runtime reserves32MiB extra inside
# the container for allocator overhead. Enforce both distinct budgets.
grep -Fxq "maxmemory 64mb" "/etc/nakpanel/valkey/sub-$1/valkey.conf"
test "$(cat /sys/fs/cgroup"$cgroup"/memory.max)" = 100663296
test "$(cat /sys/fs/cgroup"$cgroup"/pids.max)" = 64
read -r quota period </sys/fs/cgroup"$cgroup"/cpu.max
test "$quota" != max
test "$quota" -gt 0 && test "$((quota * 100 / period))" = 25
assert_private_valkey_paths() {
  if runuser -u nobody -- test -r "/etc/nakpanel/valkey/sub-$1/users.acl"; then echo "unrelated UID can read Valkey ACL" >&2; return 1; fi
  if runuser -u nobody -- test -r "/run/nakpanel/valkey/sub-$1/valkey.sock"; then echo "unrelated UID can access Valkey socket" >&2; return 1; fi
  return 0
}
assert_private_valkey_paths "$1"
' _ "${subscription_id}" "${username}"
}
assert_valkey_boundary
multipass restart "${VM_NAME}"
wait_for_cloud_init "${VM_NAME}"
assert_current_vm_identity
# Observe restart policy and finite limits without requesting reconciliation.
multipass_exec_short "${VM_NAME}" -- sudo systemctl is-active --quiet "nakpanel-valkey@${subscription_id}.service"
assert_valkey_boundary
assert_valkey_traversal
multipass_exec_short "${VM_NAME}" -- sudo -u "${username}" redis-cli -s "${socket}" --user app --pass "${credential}" --no-auth-warning ping | grep -Fq PONG
VM_IP="$(vm_ip)"
curl -skfL -c "${tmpdir}/admin.cookies" -d email=admin@nakpanel.test -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"
curl -skf -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" -d desired_state=disabled -d memory_mb=64 -d max_clients=32 -d cpu_percent=25 -d process_limit=64 -d idle_timeout_seconds=300 "https://${VM_IP}:7443/subscriptions/${subscription_id}/valkey" >/dev/null
wait_for "SELECT convergence_status FROM valkey_instances WHERE subscription_id=${subscription_id}" in_sync
multipass_exec_short "${VM_NAME}" -- sudo bash -c 'set -e; ! podman container exists "nakpanel-valkey-sub-$1"; test ! -S "/run/nakpanel/valkey/sub-$1/valkey.sock"' _ "${subscription_id}"
echo "Native rootful subscription Valkey cache verification passed for ${VM_NAME} (${VM_IP})."
