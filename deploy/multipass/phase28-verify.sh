#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase28 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

fail(){ echo "phase28: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){
  local query="$1" expected="$2" value=""
  for _ in $(seq 1 120); do
    value="$(db "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "got ${value}, want ${expected}: ${query}"
}

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${SCRIPT_DIR}/phase27-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
sudo deploy/install/phase21-25-install.sh
command -v podman newuidmap newgidmap slirp4netns >/dev/null
sudo test -x /usr/lib/nakpanel/slirp4netns
make build
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

VM_IP="$(vm_ip)"
BASE_URL="https://${VM_IP}:7443"
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
for _ in $(seq 1 60); do curl -skf "${BASE_URL}/healthz" >/dev/null && break; sleep 2; done
curl -skf "${BASE_URL}/healthz" >/dev/null
curl -sk --fail -c "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "${BASE_URL}/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"

site_id="$(db "SELECT site.id
FROM sites site
JOIN subscriptions subscription ON subscription.id=site.subscription_id AND subscription.status='active'
JOIN customers customer ON customer.id=subscription.customer_id AND customer.status='active'
WHERE site.desired_status='active'
ORDER BY site.id LIMIT 1")"
subscription_id="$(db "SELECT subscription_id FROM sites WHERE id=${site_id}")"
domain="$(db "SELECT domain FROM sites WHERE id=${site_id}")"
php_version="$(db "SELECT desired_php_version FROM sites WHERE id=${site_id}")"
username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")"
[[ "${site_id}" =~ ^[0-9]+$ && "${subscription_id}" =~ ^[0-9]+$ ]] || fail "site fixture is unavailable"

db "UPDATE subscription_entitlements SET hosting_policy=
jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(hosting_policy,
'{permissions,applications}','true'::jsonb,true),
'{permissions,custom_oci_images}','true'::jsonb,true),
'{permissions,application_egress}','false'::jsonb,true),
'{applications,allowed_runtimes}','[\"oci\"]'::jsonb,true),
'{applications,allowed_registries}','[\"docker.io\"]'::jsonb,true),
'{applications,rootless}','true'::jsonb,true),
'{resources,max_applications}','3'::jsonb,true)
WHERE subscription_id=${subscription_id}" >/dev/null

# Pre-cache one immutable test image in the subscription user's dedicated
# rootless store. Runtime deployment itself never pulls mutable or missing
# images, so registry availability cannot change a queued revision.
image_digest="$(multipass_exec_short "${VM_NAME}" -- skopeo inspect docker://docker.io/library/nginx:alpine | jq -r .Digest | tr -d '\r')"
image_ref="docker.io/library/nginx@${image_digest}"
multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${subscription_id}" "${image_ref}" <<'REMOTE'
set -euo pipefail
username="$1"; subscription_id="$2"; image_ref="$3"
uid="$(id -u "${username}")"
start="$((100000000 + uid * 65536))"
grep -q "^${username}:" /etc/subuid || usermod --add-subuids "${start}-$((start+65535))" "${username}"
grep -q "^${username}:" /etc/subgid || usermod --add-subgids "${start}-$((start+65535))" "${username}"
base="/var/lib/nakpanel/containers/sub-${subscription_id}"
runtime="/run/nakpanel-containers/sub-${subscription_id}"
install -d -o "${username}" -g "${username}" -m 0700 "${base}/home" "${base}/data" "${base}/config" "${runtime}"
cd /
runuser -u "${username}" -- env HOME="${base}/home" XDG_DATA_HOME="${base}/data" \
  XDG_CONFIG_HOME="${base}/config" XDG_RUNTIME_DIR="${runtime}" TMPDIR="${runtime}" podman pull "${image_ref}" >/dev/null
REMOTE

application_id="$(db "SELECT id FROM application_instances WHERE subscription_id=${subscription_id} AND name='phase28-test'")"
application_update_args=()
if [[ "${application_id}" =~ ^[0-9]+$ ]]; then
  application_update_args+=(--data-urlencode "resource_id=${application_id}")
fi
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  ${application_update_args[@]+"${application_update_args[@]}"} \
  --data-urlencode "site_id=${site_id}" --data-urlencode 'return_to=site-containers' \
  --data-urlencode 'name=phase28-test' --data-urlencode 'runtime=oci' \
  --data-urlencode "image_ref=${image_ref}" --data-urlencode 'desired_state=running' \
  --data-urlencode 'route_mode=prefix' --data-urlencode 'route_prefix=/phase28/' \
  --data-urlencode 'container_port=80' --data-urlencode 'health_kind=http' \
  --data-urlencode 'health_path=/' --data-urlencode 'health_timeout_seconds=30' \
  --data-urlencode 'environment={"PHASE":"28"}' --data-urlencode 'secrets={"TEST_PASSWORD":"phase28-secret"}' \
  "${BASE_URL}/subscriptions/${subscription_id}/applications" -o /dev/null

application_id="$(db "SELECT id FROM application_instances WHERE subscription_id=${subscription_id} AND name='phase28-test'")"
wait_for "SELECT convergence_status||':'||observed_state FROM application_instances WHERE id=${application_id}" "in_sync:healthy"
active_revision="$(db "SELECT active_generation FROM application_instances WHERE id=${application_id}")"
active_endpoint="$(db "SELECT endpoint_port FROM application_instances WHERE id=${application_id}")"
active_container="$(db "SELECT container_name FROM application_generations WHERE application_id=${application_id} AND desired_revision=${active_revision}")"
multipass_exec_short "${VM_NAME}" -- sudo grep -Fq \
  'network_cmd_path="/usr/lib/nakpanel/slirp4netns"' \
  "/var/lib/nakpanel/containers/sub-${subscription_id}/config/containers/containers.conf" ||
  fail "rootless Podman does not use the managed network compatibility command"

curl -s --fail --resolve "${domain}:80:${VM_IP}" "http://${domain}/phase28/" -o "${tmpdir}/application.html"
grep -Fq "Welcome to nginx" "${tmpdir}/application.html" || fail "container is not reachable through tenant nginx"
container_base="/var/lib/nakpanel/containers/sub-${subscription_id}"
container_runtime="/run/nakpanel-containers/sub-${subscription_id}"
port_bindings="$(multipass_exec_short "${VM_NAME}" -- sudo bash -c \
  'cd / && exec runuser -u "$1" -- env HOME="$2/home" XDG_DATA_HOME="$2/data" XDG_CONFIG_HOME="$2/config" XDG_RUNTIME_DIR="$3" podman inspect --format "{{json .HostConfig.PortBindings}}" "$4"' \
  _ "${username}" "${container_base}" "${container_runtime}" "${active_container}")"
grep -Fq '"HostIp":"127.0.0.1"' <<<"${port_bindings}" ||
  fail "Podman generation is not configured for a loopback-only endpoint: ${port_bindings}"
multipass_exec_short "${VM_NAME}" -- curl -sSf --connect-timeout 3 \
  "http://127.0.0.1:${active_endpoint}/" >/dev/null ||
  fail "container endpoint is not reachable on guest loopback"
if curl -sSf --connect-timeout 3 "http://${VM_IP}:${active_endpoint}/" >/dev/null 2>&1; then
  fail "container endpoint is reachable through the VM address"
fi
if multipass exec "${VM_NAME}" -- sudo bash -se -- "${username}" "${subscription_id}" "${active_container}" <<'REMOTE'
set -euo pipefail
cd /
username="$1"; subscription_id="$2"; container="$3"
base="/var/lib/nakpanel/containers/sub-${subscription_id}"
runtime="/run/nakpanel-containers/sub-${subscription_id}"
runuser -u "${username}" -- env HOME="${base}/home" XDG_DATA_HOME="${base}/data" \
  XDG_CONFIG_HOME="${base}/config" XDG_RUNTIME_DIR="${runtime}" \
  podman exec "${container}" sh -c 'wget -T 3 -qO- http://1.1.1.1 >/dev/null'
REMOTE
then
  fail "application egress is available despite the disabled entitlement"
fi
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%U' "/home/${username}" | tr -d '\r')" == "root" ]] || fail "subscription home is no longer root-owned"
multipass_exec_short "${VM_NAME}" -- sudo grep -Eq "^${username}:[0-9]+:65536$" /etc/subuid || fail "subordinate UID range is missing"
multipass_exec_short "${VM_NAME}" -- sudo grep -Eq "^${username}:[0-9]+:65536$" /etc/subgid || fail "subordinate GID range is missing"
secret_path="/var/lib/nakpanel/containers/sub-${subscription_id}/apps/${application_id}/generations/${active_revision}/secrets/TEST_PASSWORD"
secret_mode="$(multipass_exec_short "${VM_NAME}" -- sudo stat -c %a "${secret_path}" | tr -d '\r')"
[[ "${secret_mode}" == "600" ]] || fail "mounted secret is not mode 0600"
if db "SELECT args::text FROM river_job WHERE kind='converge_application' ORDER BY id DESC LIMIT 5" | grep -Fq 'phase28-secret'; then
  fail "application secret leaked into River arguments"
fi

# A bad readiness probe must leave the last-known-good route and generation.
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  --data-urlencode "resource_id=${application_id}" --data-urlencode "site_id=${site_id}" \
  --data-urlencode 'return_to=site-containers' --data-urlencode 'name=phase28-test' \
  --data-urlencode 'runtime=oci' --data-urlencode "image_ref=${image_ref}" \
  --data-urlencode 'desired_state=running' --data-urlencode 'route_mode=prefix' \
  --data-urlencode 'route_prefix=/phase28/' --data-urlencode 'container_port=80' \
  --data-urlencode 'health_kind=http' --data-urlencode 'health_path=/definitely-unhealthy' \
  --data-urlencode 'health_timeout_seconds=2' --data-urlencode 'environment={"PHASE":"28"}' \
  "${BASE_URL}/subscriptions/${subscription_id}/applications" -o /dev/null
wait_for "SELECT convergence_status FROM application_instances WHERE id=${application_id}" "failed"
failed_revision="$(db "SELECT desired_revision FROM application_instances WHERE id=${application_id}")"
[[ "$(db "SELECT active_generation FROM application_instances WHERE id=${application_id}")" == "${active_revision}" ]] || fail "unhealthy candidate replaced the active revision"
curl -s --fail --resolve "${domain}:80:${VM_IP}" "http://${domain}/phase28/" >/dev/null || fail "rollback did not preserve tenant traffic"
multipass_exec_short "${VM_NAME}" -- sudo test ! -e \
  "/var/lib/nakpanel/containers/sub-${subscription_id}/apps/${application_id}/generations/${failed_revision}" ||
  fail "failed candidate secret generation remains on disk"

# Restore a healthy desired revision, then prove reboot recovery.
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  --data-urlencode "resource_id=${application_id}" --data-urlencode "site_id=${site_id}" \
  --data-urlencode 'return_to=site-containers' --data-urlencode 'name=phase28-test' \
  --data-urlencode 'runtime=oci' --data-urlencode "image_ref=${image_ref}" \
  --data-urlencode 'desired_state=running' --data-urlencode 'route_mode=prefix' \
  --data-urlencode 'route_prefix=/phase28/' --data-urlencode 'container_port=80' \
  --data-urlencode 'health_kind=http' --data-urlencode 'health_path=/' \
  --data-urlencode 'health_timeout_seconds=30' --data-urlencode 'environment={"PHASE":"28"}' \
  "${BASE_URL}/subscriptions/${subscription_id}/applications" -o /dev/null
wait_for "SELECT convergence_status||':'||observed_state FROM application_instances WHERE id=${application_id}" "in_sync:healthy"
active_revision="$(db "SELECT active_generation FROM application_instances WHERE id=${application_id}")"
active_container="$(db "SELECT container_name FROM application_generations WHERE application_id=${application_id} AND desired_revision=${active_revision}")"
generation_count="$(multipass_exec_short "${VM_NAME}" -- sudo bash -c \
  'cd / && exec runuser -u "$1" -- env HOME="$2/home" XDG_DATA_HOME="$2/data" XDG_CONFIG_HOME="$2/config" XDG_RUNTIME_DIR="$3" podman ps -a --filter "label=io.nakpanel.application-id=$4" --format "{{.Names}}"' \
  _ "${username}" "${container_base}" "${container_runtime}" "${application_id}" | grep -c "^nakpanel-app-${application_id}-g")"
[[ "${generation_count}" == "1" ]] || fail "retired application containers remain after healthy rollout"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo find /etc/systemd/system -maxdepth 1 \
  -name "nakpanel-app-${application_id}-g*.service" | wc -l | tr -d '[:space:]')" == "1" ]] ||
  fail "retired application systemd units remain after healthy rollout"
[[ "$(multipass_exec_short "${VM_NAME}" -- sudo find \
  "/var/lib/nakpanel/containers/sub-${subscription_id}/apps/${application_id}/generations" \
  -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d '[:space:]')" == "1" ]] ||
  fail "retired application secret generations remain after healthy rollout"
multipass restart "${VM_NAME}"
wait_for_cloud_init
VM_IP="$(vm_ip)"
for _ in $(seq 1 90); do
  curl -s --fail --resolve "${domain}:80:${VM_IP}" "http://${domain}/phase28/" >/dev/null && break
  sleep 2
done
curl -s --fail --resolve "${domain}:80:${VM_IP}" "http://${domain}/phase28/" >/dev/null || fail "container did not recover after reboot"

# Site suspension stops the application generation; reactivation restores only
# the application whose own desired state remains running.
BASE_URL="https://${VM_IP}:7443"
for _ in $(seq 1 90); do
  curl -skf "${BASE_URL}/healthz" >/dev/null && break
  sleep 2
done
curl -skf "${BASE_URL}/healthz" >/dev/null || fail "panel did not recover after reboot"
curl -sk --fail -c "${tmpdir}/admin2.cookies" -L -d 'email=admin@nakpanel.test' \
  -d 'password=NakpanelAdmin!2026' "${BASE_URL}/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin2.cookies")"
curl -sk --fail -b "${tmpdir}/admin2.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "desired_status=suspended" -d "desired_php_version=${php_version}" \
  "${BASE_URL}/sites/${site_id}/hosting" -o /dev/null
wait_for "SELECT observed_state FROM application_instances WHERE id=${application_id}" "stopped"
curl -s --resolve "${domain}:80:${VM_IP}" -o /dev/null -w '%{http_code}' "http://${domain}/phase28/" | grep -Fq 503 || fail "suspended site did not return 503"
curl -sk --fail -b "${tmpdir}/admin2.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "desired_status=active" -d "desired_php_version=${php_version}" \
  "${BASE_URL}/sites/${site_id}/hosting" -o /dev/null
wait_for "SELECT convergence_status||':'||observed_state FROM application_instances WHERE id=${application_id}" "in_sync:healthy"
curl -s --fail --resolve "${domain}:80:${VM_IP}" "http://${domain}/phase28/" >/dev/null

curl -sk --fail -b "${tmpdir}/admin2.cookies" "${BASE_URL}/sites/${site_id}/applications" -o "${tmpdir}/applications.html"
grep -Fq "Managed runtimes are not installed yet" "${tmpdir}/applications.html" || fail "managed Applications page advertises unavailable runtimes"
if grep -Fq "Deploy application" "${tmpdir}/applications.html"; then fail "managed Applications page exposes a deploy action"; fi
curl -sk --fail -b "${tmpdir}/admin2.cookies" "${BASE_URL}/sites/${site_id}/containers" -o "${tmpdir}/containers.html"
for marker in "Deploy container" "Digest-pinned OCI workloads" "Secret values (write-only JSON)" \
  "Volume size (MB)" "Subscription container limits"; do
  grep -Fq "${marker}" "${tmpdir}/containers.html" || fail "Containers workspace is missing ${marker}"
done
curl -sk --fail -b "${tmpdir}/admin2.cookies" \
  "${BASE_URL}/sites/${site_id}/containers/${application_id}" -o "${tmpdir}/container-detail.html"
for marker in "Runtime overview" "data-np-container-logs" "Remove"; do
  grep -Fq "${marker}" "${tmpdir}/container-detail.html" || fail "Container detail is missing ${marker}"
done
curl -sk --fail -b "${tmpdir}/admin2.cookies" \
  "${BASE_URL}/sites/${site_id}/containers/${application_id}/logs?lines=20&bytes=4096" \
  -o "${tmpdir}/container-logs.json"
jq -e '.lines | type == "array"' "${tmpdir}/container-logs.json" >/dev/null ||
  fail "bounded container logs endpoint is unavailable"
curl -sk --fail -b "${tmpdir}/admin2.cookies" "${BASE_URL}/tools-settings/application-catalog" -o "${tmpdir}/catalog.html"
grep -Fq "Provider Application Catalog" "${tmpdir}/catalog.html" || fail "provider catalog workspace is missing"

curl -sk --fail -b "${tmpdir}/admin2.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "site_id=${site_id}" -d "return_to=site-containers" \
  "${BASE_URL}/subscriptions/${subscription_id}/services/application/${application_id}/delete" -o /dev/null
wait_for "SELECT count(*) FROM application_instances WHERE id=${application_id}" "0"
multipass_exec_short "${VM_NAME}" -- sudo test ! -e "/var/lib/nakpanel/containers/sub-${subscription_id}/apps/${application_id}" ||
  fail "removed application storage remains on disk"
if multipass_exec_short "${VM_NAME}" -- sudo find /etc/systemd/system -maxdepth 1 \
  -name "nakpanel-app-${application_id}-g*.service" -print -quit | grep -q .; then
  fail "removed application systemd generation remains installed"
fi
curl -s --resolve "${domain}:80:${VM_IP}" "http://${domain}/phase28/" -o "${tmpdir}/removed-route.html"
if grep -Fq "Welcome to nginx" "${tmpdir}/removed-route.html"; then
  fail "removed application route still serves the former container"
fi

echo "Phase 28 operational application runtime verification passed on ${VM_NAME} (${VM_IP})."
