#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; echo "phase24 verifier failed at line ${LINENO}: ${BASH_COMMAND}" >&2; exit "${status}"' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase23-verify.sh"
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
fail(){ echo "phase24: $*" >&2; exit 1; }
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){ local query="$1" expected="$2" value=""; for _ in $(seq 1 90); do value="$(db "${query}")"; [[ "${value}" == "${expected}" ]] && return 0; sleep 2; done; fail "got ${value}, want ${expected}: ${query}"; }
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
subscription_id="$(db "SELECT subscription_id FROM sites WHERE id=${site_id}")"
domain="$(db "SELECT domain FROM sites WHERE id=${site_id}")"
username="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${subscription_id}")"
db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(jsonb_set(COALESCE(hosting_policy,'{}'::jsonb),'{permissions,git}','true'::jsonb,true),'{permissions,staging}','true'::jsonb,true),'{permissions,applications}','true'::jsonb,true) WHERE subscription_id=${subscription_id}" >/dev/null

curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "subscription_id=${subscription_id}" -d 'mode=hosted' -d 'branch=main' -d 'deploy_target=.' -d 'automatic=true' \
  "https://${VM_IP}:7443/sites/${site_id}/git" -o /dev/null
wait_for "SELECT convergence_status FROM git_repositories WHERE site_id=${site_id}" "in_sync"
multipass_exec_short "${VM_NAME}" -- sudo test -f "/var/lib/nakpanel/git/site-${site_id}/repository.git/HEAD" || fail "hosted Git repository was not created"
multipass exec "${VM_NAME}" -- sudo -u "${username}" env SITE_ID="${site_id}" bash -se <<'REMOTE'
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
git -C "${work}" init -q
git -C "${work}" config user.name "Nakpanel verifier"
git -C "${work}" config user.email "verifier@nakpanel.test"
printf 'phase24 deployed\n' >"${work}/phase24.txt"
git -C "${work}" add phase24.txt
git -C "${work}" commit -qm 'phase24 verifier commit'
git -C "${work}" branch -M main
git -C "${work}" remote add origin "/var/lib/nakpanel/git/site-${SITE_ID}/repository.git"
git -C "${work}" push -q --force origin main
REMOTE
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" -d "subscription_id=${subscription_id}" \
  "https://${VM_IP}:7443/sites/${site_id}/git/deploy" -o /dev/null
wait_for "SELECT status FROM git_deployments ORDER BY id DESC LIMIT 1" "succeeded"
multipass_exec_short "${VM_NAME}" -- sudo test -f "/home/${username}/domains/${domain}/public_html/phase24.txt" || fail "hosted Git commit was not deployed"
multipass exec "${VM_NAME}" -- sudo -u "${username}" env SITE_ID="${site_id}" bash -se <<'REMOTE'
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
git -C "${work}" clone -q "/var/lib/nakpanel/git/site-${SITE_ID}/repository.git" .
git -C "${work}" config user.name "Nakpanel verifier"
git -C "${work}" config user.email "verifier@nakpanel.test"
git -C "${work}" rm -q phase24.txt
printf 'phase24 replacement\n' >"${work}/phase24-next.txt"
git -C "${work}" add phase24-next.txt
git -C "${work}" commit -qm 'verify deleted paths are removed'
git -C "${work}" push -q origin main
REMOTE
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" -d "subscription_id=${subscription_id}" \
  "https://${VM_IP}:7443/sites/${site_id}/git/deploy" -o /dev/null
wait_for "SELECT status FROM git_deployments ORDER BY id DESC LIMIT 1" "succeeded"
multipass_exec_short "${VM_NAME}" -- sudo test ! -e "/home/${username}/domains/${domain}/public_html/phase24.txt" || fail "Git deployment retained a file deleted by the next revision"
multipass_exec_short "${VM_NAME}" -- sudo test -f "/home/${username}/domains/${domain}/public_html/phase24-next.txt" || fail "second hosted Git revision was not deployed"
curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" -d "subscription_id=${subscription_id}" \
  "https://${VM_IP}:7443/sites/${site_id}/git/webhook" -o "${tmpdir}/webhook.html"
grep -Eq "/git/hooks/${site_id}/[a-f0-9]{64}" "${tmpdir}/webhook.html" || fail "one-time webhook URL was not returned"

curl -sk --fail -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "site_id=${site_id}" -d 'path=private' -d 'realm=Phase 24 private' -d 'username=phase24' \
  --data-urlencode 'password=Phase24-Protected!2026' -d 'enabled=true' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/protected-directories" -o /dev/null
wait_for "SELECT convergence_status FROM subscription_system_accounts WHERE subscription_id=${subscription_id}" "in_sync"
multipass_exec_short "${VM_NAME}" -- sudo grep -Fq 'auth_basic "Phase 24 private"' "/etc/nginx/nakpanel/protected/site-${site_id}/locations.conf" || fail "protected directory was not rendered"
[[ "$(db "SELECT password_hash LIKE '\$2%' FROM protected_directories WHERE site_id=${site_id} AND relative_path='private'")" == "t" ]] || fail "protected-directory password was not bcrypt-hashed"
[[ "$(db "SELECT COUNT(*) FROM audit_events WHERE metadata::text LIKE '%Phase24-Protected!2026%'")" == "0" ]] || fail "protected-directory password leaked into audit metadata"

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/applications" -o "${tmpdir}/applications.html"
# Phase 30 promotes this compatibility URL to the PHP Application workspace.
# The later verifier exercises both Classic and Managed behavior in depth; this
# earlier phase only proves that its route survives the full verifier chain.
for marker in 'PHP Application' 'Classic Hosting' 'Managed Deployment'; do
  grep -Fq "${marker}" "${tmpdir}/applications.html" || fail "PHP application workspace is missing ${marker}"
done
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}/staging" -o "${tmpdir}/staging.html"
grep -Eq 'automatic rollback point|Create a second domain' "${tmpdir}/staging.html" || fail "staging workflow is missing"

echo "Phase 24 Git, applications, protected directories, and staging verification passed for ${VM_NAME} (${VM_IP})."
