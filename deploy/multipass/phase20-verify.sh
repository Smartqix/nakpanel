#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase19-verify.sh"
fi

sync_repo "${ROOT_DIR}"
VM_IP="$(vm_ip)"
multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
cd /tmp/nakpanel-src
make build
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panelctl /usr/local/bin/panelctl
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo mkdir -p /etc/systemd/system/nakpanel.service.d
sudo tee /etc/systemd/system/nakpanel.service.d/phase20.conf >/dev/null <<EOF
[Service]
Environment=NAKPANEL_PUBLIC_URL=https://${VM_IP}:7443
Environment=NAKPANEL_BILLING_WEBHOOK_URL=http://127.0.0.1:18080/hook
Environment=NAKPANEL_BILLING_WEBHOOK_SECRET=phase20-webhook-secret
EOF
sudo pkill -f webhook_sink.py 2>/dev/null || true
sudo rm -f /tmp/phase20-webhooks.jsonl
sudo -u nakpanel env WEBHOOK_SINK_SECRET=phase20-webhook-secret WEBHOOK_SINK_OUTPUT=/tmp/phase20-webhooks.jsonl \
  nohup python3 /tmp/nakpanel-src/deploy/multipass/webhook_sink.py >/tmp/phase20-webhook-sink.log 2>&1 &
sudo systemctl daemon-reload
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
fail(){ echo "phase20: $*" >&2; exit 1; }
db(){ multipass exec "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
cli(){ multipass exec "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' panelctl --actor phase20-verifier "$@"; }
api(){ curl -skS -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' "$@"; }

for _ in $(seq 1 90); do curl -skf "https://${VM_IP}:7443/login" >/dev/null && break; sleep 2; done
curl -skf "https://${VM_IP}:7443/login" >/dev/null || fail "panel is not reachable"

key_output="$(cli api-key create --name phase20-verifier --cidrs '192.168.252.0/24,127.0.0.0/8' --rate-limit 120)"
API_KEY="$(printf '%s\n' "${key_output}" | grep '^npk_' | tail -1)"
[[ "${API_KEY}" == npk_* ]] || fail "panelctl did not display the API key once"
prefix="$(printf '%s' "${API_KEY}" | cut -d_ -f2)"
[[ "$(db "SELECT count(*) FROM api_keys WHERE key_prefix='${prefix}' AND encode(key_hash,'hex') NOT LIKE '%'||encode(convert_to('${API_KEY}','UTF8'),'hex')||'%'")" == 1 ]] || fail "raw key storage check failed"

headers="$(curl -skD - -o "${tmpdir}/cookie-only.json" -b 'nakpanel_session=fake' "https://${VM_IP}:7443/api/v1/ping")"
grep -q ' 401 ' <<<"${headers}" || fail "cookie-only API request was not 401"
! grep -qi '^Set-Cookie:' <<<"${headers}" || fail "API emitted a session cookie"

api "https://${VM_IP}:7443/api/v1/ping" -o "${tmpdir}/ping.json"
grep -Fq '"api_version":"v1"' "${tmpdir}/ping.json" || fail "ping contract failed"
api "https://${VM_IP}:7443/api/v1/providers" -o "${tmpdir}/providers.json"
grep -Fq '"ref":"admin"' "${tmpdir}/providers.json" || fail "admin provider is missing"
api "https://${VM_IP}:7443/api/v1/plans?provider=admin" -o "${tmpdir}/plans.json"
PLAN_SLUG="$(db "SELECT api_slug FROM plans WHERE reseller_id IS NULL AND is_active ORDER BY id LIMIT 1")"
[[ -n "${PLAN_SLUG}" ]] || fail "no active admin plan"

stamp="$(date +%s)"
external_ref="phase20-${stamp}"
domain="${external_ref}.test"
body="{\"external_ref\":\"${external_ref}\",\"provider\":\"admin\",\"plan\":\"${PLAN_SLUG}\",\"email\":\"${external_ref}@example.test\",\"name\":\"Phase 20 ${stamp}\",\"domain\":\"${domain}\"}"
status="$(api -o "${tmpdir}/created.json" -w '%{http_code}' -H 'Idempotency-Key: create-one' -d "${body}" "https://${VM_IP}:7443/api/v1/accounts")"
[[ "${status}" == 202 ]] || fail "account create returned ${status}: $(cat "${tmpdir}/created.json")"
account_id="$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "${tmpdir}/created.json")"
[[ "${account_id}" == acc_* ]] || fail "public account id is missing"
status="$(api -o "${tmpdir}/replay.json" -w '%{http_code}' -H 'Idempotency-Key: create-one' -d "${body}" "https://${VM_IP}:7443/api/v1/accounts")"
[[ "${status}" == 202 ]] || fail "idempotent replay returned ${status}"
grep -Eq "\"id\"[[:space:]]*:[[:space:]]*\"${account_id}\"" "${tmpdir}/replay.json" || fail "idempotent replay changed the account identity"
status="$(api -o "${tmpdir}/duplicate.json" -w '%{http_code}' -d "${body}" "https://${VM_IP}:7443/api/v1/accounts")"
[[ "${status}" == 200 ]] || fail "external_ref retry returned ${status}"
[[ "$(db "SELECT count(*) FROM billing_accounts WHERE external_ref='${external_ref}'")" == 1 ]] || fail "duplicate billing account was created"

api "https://${VM_IP}:7443/api/v1/accounts/${account_id}" -o "${tmpdir}/account.json"
grep -Fq '"lifecycle":"active"' "${tmpdir}/account.json" || fail "account lifecycle response failed"
for _ in $(seq 1 90); do
  [[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${account_id}'")" == active ]] && break
  sleep 2
done
[[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${account_id}'")" == active ]] || fail "account did not finish provisioning"
for command in suspend unsuspend; do
  api -X POST -d '{}' "https://${VM_IP}:7443/api/v1/accounts/${account_id}/${command}" -o "${tmpdir}/${command}.json"
done
status="$(api -X POST -d "{\"plan\":\"${PLAN_SLUG}\"}" "https://${VM_IP}:7443/api/v1/accounts/${account_id}/change-plan" -o "${tmpdir}/change-plan.json" -w '%{http_code}')"
[[ "${status}" == 202 ]] || fail "same-plan idempotent change returned ${status}: $(cat "${tmpdir}/change-plan.json")"

api -X POST -d '{}' "https://${VM_IP}:7443/api/v1/accounts/${account_id}/login-link" -o "${tmpdir}/login-link.json"
login_url="$(sed -n 's/.*"url":"\([^"]*\)".*/\1/p' "${tmpdir}/login-link.json" | sed 's#\\u0026#\&#g')"
[[ "${login_url}" == "https://${VM_IP}:7443/sso/customer/"* ]] || fail "login URL did not use NAKPANEL_PUBLIC_URL"
curl -skD "${tmpdir}/sso.headers" -o /dev/null "${login_url}"
grep -qi '^Set-Cookie: nakpanel_session=' "${tmpdir}/sso.headers" || fail "SSO exchange did not create a session"
[[ "$(curl -sk -o /dev/null -w '%{http_code}' "${login_url}")" == 404 ]] || fail "SSO token was reusable"

api -X DELETE "https://${VM_IP}:7443/api/v1/accounts/${account_id}" -o "${tmpdir}/cancel.json"
grep -Fq '"lifecycle":"cancelled"' "${tmpdir}/cancel.json" || fail "soft cancellation failed"
api -X POST -d '{}' "https://${VM_IP}:7443/api/v1/accounts/${account_id}/unsuspend" -o "${tmpdir}/recover.json"
grep -Fq '"lifecycle":"active"' "${tmpdir}/recover.json" || fail "soft cancellation recovery failed"

[[ "$(db "SELECT count(*) FROM audit_events WHERE action='api.request' AND actor_label LIKE 'api-key:phase20-verifier:%'")" -ge 10 ]] || fail "authenticated API calls were not audited"
[[ "$(db "SELECT count(*) FROM river_job WHERE queue IN ('default','heavy','webhooks')")" -ge 1 ]] || fail "Phase 20 queue fanout is missing"

status="$(api -X DELETE "https://${VM_IP}:7443/api/v1/accounts/${account_id}?purge=true" -o "${tmpdir}/purge.json" -w '%{http_code}')"
[[ "${status}" == 202 ]] || fail "explicit purge returned ${status}: $(cat "${tmpdir}/purge.json")"
for _ in $(seq 1 90); do
  [[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${account_id}'")" == terminated ]] && break
  sleep 2
done
[[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${account_id}'")" == terminated ]] || fail "teardown did not terminate"
[[ "$(db "SELECT count(*) FROM billing_accounts b JOIN subscriptions s ON s.id=b.subscription_id WHERE b.public_id='${account_id}' AND s.status='cancelled'")" == 1 ]] || fail "purge removed the billing/subscription tombstone"
[[ "$(db "SELECT count(*) FROM sites WHERE subscription_id=(SELECT subscription_id FROM billing_accounts WHERE public_id='${account_id}')")" == 0 ]] || fail "purge retained hosted sites"

for _ in $(seq 1 90); do
  multipass exec "${VM_NAME}" -- test -s /tmp/phase20-webhooks.jsonl && break
  sleep 2
done
multipass exec "${VM_NAME}" -- grep -Fq '"valid":true' /tmp/phase20-webhooks.jsonl || fail "webhook signature or delivery failed"
multipass exec "${VM_NAME}" -- grep -F "\"event\":\"account.provisioned\"" /tmp/phase20-webhooks.jsonl | grep -Fq "${account_id}" || fail "account.provisioned webhook was not delivered for the current account"
multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
sudo pkill -f webhook_sink.py 2>/dev/null || true
sudo tee /etc/systemd/system/nakpanel.service.d/phase20.conf >/dev/null <<EOF
[Service]
Environment=NAKPANEL_PUBLIC_URL=https://${VM_IP}:7443
EOF
sudo systemctl daemon-reload
sudo systemctl restart nakpanel.service
REMOTE

echo "Phase 20 provisioning API verification passed for ${VM_NAME} (${VM_IP}); account ${account_id}."
