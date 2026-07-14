#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase18-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
fail() { echo "phase19: $*" >&2; exit 1; }
db_value() {
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}
wait_for_value() {
  local query="$1" expected="$2" value=""
  for _ in $(seq 1 90); do
    value="$(db_value "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  fail "got ${value}, want ${expected}: ${query}"
}

for _ in $(seq 1 60); do
  curl -skf -o /dev/null "https://${VM_IP}:7443/login" && break
  sleep 2
done
curl -skf -o /dev/null "https://${VM_IP}:7443/login" || fail "panel is not reachable"
curl -sk --fail -c "${tmpdir}/admin.cookies" -L -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"

domain="phase15-account.test"
subscription_id="$(db_value "SELECT subscription_id FROM sites WHERE domain='${domain}'")"
site_id="$(db_value "SELECT id FROM sites WHERE domain='${domain}'")"
mail_domain_id="$(db_value "SELECT id FROM mail_domains WHERE domain='${domain}' AND NOT delete_requested")"
[[ -n "${subscription_id}" && -n "${site_id}" && -n "${mail_domain_id}" ]] || fail "Phase 18 mail fixture is missing"
# Reused labs may predate the Phase 18 policy-preservation fix. Normalize the
# effective snapshot so the UI and the backend entitlement gate agree.
multipass exec "${VM_NAME}" -- bash -c "sudo -u postgres psql -qd nakpanel -c \"UPDATE subscription_entitlements SET max_mailboxes=2, hosting_policy=jsonb_set(jsonb_set(jsonb_set(('{\\\"resources\\\":{},\\\"permissions\\\":{},\\\"mail\\\":{}}'::jsonb || COALESCE(hosting_policy,'{}'::jsonb)),'{resources,max_mailboxes}','2'::jsonb,true),'{permissions,mail}','true'::jsonb,true),'{mail}',COALESCE(hosting_policy->'mail','{}'::jsonb) || '{\\\"enabled\\\":true,\\\"webmail\\\":true}'::jsonb,true) WHERE subscription_id=${subscription_id}\"" >/dev/null

curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/sites/${site_id}?tab=mail" -o "${tmpdir}/mail.html"
for marker in '>Mail<' 'Mailboxes' "Mail for ${domain}" 'data-np-generate-password' 'name="site_id"' 'value="site-mail"' 'Reconfigure webmail'; do
  grep -Fq "${marker}" "${tmpdir}/mail.html" || fail "mail workspace is missing ${marker}"
done
sidebar="$(sed -n '/class="np-routed-side"/,/<\/aside>/p' "${tmpdir}/mail.html")"
grep -Fq 'href="/sites"' <<<"${sidebar}" || fail "provider sidebar is missing Domains"
if grep -Fq 'href="/mail"' <<<"${sidebar}"; then
  fail "provider sidebar still exposes Mail"
fi
if grep -Eq 'password_hash|smarthost_password" value="[^" ]+' "${tmpdir}/mail.html"; then
  fail "mail workspace rendered a secret"
fi
for legacy_path in mail email; do
  redirect="$(curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/${legacy_path}?domain_id=${mail_domain_id}")"
  [[ "${redirect}" == "303 https://${VM_IP}:7443/sites/${site_id}?tab=mail" ]] || fail "/${legacy_path} redirect was ${redirect}"
done

# Create a mailbox through the same routed UI form. Phase 18 leaves one slot
# after deleting bob, so this also exercises the live entitlement gate.
multipass exec "${VM_NAME}" -- sudo -u postgres psql -qd nakpanel -c "DELETE FROM mailboxes USING mail_domains WHERE mailboxes.mail_domain_id=mail_domains.id AND mail_domains.domain='${domain}' AND mailboxes.local_part='phase19-ui'" >/dev/null
curl -sk -o /dev/null -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d 'return_to=site-mail' -d "site_id=${site_id}" -d "mail_domain_id=${mail_domain_id}" -d 'local_part=phase19-ui' \
  --data-urlencode 'password=Phase19-Mailbox!2026' -d 'quota_mb=256' -d 'enabled=true' \
  "https://${VM_IP}:7443/subscriptions/${subscription_id}/mailboxes"
wait_for_value "SELECT COUNT(*) FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.domain='${domain}' AND mb.local_part='phase19-ui'" '1'
[[ "$(db_value "SELECT password_hash LIKE '\$argon2id\$%' FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.domain='${domain}' AND mb.local_part='phase19-ui'")" == "t" ]] || fail "UI mailbox password was not hashed"
[[ "$(db_value "SELECT COUNT(*) FROM audit_events WHERE metadata::text LIKE '%Phase19-Mailbox!2026%'")" == "0" ]] || fail "mailbox password leaked into audit metadata"

# Client workspace remains tenant-scoped and retains Plesk-style aggregate
# Mail navigation even when its own subscription does not grant mail.
curl -sk --fail -c "${tmpdir}/client.cookies" -L -d 'email=client@nakpanel.test' -d 'password=NakpanelClient!2026' "https://${VM_IP}:7443/login" >/dev/null
curl -sk --fail -b "${tmpdir}/client.cookies" "https://${VM_IP}:7443/mail" -o "${tmpdir}/client-mail.html"
grep -Fq '>Mail<' "${tmpdir}/client-mail.html" || fail "client sidebar does not expose Mail"
if grep -Fq "phase19-ui@${domain}" "${tmpdir}/client-mail.html"; then
  fail "client can see another customer's mailbox"
fi

# Admin-only status and settings, including blank-password preservation and
# explicit relay clearing. The secret is inserted only to prove it never
# needs to round-trip through HTML.
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/mail/status" -o "${tmpdir}/mail-status.json"
grep -Fq '"state":"active"' "${tmpdir}/mail-status.json" || fail "Stalwart is not active in /mail/status"
grep -Fq '"listeners"' "${tmpdir}/mail-status.json" || fail "mail status has no listener summary"
multipass exec "${VM_NAME}" -- sudo -u postgres psql -qd nakpanel -c "UPDATE mail_settings SET smarthost_password='phase19-preserve-secret'" >/dev/null
mail_host="$(db_value 'SELECT mail_hostname FROM mail_settings WHERE id')"
relay_host="$(db_value 'SELECT smarthost_host FROM mail_settings WHERE id')"
relay_port="$(db_value 'SELECT smarthost_port FROM mail_settings WHERE id')"
relay_user="$(db_value 'SELECT smarthost_username FROM mail_settings WHERE id')"
rate_limit="$(db_value 'SELECT outbound_rate_limit FROM mail_settings WHERE id')"
threshold="$(db_value 'SELECT queue_alert_threshold FROM mail_settings WHERE id')"
curl -sk -o /dev/null -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "mail_hostname=${mail_host}" -d "smarthost_host=${relay_host}" -d "smarthost_port=${relay_port}" \
  -d "smarthost_username=${relay_user}" -d 'smarthost_password=' -d "outbound_rate_limit=${rate_limit}" \
  -d "queue_alert_threshold=${threshold}" "https://${VM_IP}:7443/settings/mail"
[[ "$(db_value "SELECT smarthost_password FROM mail_settings WHERE id")" == 'phase19-preserve-secret' ]] || fail "blank relay password did not preserve the current credential"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/tools-settings" -o "${tmpdir}/settings.html"
if grep -Fq 'phase19-preserve-secret' "${tmpdir}/settings.html"; then
  fail "relay password rendered in Tools & Settings"
fi
curl -sk -o /dev/null -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "mail_hostname=${mail_host}" -d 'clear_smarthost=true' -d "outbound_rate_limit=${rate_limit}" \
  -d "queue_alert_threshold=${threshold}" "https://${VM_IP}:7443/settings/mail"
[[ -z "$(db_value 'SELECT smarthost_password FROM mail_settings WHERE id')" ]] || fail "Clear relay retained the relay credential"

multipass exec "${VM_NAME}" -- sudo systemctl is-active --quiet stalwart-mail.service || fail "Stalwart is not healthy"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
go test ./internal/control/http ./internal/control/provision ./internal/control/workspace ./internal/agent/ops ./internal/agent/rpc -count=1
REMOTE

echo "Phase 19 first-class Mail workspace verification passed for ${VM_NAME} (${VM_IP})."
