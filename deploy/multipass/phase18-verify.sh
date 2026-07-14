#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase17-verify.sh"
fi

sync_repo "${ROOT_DIR}"
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
make build
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0755 bin/panelctl /usr/local/bin/panelctl
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo bash deploy/install/phase18-install.sh
sudo apt-get install -y dnsutils >/dev/null
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

# multipass 1.16 on macOS occasionally keeps spinning after the remote
# command has finished; give every short exec a watchdog and retry on hang.
mp_exec() {
  local budget="${MP_TIMEOUT:-120}"
  local attempt pid waited output_dir status
  for attempt in 1 2 3; do
    output_dir="$(mktemp -d "${TMPDIR:-/tmp}/nakpanel-mp.XXXXXX")"
    multipass exec "$@" >"${output_dir}/stdout" 2>"${output_dir}/stderr" &
    pid=$!
    waited=0
    while kill -0 "${pid}" 2>/dev/null && [[ "${waited}" -lt "${budget}" ]]; do
      sleep 1
      waited=$((waited + 1))
    done
    if kill -0 "${pid}" 2>/dev/null; then
      kill -9 "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
      cat "${output_dir}/stdout" || true
      cat "${output_dir}/stderr" >&2 || true
      rm -rf "${output_dir}"
      echo "multipass exec watchdog fired (attempt ${attempt}): $*" >&2
      continue
    fi
    if wait "${pid}"; then
      status=0
    else
      status=$?
    fi
    # Multipass has fully exited before output reaches a consumer such as
    # grep -q, so an early-closing pipe cannot strand the exec process.
    cat "${output_dir}/stdout" || true
    cat "${output_dir}/stderr" >&2 || true
    rm -rf "${output_dir}"
    return "${status}"
  done
  echo "multipass exec kept hanging: $*" >&2
  return 124
}
db_value() {
  mp_exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}
cli() {
  mp_exec "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
    NAKPANEL_AGENT_SOCKET='/run/nakpanel/agent.sock' panelctl --actor phase18-verifier "$@"
}
wait_for_value() {
  local query="$1" expected="$2" value=""
  for _ in $(seq 1 120); do
    value="$(db_value "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  echo "got ${value}, want ${expected}: ${query}" >&2
  exit 1
}
vm() { mp_exec "${VM_NAME}" -- bash -c "$1"; }
# The host may run bash 3.2, where a failing bare [[ ]] does not trip set -e;
# every assertion must fail explicitly.
fail() { echo "phase18: $*" >&2; exit 1; }

VM_IP="$(vm_ip)"
DOMAIN="phase15-account.test"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

# Reset any mail state a previous run left behind so the flow below always
# starts from "mail never enabled" intent.
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
pkill -f smtpsink >/dev/null 2>&1 || true
sudo systemctl stop stalwart-mail.service 2>/dev/null || true
sudo rm -rf /var/lib/stalwart/data
sudo -u postgres psql -qd nakpanel <<'SQL'
DELETE FROM mail_aliases;
DELETE FROM mailboxes;
DELETE FROM mail_domains;
DELETE FROM notifications WHERE kind='mail_outbound_spike';
UPDATE mail_settings SET mail_hostname='', smarthost_host='', smarthost_port=587,
  smarthost_username='', smarthost_password='', outbound_rate_limit='200/1h', queue_alert_threshold=50;
DELETE FROM dns_records WHERE zone_id IN (SELECT id FROM dns_zones WHERE domain='phase15-account.test')
  AND ((record_type='MX' AND host='@') OR (record_type='A' AND host='mail')
    OR (record_type='TXT' AND host='@' AND value LIKE 'v=spf1%')
    OR (record_type='TXT' AND host='_dmarc') OR (record_type='TXT' AND host LIKE '%._domainkey'));
SQL
REMOTE

# --- Two-tenant isolation and max_mailboxes gate (the correctness core) ----
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
sudo -u postgres psql -qc "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='ubuntu') THEN CREATE ROLE ubuntu LOGIN SUPERUSER; END IF; END\$\$;"
sudo -u postgres psql -qc 'DROP DATABASE IF EXISTS nakpanel_phase18_test'
sudo -u postgres psql -qc 'CREATE DATABASE nakpanel_phase18_test OWNER ubuntu'
DB_DSN='postgres:///nakpanel_phase18_test?host=/var/run/postgresql&sslmode=disable' make goose-up >/dev/null
NAKPANEL_TEST_DATABASE_URL='postgres:///nakpanel_phase18_test?host=/var/run/postgresql&sslmode=disable' \
  go test ./internal/control/quota -run TestMailTenantIsolationTwoTenants -count=1 -v | tail -3
REMOTE

# --- Part A: domain enablement, DKIM, DNS records through the panel zone ---
SUBSCRIPTION_ID="$(db_value "SELECT subscription_id FROM sites WHERE domain='${DOMAIN}'")"
[[ -n "${SUBSCRIPTION_ID}" ]] || fail "no subscription hosts ${DOMAIN}"
# Give the subscription a mailbox entitlement of 2 (fail-closed gate below).
mp_exec "${VM_NAME}" -- bash -c "sudo -u postgres psql -qd nakpanel -c \"UPDATE subscription_entitlements SET max_mailboxes=2, hosting_policy=jsonb_set(jsonb_set(jsonb_set(('{\\\"resources\\\":{},\\\"permissions\\\":{},\\\"mail\\\":{}}'::jsonb || COALESCE(hosting_policy,'{}'::jsonb)),'{resources,max_mailboxes}','2'::jsonb,true),'{permissions,mail}','true'::jsonb,true),'{mail}',COALESCE(hosting_policy->'mail','{}'::jsonb) || '{\\\"enabled\\\":true,\\\"webmail\\\":true}'::jsonb,true) WHERE subscription_id=${SUBSCRIPTION_ID}\""

# Ensure the panel manages the domain's DNS zone.
panel_ready=0
for _ in $(seq 1 60); do
  if curl -skf -o /dev/null "https://${VM_IP}:7443/login"; then
    panel_ready=1
    break
  fi
  sleep 2
done
[[ "${panel_ready}" == "1" ]] || fail "panel did not come back on :7443"
curl -sk --fail -c "${tmpdir}/admin.cookies" -L -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
csrf="$(csrf_token "${tmpdir}/admin.cookies")"
zone_id="$(db_value "SELECT COALESCE((SELECT id FROM dns_zones WHERE domain='${DOMAIN}'),0)")"
if [[ "${zone_id}" == "0" ]]; then
  curl -sk -o /dev/null -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
    -d "domain=${DOMAIN}" -d "address=${VM_IP}" "https://${VM_IP}:7443/dns"
fi
wait_for_value "SELECT status FROM dns_zones WHERE domain='${DOMAIN}'" 'active'
serial_before="$(db_value "SELECT serial FROM dns_zones WHERE domain='${DOMAIN}'")"

cli mail enable "${DOMAIN}" --dmarc quarantine | grep -Fq 'Mail enabled'
wait_for_value "SELECT convergence_status FROM mail_domains WHERE domain='${DOMAIN}'" 'in_sync'
wait_for_value "SELECT status FROM dns_zones WHERE domain='${DOMAIN}'" 'active'
serial_after="$(db_value "SELECT serial FROM dns_zones WHERE domain='${DOMAIN}'")"
[[ "${serial_after}" -gt "${serial_before}" ]] || fail "zone serial did not bump on mail enablement (${serial_before} -> ${serial_after})"

vm "dig +short @127.0.0.1 MX ${DOMAIN}" | grep -Fq "10 mail.${DOMAIN}."
vm "dig +short @127.0.0.1 A mail.${DOMAIN}" | grep -Fq "${VM_IP}"
vm "dig +short @127.0.0.1 TXT ${DOMAIN}" | grep -Fq 'v=spf1 mx ~all'
vm "dig +short @127.0.0.1 TXT _dmarc.${DOMAIN}" | grep -Fq 'v=DMARC1; p=quarantine'
vm "dig +short @127.0.0.1 TXT nak1._domainkey.${DOMAIN}" | grep -Fq 'v=DKIM1'
vm "test \"\$(sudo stat -c '%U:%G:%a' /var/lib/nakpanel/dkim/${DOMAIN}/nak1.key)\" = root:root:600"
vm "sudo systemctl is-active stalwart-mail.service" | grep -qx active
vm "! sudo systemctl is-active --quiet apache2.service && ! sudo systemctl is-failed --quiet apache2.service"

# Re-running domain enablement is idempotent: no key churn, no config churn,
# no duplicate DNS records.
dkim_before="$(vm "sudo sha256sum /var/lib/nakpanel/dkim/${DOMAIN}/nak1.key" | awk '{print $1}')"
config_before="$(vm "sudo sha256sum /etc/stalwart/config.toml.nakpanel-intent" | awk '{print $1}')"
started_before="$(vm "sudo systemctl show -p ActiveEnterTimestamp stalwart-mail.service")"
records_before="$(db_value "SELECT COUNT(*) FROM dns_records WHERE zone_id=(SELECT id FROM dns_zones WHERE domain='${DOMAIN}')")"
cli mail enable "${DOMAIN}" --dmarc quarantine >/dev/null
wait_for_value "SELECT convergence_status FROM mail_domains WHERE domain='${DOMAIN}'" 'in_sync'
sleep 4
[[ "$(vm "sudo sha256sum /var/lib/nakpanel/dkim/${DOMAIN}/nak1.key" | awk '{print $1}')" == "${dkim_before}" ]] || fail "re-running mail enable rotated the DKIM key"
[[ "$(vm "sudo sha256sum /etc/stalwart/config.toml.nakpanel-intent" | awk '{print $1}')" == "${config_before}" ]] || fail "re-running mail enable churned the rendered stalwart intent"
[[ "$(vm "sudo systemctl show -p ActiveEnterTimestamp stalwart-mail.service")" == "${started_before}" ]] || fail "re-running mail enable restarted stalwart despite unchanged intent"
[[ "$(db_value "SELECT COUNT(*) FROM dns_records WHERE zone_id=(SELECT id FROM dns_zones WHERE domain='${DOMAIN}')")" == "${records_before}" ]] || fail "re-running mail enable changed the DNS record count"
[[ "$(db_value "SELECT COUNT(*) FROM (SELECT host,record_type,value FROM dns_records WHERE zone_id=(SELECT id FROM dns_zones WHERE domain='${DOMAIN}') GROUP BY 1,2,3 HAVING COUNT(*)>1) dup")" == "0" ]] || fail "duplicate managed DNS records"

# --- Part B: mailboxes, aliases, plan gate, SMTP submit + IMAP retrieve ----
alice_out="$(cli mail add "alice@${DOMAIN}")"
echo "${alice_out}" | grep -Fq 'Generated password:'
ALICE_PW="$(echo "${alice_out}" | sed -n 's/.*Generated password: //p' | tr -d '[:space:]')"
bob_out="$(cli mail add "bob@${DOMAIN}")"
BOB_PW="$(echo "${bob_out}" | sed -n 's/.*Generated password: //p' | tr -d '[:space:]')"
cli mail list "${DOMAIN}" | grep -Fq "alice@${DOMAIN}"
if cli mail add "carol@${DOMAIN}" >"${tmpdir}/carol.out" 2>&1; then
  echo 'mailbox over max_mailboxes was accepted' >&2
  exit 1
fi
grep -Fq 'quota exceeded' "${tmpdir}/carol.out"
cli mail alias add "sales@${DOMAIN}" --to "alice@${DOMAIN}" | grep -Fq 'saved'

# Send alice -> bob over authenticated submission, then read it back on IMAP.
vm "printf 'From: alice@${DOMAIN}\r\nTo: bob@${DOMAIN}\r\nSubject: phase18 direct\r\n\r\nhello bob\r\n' > /tmp/phase18-msg1.txt"
vm "curl -sS --url smtp://127.0.0.1:587 --ssl-reqd -k --mail-from alice@${DOMAIN} --mail-rcpt bob@${DOMAIN} -u 'alice@${DOMAIN}:${ALICE_PW}' -T /tmp/phase18-msg1.txt"
for _ in $(seq 1 60); do
  count="$(vm "curl -sk --url imaps://127.0.0.1:993 -u 'bob@${DOMAIN}:${BOB_PW}' -X 'STATUS INBOX (MESSAGES)'" | grep -o 'MESSAGES [0-9]*' | awk '{print $2}')"
  [[ "${count:-0}" -ge 1 ]] && break
  sleep 2
done
[[ "${count:-0}" -ge 1 ]] || fail "message did not arrive in bob inbox"
vm "curl -sk --url 'imaps://127.0.0.1:993/INBOX;MAILINDEX=1' -u 'bob@${DOMAIN}:${BOB_PW}'" > "${tmpdir}/bob-msg.txt"
grep -Fq 'hello bob' "${tmpdir}/bob-msg.txt"
grep -Fq 'DKIM-Signature' "${tmpdir}/bob-msg.txt"
grep -Fq "s=nak1" "${tmpdir}/bob-msg.txt"

# Alias delivery: mail to sales@ lands in alice's mailbox.
vm "printf 'From: bob@${DOMAIN}\r\nTo: sales@${DOMAIN}\r\nSubject: phase18 alias\r\n\r\nhello sales\r\n' > /tmp/phase18-msg2.txt"
vm "curl -sS --url smtp://127.0.0.1:587 --ssl-reqd -k --mail-from bob@${DOMAIN} --mail-rcpt sales@${DOMAIN} -u 'bob@${DOMAIN}:${BOB_PW}' -T /tmp/phase18-msg2.txt"
for _ in $(seq 1 60); do
  count="$(vm "curl -sk --url imaps://127.0.0.1:993 -u 'alice@${DOMAIN}:${ALICE_PW}' -X 'STATUS INBOX (MESSAGES)'" | grep -o 'MESSAGES [0-9]*' | awk '{print $2}')"
  [[ "${count:-0}" -ge 1 ]] && break
  sleep 2
done
[[ "${count:-0}" -ge 1 ]] || fail "alias message did not arrive in alice inbox"

# Passwords are stored as argon2id hashes, never plaintext, never in logs.
[[ "$(db_value "SELECT COUNT(*) FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.domain='${DOMAIN}' AND mb.password_hash NOT LIKE '\$argon2id\$%'")" == "0" ]] || fail "mailbox password stored without argon2id hash"
[[ "$(db_value "SELECT COUNT(*) FROM audit_events WHERE metadata::text LIKE '%${ALICE_PW}%'")" == "0" ]] || fail "mailbox password leaked into audit metadata"

# --- Part C: webmail (Roundcube against Stalwart IMAP/SMTP) ---------------
curl -sk -o /dev/null -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${csrf}" \
  -d "domain=${DOMAIN}" "https://${VM_IP}:7443/webmail"
wait_for_value "SELECT status FROM webmail_hosts WHERE hostname='webmail.${DOMAIN}'" 'active'
vm "sudo cat /etc/roundcube/config.inc.php" | grep -Fq "tls://127.0.0.1:143"
curl -s -c "${tmpdir}/rc.cookies" -H "Host: webmail.${DOMAIN}" "http://${VM_IP}/?_task=login" -o "${tmpdir}/rc-login.html"
grep -Fq 'name="_token"' "${tmpdir}/rc-login.html"
rc_token="$(grep -o 'name="_token" value="[^"]*"' "${tmpdir}/rc-login.html" | head -1 | sed 's/.*value="//;s/"$//')"
curl -s -D "${tmpdir}/rc-headers.txt" -o /dev/null -b "${tmpdir}/rc.cookies" -c "${tmpdir}/rc.cookies" \
  -H "Host: webmail.${DOMAIN}" \
  -d "_token=${rc_token}" -d "_task=login" -d "_action=login" -d "_timezone=UTC" -d "_url=" \
  -d "_user=alice@${DOMAIN}" -d "_pass=${ALICE_PW}" \
  "http://${VM_IP}/?_task=login"
grep -iq 'location: .*_task=mail' "${tmpdir}/rc-headers.txt"

# --- Deletion: the directory row is the account -----------------------------
cli mail del "bob@${DOMAIN}" --yes | grep -Fq 'deleted'
sleep 35 # let Stalwart's 30s directory cache expire
if vm "curl -sk --url imaps://127.0.0.1:993 -u 'bob@${DOMAIN}:${BOB_PW}' -X 'STATUS INBOX (MESSAGES)'" >/dev/null 2>&1; then
  echo 'deleted mailbox can still authenticate' >&2
  exit 1
fi
if vm "curl -sS --url smtp://127.0.0.1:587 --ssl-reqd -k --mail-from alice@${DOMAIN} --mail-rcpt bob@${DOMAIN} -u 'alice@${DOMAIN}:${ALICE_PW}' -T /tmp/phase18-msg1.txt" >/dev/null 2>&1; then
  echo 'stalwart still accepts mail for a deleted mailbox' >&2
  exit 1
fi

# --- Deliverability: smarthost routing, rate limit, spike alert ------------
cli mail relay set --host 127.0.0.1 --port 2525 | grep -Fq 'relays through'
cli mail settings --rate-limit 2/1h --alert-threshold 1 | grep -Fq 'updated'
# The running process has the new settings once (a) the rendered intent
# sidecar contains them and (b) stalwart was (re)started after that render.
stalwart_current() {
  vm "sudo grep -q 'remote.\"smarthost\"' /etc/stalwart/config.toml.nakpanel-intent" || return 1
  vm "sudo grep -Fq '\"2/1h\"' /etc/stalwart/config.toml.nakpanel-intent" || return 1
  vm "test \$(date -d \"\$(sudo systemctl show -p ActiveEnterTimestamp --value stalwart-mail.service)\" +%s) -ge \$(sudo stat -c %Y /etc/stalwart/config.toml.nakpanel-intent)" || return 1
  vm "sudo systemctl is-active stalwart-mail.service" | grep -qx active
}
for _ in $(seq 1 90); do
  stalwart_current && break
  sleep 2
done
stalwart_current || fail "stalwart did not restart with the smarthost and rate-limit config"
sleep 2
vm "rm -f /tmp/smtpsink.log && cd /tmp/nakpanel-src && (nohup go run ./deploy/multipass/smtpsink -addr 127.0.0.1:2525 -out /tmp/smtpsink.log >/tmp/smtpsink.out 2>&1 &) && sleep 3"
vm "printf 'From: alice@${DOMAIN}\r\nTo: ext@external-example.test\r\nSubject: relay\r\n\r\nvia smarthost\r\n' > /tmp/phase18-ext.txt"
for i in 1 2 3; do
  vm "curl -sS --url smtp://127.0.0.1:587 --ssl-reqd -k --mail-from alice@${DOMAIN} --mail-rcpt ext${i}@external-example.test -u 'alice@${DOMAIN}:${ALICE_PW}' -T /tmp/phase18-ext.txt"
done
sink_count=0
for _ in $(seq 1 45); do
  sink_count="$(vm "grep -c 'MAIL FROM' /tmp/smtpsink.log 2>/dev/null || true")"
  [[ "${sink_count:-0}" -ge 1 ]] && break
  sleep 2
done
{ [[ "${sink_count:-0}" -ge 1 && "${sink_count}" -le 2 ]] || fail "smarthost sink received ${sink_count} messages, want 1-2 (throttled)"; }
# The throttled remainder shows up as a spike alert after the queue sweep.
mp_exec "${VM_NAME}" -- sudo systemctl restart nakpanel.service
wait_for_value "SELECT COUNT(*)>0 FROM notifications WHERE kind='mail_outbound_spike' AND resolved_at IS NULL AND dedupe_key='mail-spike:${DOMAIN}'" 't'

# Operator docs cover the PTR/rDNS step the panel cannot automate.
grep -Fq 'PTR / reverse DNS' "${ROOT_DIR}/docs/MAIL.md"

[[ "$(db_value "SELECT COUNT(*) FROM audit_events WHERE actor_label='phase18-verifier'")" -ge 5 ]] || fail "expected at least 5 phase18-verifier audit events"

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
NAKPANEL_TEST_DATABASE_URL='postgres:///nakpanel_phase18_test?host=/var/run/postgresql&sslmode=disable' \
  go test ./internal/agent/ops ./internal/control/quota ./internal/control/provision ./internal/control/http ./internal/control/maintenance ./cmd/panelctl -count=1
REMOTE
echo "Phase 18 mail hosting verification passed for ${VM_NAME} (${VM_IP})."
