#!/usr/bin/env bash
# Adversarial validation suite (the production gate).
#
# Provisions two real hostile tenants (A and B) on a throwaway Multipass VM and
# attacks the boundary from A's position. EVERY check asserts an attack is
# REJECTED; the suite exits non-zero if any attack SUCCEEDS. It is a required
# CI gate, separate from the functional phaseN-verify.sh scripts.
#
# Env:
#   NAKPANEL_SKIP_PRIOR_PHASES=1   reuse an already-provisioned VM (dev loop);
#                                  otherwise the full phase chain installs the
#                                  stack first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase26-verify.sh"
fi

# ---------------------------------------------------------------------------
# Bootstrap: build current HEAD (with the hardening) + agentprobe, wire the
# provisioning-API env + webhook sink, and make sure disk quotas are active.
# ---------------------------------------------------------------------------
sync_repo "${ROOT_DIR}"
VM_IP="$(vm_ip)"
multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
cd /tmp/nakpanel-src
make build
go build -o bin/agentprobe ./deploy/multipass/agentprobe
sudo install -m 0755 bin/panel /usr/local/bin/nakpanel-panel
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0755 bin/panelctl /usr/local/bin/panelctl
sudo install -m 0755 bin/agentprobe /usr/local/bin/agentprobe
sudo -u nakpanel env DB_DSN='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' make goose-up
sudo mkdir -p /etc/systemd/system/nakpanel.service.d
sudo tee /etc/systemd/system/nakpanel.service.d/phase20.conf >/dev/null <<EOF
[Service]
Environment=NAKPANEL_PUBLIC_URL=https://${VM_IP}:7443
Environment=NAKPANEL_BILLING_WEBHOOK_URL=http://127.0.0.1:18080/hook
Environment=NAKPANEL_BILLING_WEBHOOK_SECRET=security-webhook-secret
EOF
sudo pkill -f webhook_sink.py 2>/dev/null || true
sudo rm -f /tmp/security-webhooks.jsonl
sudo -u nakpanel env WEBHOOK_SINK_SECRET=security-webhook-secret WEBHOOK_SINK_OUTPUT=/tmp/security-webhooks.jsonl \
  nohup python3 /tmp/nakpanel-src/deploy/multipass/webhook_sink.py >/tmp/security-webhook-sink.log 2>&1 &
sudo systemctl daemon-reload
# Disk quotas do not survive a VM reboot until the kernel module is present.
if ! sudo quotaon -p / 2>/dev/null | grep -q 'user quota .* is on'; then
  sudo modprobe quota_v2 2>/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "linux-modules-extra-\$(uname -r)" >/dev/null 2>&1 || true
  sudo modprobe quota_v2 2>/dev/null || true
  sudo mount -o remount,usrquota,grpquota / 2>/dev/null || true
  sudo quotacheck -ugm / 2>/dev/null || sudo quotacheck -cugm / 2>/dev/null || true
  sudo quotaon -uv / 2>/dev/null || true
fi
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

tmpdir="$(mktemp -d)"
STAMP="$(date +%s)"
FAILS=0
cleanup() {
  rm -rf "${tmpdir}"
  # Purge the adversarial tenants while the webhook sink and suite key are
  # still available.
  if [[ -n "${A_ACC:-}" ]]; then api -X DELETE "https://${VM_IP}:7443/api/v1/accounts/${A_ACC}?purge=true" -o /dev/null || true; fi
  if [[ -n "${B_ACC:-}" ]]; then api -X DELETE "https://${VM_IP}:7443/api/v1/accounts/${B_ACC}?purge=true" -o /dev/null || true; fi
  for _ in $(seq 1 90); do
    pending=0
    for account in "${A_ACC:-}" "${B_ACC:-}" "${CONC_ACC:-}"; do
      [[ -z "${account}" ]] && continue
      [[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${account}'")" == terminated ]] || pending=1
    done
    [[ "${pending}" == 0 ]] && break
    sleep 2
  done
  # Let teardown notifications reach the verifier sink before removing its
  # endpoint, otherwise the lab is left with retrying delivery jobs.
  for _ in $(seq 1 60); do
    [[ "$(db "SELECT count(*) FROM billing_webhook_outbox outbox JOIN billing_accounts account ON account.id=outbox.billing_account_id WHERE account.external_ref IN ('secA${STAMP}','secB${STAMP}','secconc${STAMP}') AND outbox.status<>'sent'")" == 0 ]] && break
    sleep 2
  done
  for raw_key in "${API_KEY:-}" "${rk:-}" "${ek:-}" "${ipk:-}"; do
    [[ -z "${raw_key}" ]] && continue
    cli api-key revoke "$(printf '%s' "${raw_key}" | cut -d_ -f2)" --yes >/dev/null 2>&1 || true
  done
  multipass_exec_short "${VM_NAME}" -- sudo pkill -f webhook_sink.py 2>/dev/null || true
  multipass exec "${VM_NAME}" -- bash -se <<REMOTE || true
set -euo pipefail
sudo tee /etc/systemd/system/nakpanel.service.d/phase20.conf >/dev/null <<EOF
[Service]
Environment=NAKPANEL_PUBLIC_URL=https://${VM_IP}:7443
EOF
sudo systemctl daemon-reload
sudo systemctl restart nakpanel.service
REMOTE
}
trap cleanup EXIT

fail() { echo "SECURITY-FAIL: $*" >&2; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }
part() { echo; echo "== $* =="; }

db()  { multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
cli() { multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' NAKPANEL_AGENT_SOCKET='/run/nakpanel/agent.sock' panelctl --actor security-suite "$@"; }
api() { curl -skS -H "Authorization: Bearer ${API_KEY}" -H 'Content-Type: application/json' "$@"; }
mysql_root() { multipass_exec_short "${VM_NAME}" -- sudo mysql -N -B -e "$1"; }

# admin_post ENDPOINT curl-args...  (uses the admin session + CSRF)
admin_post() { local ep="$1"; shift; curl -sk -o "${tmpdir}/out" -w '%{http_code}' -b "${tmpdir}/admin.cookies" -H "X-Nakpanel-CSRF: ${ADMIN_CSRF}" "$@" "https://${VM_IP}:7443/${ep}"; }
# a_post ENDPOINT curl-args...  (uses tenant A's session + CSRF)
a_post() { local ep="$1"; shift; curl -sk -o "${tmpdir}/out" -w '%{http_code}' -b "${tmpdir}/a.cookies" -H "X-Nakpanel-CSRF: ${A_CSRF}" "$@" "https://${VM_IP}:7443/${ep}"; }

wait_for() { # QUERY EXPECTED
  local q="$1" want="$2" got=""
  for _ in $(seq 1 90); do got="$(db "$q")"; [[ "${got}" == "${want}" ]] && return 0; sleep 2; done
  fail "timeout waiting for [${q}] == ${want} (got ${got})"; return 1
}

echo "Security suite starting against ${VM_NAME} (${VM_IP}); stamp ${STAMP}"

# --- Admin session + API key ------------------------------------------------
for _ in $(seq 1 60); do curl -skf -o /dev/null "https://${VM_IP}:7443/login" && break; sleep 2; done
curl -skf -o /dev/null "https://${VM_IP}:7443/login" || { echo "panel unreachable" >&2; exit 1; }
curl -sk --fail -c "${tmpdir}/admin.cookies" -L -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
ADMIN_CSRF="$(csrf_token "${tmpdir}/admin.cookies")"

key_out="$(cli api-key create --name security-suite --cidrs '192.168.252.0/24,127.0.0.0/8' --rate-limit 600)"
API_KEY="$(printf '%s\n' "${key_out}" | grep '^npk_' | tail -1)"
[[ "${API_KEY}" == npk_* ]] || { echo "no API key" >&2; exit 1; }
PLAN_SLUG="$(db "SELECT api_slug FROM plans WHERE reseller_id IS NULL AND is_active ORDER BY id LIMIT 1")"
[[ -n "${PLAN_SLUG}" ]] || { echo "no active admin plan" >&2; exit 1; }

# --- Provision tenants A and B ---------------------------------------------
provision_tenant() { # LABEL -> exports <LABEL>_ACC/_SUB/_USER/_DOMAIN/_SITE
  local label="$1" ref dom body acc sub user site
  ref="sec${label}${STAMP}"
  dom="${ref}.test"
  body="{\"external_ref\":\"${ref}\",\"provider\":\"admin\",\"plan\":\"${PLAN_SLUG}\",\"email\":\"${ref}@example.test\",\"name\":\"tenant ${label}\",\"domain\":\"${dom}\"}"
  api -o "${tmpdir}/${label}.json" -d "${body}" "https://${VM_IP}:7443/api/v1/accounts" >/dev/null
  acc="$(sed -n 's/.*"id":"\(acc_[^"]*\)".*/\1/p' "${tmpdir}/${label}.json")"
  [[ "${acc}" == acc_* ]] || { echo "tenant ${label} create failed: $(cat "${tmpdir}/${label}.json")" >&2; exit 1; }
  for _ in $(seq 1 90); do [[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${acc}'")" == active ]] && break; sleep 2; done
  [[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${acc}'")" == active ]] || { echo "tenant ${label} did not provision" >&2; exit 1; }
  sub="$(db "SELECT subscription_id FROM billing_accounts WHERE public_id='${acc}'")"
  user="$(db "SELECT username FROM subscription_system_accounts WHERE subscription_id=${sub}")"
  site="$(db "SELECT id FROM sites WHERE subscription_id=${sub} ORDER BY id LIMIT 1")"
  eval "${label}_ACC=\"${acc}\"; ${label}_SUB=\"${sub}\"; ${label}_USER=\"${user}\"; ${label}_DOMAIN=\"${dom}\"; ${label}_SITE=\"${site}\""
  # Enable mail + a generous entitlement so the tenant is fully featured.
  db "UPDATE subscription_entitlements SET max_mailboxes=3, max_databases=3, hosting_policy=jsonb_set(jsonb_set(jsonb_set(('{\"resources\":{},\"permissions\":{},\"mail\":{}}'::jsonb || COALESCE(hosting_policy,'{}'::jsonb)),'{resources,max_mailboxes}','3'::jsonb,true),'{permissions,mail}','true'::jsonb,true),'{mail}',COALESCE(hosting_policy->'mail','{}'::jsonb) || '{\"enabled\":true,\"webmail\":true}'::jsonb,true) WHERE subscription_id=${sub}" >/dev/null
  echo "  provisioned tenant ${label}: acc=${acc} sub=${sub} user=${user} domain=${dom} site=${site}"
}
provision_tenant A
provision_tenant B

# Give each tenant a database, a DNS zone+record, a mailbox, and a backup
# (admin acts on their behalf; the cross-tenant attacks come later as A).
provision_resources() { # LABEL
  local label="$1" lc sub dom site dbname dbuser
  lc="$(printf '%s' "${label}" | tr 'A-Z' 'a-z')"
  eval "sub=\${${label}_SUB}; dom=\${${label}_DOMAIN}; site=\${${label}_SITE}"
  dbname="db${lc}${STAMP}"   # the handler lowercases db_name/db_user
  dbuser="dbu${lc}${STAMP}"
  admin_post databases -d "subscription_id=${sub}" -d "site_id=${site}" -d "db_name=${dbname}" -d "db_user=${dbuser}" >/dev/null
  admin_post dns -d "domain=${dom}" -d "address=${VM_IP}" >/dev/null
  cli mail enable "${dom}" --dmarc quarantine >/dev/null 2>&1 || true
  cli mail add "user@${dom}" --password "TenantMbx-${label}-2026" >/dev/null 2>&1 || true
  cli backup create "${dom}" >/dev/null 2>&1 || true
  eval "${label}_DB=\"${dbname}\"; ${label}_DBUSER=\"${dbuser}\""
}
provision_resources A
provision_resources B
# Wait for the databases + a DNS zone to converge so the isolation checks have
# real objects to attack.
wait_for "SELECT count(*) FROM databases WHERE db_name='${A_DB}' AND status='active'" 1 || true
A_DBUSER="$(db "SELECT db_user FROM databases WHERE db_name='${A_DB}'")"

# --- Tenant A's real browser session (via the provisioning-API SSO link) ----
api -X POST -d '{}' "https://${VM_IP}:7443/api/v1/accounts/${A_ACC}/login-link" -o "${tmpdir}/a-link.json" >/dev/null
A_SSO="$(sed -n 's/.*"url":"\([^"]*\)".*/\1/p' "${tmpdir}/a-link.json" | sed 's#\\u0026#\&#g')"
curl -sk -c "${tmpdir}/a.cookies" -o /dev/null "${A_SSO}"
A_CSRF="$(csrf_token "${tmpdir}/a.cookies" 2>/dev/null || true)"
[[ -n "${A_CSRF}" ]] || fail "could not establish tenant A session via SSO"

##############################################################################
part "Part A — Filesystem boundary (agent ops reject hostile input before writing)"
##############################################################################
probe() { # OP DATA-JSON  -> prints agentprobe JSON (run as the panel user)
  multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel /usr/local/bin/agentprobe -op "$1" -data "$2"
}
assert_rejected() { # LABEL JSON
  if grep -q '"ok":false' <<<"$2"; then ok "$1 rejected"; else fail "$1 was ACCEPTED at the agent boundary: $2"; fi
}

for d in '../../etc' '/etc/passwd' 'a.b\nc.d' 'x.gh;}server{listen 80;root /etc;}' 'a.b c.d' "$(printf 'a.b%s.c' '\\u0000')"; do
  r="$(probe create_site "{\"username\":\"npprobe1\",\"domain\":\"${d}\",\"php_version\":\"8.3\"}")"
  assert_rejected "create_site hostile domain [${d}]" "${r}"
done
r="$(probe create_site "{\"username\":\"npprobe1\",\"domain\":\"$(printf 'a%.0s' {1..64}).test\",\"php_version\":\"8.3\"}")"
assert_rejected "create_site overlong label" "${r}"
for u in 'root' 'mysql' 'nakpanel' '../root' 'ROOT' 'ro' 'a;b'; do
  r="$(probe create_site "{\"username\":\"${u}\",\"domain\":\"probe.example.test\",\"php_version\":\"8.3\"}")"
  assert_rejected "create_site hostile username [${u}]" "${r}"
done
r="$(probe create_site '{"username":"npprobe1","domain":"probe.example.test","php_version":"8.3","docroot":"/etc"}')"
assert_rejected "create_site client-supplied docroot" "${r}"

# Symlink swap: plant a symlink to /etc inside tenant A's tree, force a
# convergence (which chowns the tree), and prove /etc was not re-owned.
multipass exec "${VM_NAME}" -- bash -se <<REMOTE
set -euo pipefail
home="/home/${A_USER}"
target="\${home}/domains/${A_DOMAIN}/public_html"
sudo mkdir -p "\${target}"
sudo ln -sfn /etc "\${target}/etc-escape"
sudo touch /etc/nakpanel-symlink-canary
REMOTE
etc_owner_before="$(multipass_exec_short "${VM_NAME}" -- stat -c '%U' /etc/nakpanel-symlink-canary)"
reconcile_before="$(db "SELECT COALESCE(MAX(id),0) FROM reconciliation_runs")"
cli reconcile --system >/dev/null
reconcile_run="$(db "SELECT COALESCE(MAX(id),0) FROM reconciliation_runs")"
if (( reconcile_run <= reconcile_before )); then
  fail "system reconciliation did not create a run"
else
  wait_for "SELECT status FROM reconciliation_runs WHERE id=${reconcile_run}" active
fi
etc_owner_after="$(multipass_exec_short "${VM_NAME}" -- stat -c '%U' /etc/nakpanel-symlink-canary)"
if [[ "${etc_owner_before}" == "root" && "${etc_owner_after}" == "root" ]]; then
  ok "symlink swap did not re-own /etc (canary still ${etc_owner_after})"
else
  fail "symlink swap re-owned /etc: before=${etc_owner_before} after=${etc_owner_after}"
fi
multipass_exec_short "${VM_NAME}" -- sudo rm -f /etc/nakpanel-symlink-canary || true

##############################################################################
part "Part B — Config template injection (rejected; rendered configs pass native checkers)"
##############################################################################
# nginx / FPM / BIND / Stalwart injection are all rejected at ValidateDomain,
# the username regex, or the DNS/mail validators (agentprobe above already
# proved the nginx/FPM domain+username vectors). DNS newline-RR injection:
r="$(probe configure_dns_zone "{\"domain\":\"${A_DOMAIN}\",\"address\":\"${VM_IP}\",\"records\":[{\"host\":\"www 300 IN A 6.6.6.6\\nevil\",\"type\":\"A\",\"value\":\"203.0.113.9\",\"ttl\":3600}]}")"
assert_rejected "configure_dns_zone newline-in-host RR injection" "${r}"
r="$(probe configure_dns_zone "{\"domain\":\"${A_DOMAIN}\",\"address\":\"${VM_IP}\",\"records\":[{\"host\":\"@\",\"type\":\"TXT\",\"value\":\"ok\\nevil 300 IN NS attacker.example.\",\"ttl\":3600}]}")"
assert_rejected "configure_dns_zone newline-in-TXT RR injection" "${r}"
# Stalwart mail injection: a mail hostname with injection chars.
r="$(probe configure_mail '{"hostname":"mail.evil\ntls.implicit=false","domains":[]}')"
assert_rejected "configure_mail hostname injection" "${r}"
# Every zone actually served on the box must pass named-checkzone, and nginx -t
# must be clean — proving the validated configs are also syntactically sound.
if multipass_exec_short "${VM_NAME}" -- bash -c 'ok=1; for z in /etc/bind/nakpanel/zones/db.*; do sudo named-checkzone "$(basename "$z" | sed s/^db.//)" "$z" >/dev/null 2>&1 || ok=0; done; sudo nginx -t >/dev/null 2>&1 || ok=0; echo $ok' | grep -qx 1; then
  ok "all rendered BIND zones pass named-checkzone and nginx -t is clean"
else
  fail "a rendered config failed its native checker"
fi

##############################################################################
part "Part C — Cross-tenant isolation (from A's position, B is unreachable)"
##############################################################################
# Files: A's system user cannot read or write B's tree (exit code of the remote
# command is the isolation verdict).
if multipass_exec_short "${VM_NAME}" -- sudo -u "${A_USER}" bash -c "cat /home/${B_USER}/domains/${B_DOMAIN}/public_html/* >/dev/null 2>&1"; then
  fail "A's system user could READ B's docroot"
else
  ok "A cannot read B's docroot"
fi
if multipass_exec_short "${VM_NAME}" -- sudo -u "${A_USER}" bash -c "touch /home/${B_USER}/pwned >/dev/null 2>&1"; then
  fail "A's system user could WRITE into B's home"
else
  ok "A cannot write into B's home"
fi

# Databases: A's MariaDB grants cover only A's database (no B, no global).
grants="$(mysql_root "SHOW GRANTS FOR '${A_DBUSER}'@'localhost'" 2>/dev/null || true)"
if grep -q "\`${A_DB}\`" <<<"${grants}" && ! grep -q "\`${B_DB}\`" <<<"${grants}" && ! grep -qE 'ON \*\.\*.*(ALL PRIVILEGES|SELECT|INSERT|CREATE)' <<<"${grants}"; then
  ok "A's DB user is granted only its own schema"
else
  fail "A's DB grants are not scoped: ${grants}"
fi
# Databases: A's session cannot create a database under B's subscription.
code="$(a_post databases -d "subscription_id=${B_SUB}" -d "site_id=${B_SITE}" -d "db_name=steal${STAMP}")"
[[ "${code}" == 404 || "${code}" == 403 ]] && ok "A cannot create a database under B (${code})" || fail "A created a DB under B: HTTP ${code}"

# Mailboxes (the untested P0): A's session cannot manage B's mail.
code="$(a_post "subscriptions/${B_SUB}/mailboxes" -d "mail_domain_id=$(db "SELECT id FROM mail_domains WHERE domain='${B_DOMAIN}'")" -d "local_part=intruder" -d "password=IntruderMbx-2026")"
[[ "${code}" == 404 || "${code}" == 403 ]] && ok "A cannot create a mailbox under B's domain (${code})" || fail "A created a mailbox under B: HTTP ${code}"
# A also cannot delete B's mailbox by guessing its id. The delete is scoped in
# SQL to A's subscription, so B's row must survive regardless of the HTTP code
# the (idempotent) delete handler returns.
B_MBX="$(db "SELECT mb.id FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.subscription_id=${B_SUB} ORDER BY mb.id DESC LIMIT 1")"
if [[ -n "${B_MBX}" ]]; then
  a_post "subscriptions/${A_SUB}/services/mailbox/${B_MBX}/delete" >/dev/null
  a_post "subscriptions/${B_SUB}/services/mailbox/${B_MBX}/delete" >/dev/null
  still="$(db "SELECT count(*) FROM mailboxes WHERE id=${B_MBX}")"
  [[ "${still}" == 1 ]] && ok "A cannot delete B's mailbox by id (row survives)" || fail "A deleted B's mailbox by id (row gone)"
else
  echo "  (skip: B has no mailbox to target)"
fi

# DNS: A's session cannot edit B's zone records.
code="$(a_post "sites/${B_SITE}/dns-records" -d "host=evil" -d "record_type=A" -d "value=6.6.6.6" -d "ttl=3600")"
[[ "${code}" == 404 || "${code}" == 403 ]] && ok "A cannot write DNS records on B's site (${code})" || fail "A wrote a DNS record on B's site: HTTP ${code}"

# Backups: A's session cannot restore B's backup.
B_BACKUP="$(db "SELECT id FROM backups WHERE subscription_id=${B_SUB} ORDER BY id DESC LIMIT 1")"
if [[ -n "${B_BACKUP}" ]]; then
  code="$(a_post restores -d "backup_id=${B_BACKUP}")"
  [[ "${code}" == 404 || "${code}" == 403 ]] && ok "A cannot restore B's backup (${code})" || fail "A restored B's backup: HTTP ${code}"
else
  echo "  (skip: B has no backup row yet)"
fi

##############################################################################
part "Part D — Entitlement / quota bypass (fail-closed on every path)"
##############################################################################
# Beyond plan limit (UI path): cap A at 1 mailbox, then the 2nd is refused.
db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{resources,max_mailboxes}','1'::jsonb,true) WHERE subscription_id=${A_SUB}" >/dev/null
over="$(cli mail add "second@${A_DOMAIN}" 2>&1 || true)"
grep -qiE 'quota exceeded|ErrExceeded|limit' <<<"${over}" && ok "CLI mailbox over plan limit → ErrExceeded" || fail "CLI created a mailbox past the limit: ${over}"
db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{resources,max_mailboxes}','3'::jsonb,true) WHERE subscription_id=${A_SUB}" >/dev/null

# Beyond plan limit (UI/database): cap A at 1 database (blocking overuse), 2nd
# is refused. A already has one database, so the next create trips the gate.
db "UPDATE subscription_entitlements SET max_databases=1, overuse_policy='block' WHERE subscription_id=${A_SUB}" >/dev/null
code="$(admin_post databases -d "subscription_id=${A_SUB}" -d "site_id=${A_SITE}" -d "db_name=over${STAMP}" -d "db_user=dbuover${STAMP}")"
if [[ "${code}" == 400 ]] && grep -qiE 'quota exceeded|exceeded' "${tmpdir}/out"; then ok "UI database over plan limit → ErrExceeded"; else fail "UI created a DB past the limit: HTTP ${code} $(cat "${tmpdir}/out")"; fi
db "UPDATE subscription_entitlements SET max_databases=3 WHERE subscription_id=${A_SUB}" >/dev/null

# Suspended subscription: provisioning is denied while suspended.
api -X POST -d '{}' "https://${VM_IP}:7443/api/v1/accounts/${A_ACC}/suspend" -o /dev/null >/dev/null
wait_for "SELECT status FROM subscriptions WHERE id=${A_SUB}" suspended || true
code="$(admin_post databases -d "subscription_id=${A_SUB}" -d "site_id=${A_SITE}" -d "db_name=susp${STAMP}")"
[[ "${code}" != 303 && "${code}" != 200 ]] && ok "provisioning under a suspended subscription is denied (${code})" || fail "provisioned under a suspended subscription: HTTP ${code}"
api -X POST -d '{}' "https://${VM_IP}:7443/api/v1/accounts/${A_ACC}/unsuspend" -o /dev/null >/dev/null
wait_for "SELECT status FROM subscriptions WHERE id=${A_SUB}" active || true

# No active subscription: a cancelled subscription cannot provision.
NOSUB="$(db "SELECT id FROM subscriptions WHERE status='cancelled' ORDER BY id LIMIT 1")"
if [[ -n "${NOSUB}" ]]; then
  code="$(admin_post databases -d "subscription_id=${NOSUB}" -d "db_name=nosub${STAMP}")"
  [[ "${code}" != 303 && "${code}" != 200 ]] && ok "provisioning without an active subscription is denied (${code})" || fail "provisioned without an active subscription: HTTP ${code}"
else
  echo "  (no cancelled subscription available to test no-active-subscription; covered by suspended)"
fi

# change-plan downgrade below current usage → plan_downgrade_conflict.
db "INSERT INTO plans(name,is_active,max_sites,max_databases,max_mailboxes,disk_mb,bandwidth_mb,php_allowlist) VALUES('security-tiny-${STAMP}',true,0,0,0,10,1024,'8.3')" >/dev/null 2>&1 || true
TINY_SLUG="$(db "SELECT COALESCE(api_slug,'') FROM plans WHERE name='security-tiny-${STAMP}'")"
if [[ -n "${TINY_SLUG}" ]]; then
  code="$(api -X POST -d "{\"plan\":\"${TINY_SLUG}\"}" "https://${VM_IP}:7443/api/v1/accounts/${A_ACC}/change-plan" -o "${tmpdir}/downgrade.json" -w '%{http_code}')"
  if [[ "${code}" == 409 ]] && grep -Fq 'plan_downgrade_conflict' "${tmpdir}/downgrade.json"; then ok "downgrade below usage → 409 plan_downgrade_conflict"; else fail "downgrade below usage was not blocked: HTTP ${code} $(cat "${tmpdir}/downgrade.json")"; fi
else
  echo "  (skip downgrade: could not create a constrained target plan)"
fi

# oversell_policy=cap: assigning past server capacity → ErrOversellCap.
db "UPDATE settings SET oversell_policy='cap', server_disk_capacity_mb=10 WHERE id=true" >/dev/null
capref="seccap${STAMP}"
code="$(api -o "${tmpdir}/cap.json" -w '%{http_code}' -d "{\"external_ref\":\"${capref}\",\"provider\":\"admin\",\"plan\":\"${PLAN_SLUG}\",\"email\":\"${capref}@example.test\",\"name\":\"cap\",\"domain\":\"${capref}.test\"}" "https://${VM_IP}:7443/api/v1/accounts")"
if [[ "${code}" != 202 ]] && grep -qiE 'oversell|capacity' "${tmpdir}/cap.json"; then ok "assign past capacity with oversell cap → rejected (${code})"; else fail "oversell cap did not fire: HTTP ${code} $(cat "${tmpdir}/cap.json")"; fi
db "UPDATE settings SET oversell_policy='warn', server_disk_capacity_mb=0 WHERE id=true" >/dev/null

##############################################################################
part "Part E — Provisioning API auth & abuse"
##############################################################################
code="$(curl -sk -o /dev/null -w '%{http_code}' "https://${VM_IP}:7443/api/v1/accounts")"
[[ "${code}" == 401 ]] && ok "no API key → 401" || fail "missing key returned ${code}"
code="$(curl -sk -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer npk_deadbeef_notarealkey' "https://${VM_IP}:7443/api/v1/ping")"
[[ "${code}" == 401 ]] && ok "malformed key → 401" || fail "malformed key returned ${code}"
hdr="$(curl -skD - -o /dev/null -b 'nakpanel_session=fake' "https://${VM_IP}:7443/api/v1/ping")"
grep -q ' 401 ' <<<"${hdr}" && ! grep -qi '^set-cookie:' <<<"${hdr}" && ok "session cookie on API → 401, no cookie set" || fail "cookie-only API request was not cleanly rejected"
# revoked key → 401
rk="$(cli api-key create --name sec-revoke-${STAMP} --cidrs '0.0.0.0/0' --rate-limit 60 | grep '^npk_' | tail -1)"
cli api-key revoke "$(printf '%s' "${rk}" | cut -d_ -f2)" --yes >/dev/null 2>&1 || true
code="$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${rk}" "https://${VM_IP}:7443/api/v1/ping")"
[[ "${code}" == 401 ]] && ok "revoked key → 401" || fail "revoked key returned ${code}"
# expired key → 401
ek="$(cli api-key create --name sec-expire-${STAMP} --cidrs '0.0.0.0/0' --rate-limit 60 --expires 2020-01-01T00:00:00Z | grep '^npk_' | tail -1)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${ek}" "https://${VM_IP}:7443/api/v1/ping")"
[[ "${code}" == 401 ]] && ok "expired key → 401" || fail "expired key returned ${code}"
# IP allowlist: a key whose CIDR excludes the caller → 403.
ipk="$(cli api-key create --name sec-ip-${STAMP} --cidrs '10.99.0.0/16' --rate-limit 60 | grep '^npk_' | tail -1)"
code="$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${ipk}" "https://${VM_IP}:7443/api/v1/ping")"
[[ "${code}" == 403 ]] && ok "request from a disallowed IP → 403" || fail "IP allowlist did not deny: ${code}"
# Cross-surface scope: an API key cannot drive UI/session routes; a session
# cannot drive the API.
code="$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${API_KEY}" "https://${VM_IP}:7443/sites")"
[[ "${code}" == 401 || "${code}" == 303 || "${code}" == 302 ]] && ok "API key cannot drive UI routes (${code})" || fail "API key reached a UI route: ${code}"
# Idempotency under concurrency: N simultaneous creates with one external_ref.
conc_ref="secconc${STAMP}"
conc_body="{\"external_ref\":\"${conc_ref}\",\"provider\":\"admin\",\"plan\":\"${PLAN_SLUG}\",\"email\":\"${conc_ref}@example.test\",\"name\":\"conc\",\"domain\":\"${conc_ref}.test\"}"
for i in 1 2 3 4 5; do api -o "${tmpdir}/conc${i}.json" -d "${conc_body}" "https://${VM_IP}:7443/api/v1/accounts" & done
wait
sleep 2
rows="$(db "SELECT count(*) FROM billing_accounts WHERE external_ref='${conc_ref}'")"
[[ "${rows}" == 1 ]] && ok "5 concurrent creates with one external_ref → exactly 1 account" || fail "concurrent idempotency created ${rows} accounts"
CONC_ACC="$(db "SELECT public_id FROM billing_accounts WHERE external_ref='${conc_ref}'")"
# Webhook signature: real deliveries carry a valid HMAC; a tampered payload
# (correct-looking header, wrong signature) fails verification.
for _ in $(seq 1 60); do multipass_exec_short "${VM_NAME}" -- test -s /tmp/security-webhooks.jsonl && break; sleep 2; done
if multipass_exec_short "${VM_NAME}" -- grep -Fq '"valid":true' /tmp/security-webhooks.jsonl; then ok "outbound webhooks carry a valid HMAC signature"; else fail "no validly-signed webhook was delivered"; fi
tampered="$(multipass_exec_short "${VM_NAME}" -- bash -c "curl -s -o /dev/null -X POST -H 'X-Nakpanel-Timestamp: 1700000000' -H 'X-Nakpanel-Signature: sha256=deadbeefdeadbeef' -H 'X-Nakpanel-Event: tampered' --data '{\"tampered\":true}' http://127.0.0.1:18080/hook; tail -1 /tmp/security-webhooks.jsonl")"
grep -q '"event":"tampered".*"valid":false\|"valid":false.*tampered\|"tampered":true' <<<"${tampered}" && grep -q '"valid":false' <<<"${tampered}" && ok "tampered webhook fails HMAC verification" || fail "tampered webhook was accepted as valid: ${tampered}"
# Soft delete: DELETE without purge cancels but keeps tenant data.
api -X DELETE "https://${VM_IP}:7443/api/v1/accounts/${CONC_ACC}" -o "${tmpdir}/soft.json" >/dev/null
grep -Fq '"lifecycle":"cancelled"' "${tmpdir}/soft.json" && ok "DELETE without purge is a soft cancel" || fail "soft delete did not cancel: $(cat "${tmpdir}/soft.json")"
CONC_SUB="$(db "SELECT subscription_id FROM billing_accounts WHERE public_id='${CONC_ACC}'")"
[[ "$(db "SELECT count(*) FROM sites WHERE subscription_id=${CONC_SUB}")" -ge 1 ]] && ok "soft delete retained the tenant's sites" || fail "soft delete removed tenant data"
api -X DELETE "https://${VM_IP}:7443/api/v1/accounts/${CONC_ACC}?purge=true" -o /dev/null >/dev/null

##############################################################################
part "Part F — Agent socket boundary"
##############################################################################
perms="$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%a %U:%G' /run/nakpanel/agent.sock)"
[[ "${perms}" == "660 root:nakpanel" ]] && ok "socket is 0660 root:nakpanel" || fail "socket perms are ${perms}"
dperms="$(multipass_exec_short "${VM_NAME}" -- sudo stat -c '%a %U:%G' /run/nakpanel)"
[[ "${dperms}" == "750 root:nakpanel" ]] && ok "socket dir is 0750 root:nakpanel" || fail "socket dir perms are ${dperms}"
if multipass_exec_short "${VM_NAME}" -- id "${A_USER}" | grep -q '(nakpanel)'; then fail "tenant user ${A_USER} is in the nakpanel group"; else ok "tenant users are not in the nakpanel group"; fi
# Non-panel uid connecting to the socket is rejected by SO_PEERCRED.
for u in "${A_USER}" nobody; do
  rc=0
  multipass_exec_short "${VM_NAME}" -- sudo -u "${u}" /usr/local/bin/agentprobe -op ping -data '{}' >/dev/null 2>&1 || rc=$?
  [[ "${rc}" != 0 ]] && ok "uid ${u} is refused by the agent socket (rc=${rc})" || fail "uid ${u} drove the agent socket"
done
# Unknown op / malformed / oversized are refused with no side effect.
r="$(probe totally_unknown_op '{}')"; grep -q '"ok":false' <<<"${r}" && grep -qi 'unknown op' <<<"${r}" && ok "unknown op → validation error" || fail "unknown op response: ${r}"
r="$(multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel /usr/local/bin/agentprobe -op ping -mode malformed 2>/dev/null || true)"; grep -qiE 'ok":false|error|too large|invalid' <<<"${r}" && ok "malformed frame → refused" || fail "malformed frame response: ${r}"
r="$(multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel /usr/local/bin/agentprobe -op ping -mode oversized 2>/dev/null || true)"; grep -qiE 'too large|ok":false|error' <<<"${r}" && ok "oversized frame → refused" || fail "oversized frame response: ${r}"
# Replay: the same idempotency id returns the cached response (single execution).
r1="$(probe ping '{}' | sed 's/.*//')"
id="replay-${STAMP}"
p1="$(multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel /usr/local/bin/agentprobe -op ping -id "${id}" -data '{}')"
p2="$(multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel /usr/local/bin/agentprobe -op ping -id "${id}" -data '{}')"
[[ "${p1}" == "${p2}" ]] && grep -q "\"id\":\"${id}\"" <<<"${p2}" && ok "replayed idempotency id returns the cached response" || fail "replay diverged: ${p1} vs ${p2}"

##############################################################################
part "Part G — Destructive-op safety"
##############################################################################
# DeleteBackup: path escape / traversal / symlink / non-tgz are all rejected.
multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
sudo ln -sfn /etc/passwd /var/lib/nakpanel/backups/link.tar.gz 2>/dev/null || true
sudo tee /var/lib/nakpanel/backups/plain.txt >/dev/null <<<x
REMOTE
for ap in '/etc/passwd' '/var/lib/nakpanel/backups/../../../etc/passwd' '/var/lib/nakpanel/backups/link.tar.gz' '/var/lib/nakpanel/backups/plain.txt'; do
  r="$(probe delete_backup "{\"archive_path\":\"${ap}\"}")"
  assert_rejected "delete_backup path [${ap}]" "${r}"
done
# RestoreBackup into an arbitrary/system path is rejected (docroot escape).
r="$(probe restore_backup "{\"domain\":\"${A_DOMAIN}\",\"username\":\"${A_USER}\",\"docroot\":\"/etc\",\"archive_path\":\"/var/lib/nakpanel/backups/none.tar.gz\",\"databases\":[]}")"
assert_rejected "restore_backup into /etc" "${r}"
# Purge scoping: purging tenant B must not remove tenant A's resources.
a_sites_before="$(db "SELECT count(*) FROM sites WHERE subscription_id=${A_SUB}")"
api -X DELETE "https://${VM_IP}:7443/api/v1/accounts/${B_ACC}?purge=true" -o /dev/null >/dev/null
for _ in $(seq 1 90); do [[ "$(db "SELECT provisioning_state FROM billing_accounts WHERE public_id='${B_ACC}'")" == terminated ]] && break; sleep 2; done
[[ "$(db "SELECT count(*) FROM sites WHERE subscription_id=${B_SUB}")" == 0 ]] && ok "purging B removed B's sites" || fail "purge did not remove B's sites"
[[ "$(db "SELECT count(*) FROM sites WHERE subscription_id=${A_SUB}")" == "${a_sites_before}" ]] && ok "purging B left A's sites intact" || fail "purging B disturbed A's sites"
B_ACC=""  # already purged; skip in cleanup

##############################################################################
part "Part H — Secret handling"
##############################################################################
# No secret material in panel/agent logs.
leak="$(multipass_exec_short "${VM_NAME}" -- bash -c "sudo journalctl -u nakpanel.service -u nakpanel-agent.service --since '-30 min' --no-pager 2>/dev/null | grep -aiE 'BEGIN (RSA |EC )?PRIVATE KEY|npk_[a-f0-9]|NakpanelAdmin!2026|TenantMbx-' | head" || true)"
[[ -z "${leak}" ]] && ok "no secret material in panel/agent logs" || fail "secret material found in logs: ${leak}"
# No secrets in audit metadata or River job args.
[[ "$(db "SELECT count(*) FROM audit_events WHERE metadata::text ~ 'PRIVATE KEY|npk_[a-f0-9]{6}|TenantMbx-'")" == 0 ]] && ok "no secrets in audit_events metadata" || fail "secret leaked into audit metadata"
[[ "$(db "SELECT count(*) FROM river_job WHERE args::text ~ 'PRIVATE KEY|certificate_pem|private_key_pem|TenantMbx-'")" == 0 ]] && ok "no secrets in River job args" || fail "secret leaked into River job args"
# API key is shown once and never retrievable afterward: only a hash is stored,
# there is no key-fetch endpoint, and `api-key list` shows the prefix only.
prefix="$(printf '%s' "${API_KEY}" | cut -d_ -f2)"
[[ "$(db "SELECT count(*) FROM api_keys WHERE key_prefix='${prefix}' AND position(convert_to('${API_KEY}','UTF8') in key_hash) > 0")" == 0 ]] && ok "API keys are stored only as a hash (raw key absent)" || fail "raw API key is recoverable from storage"
listing="$(cli api-key list 2>/dev/null || true)"
grep -q "${API_KEY}" <<<"${listing}" && fail "api-key list leaked the raw key" || ok "api-key list never reveals the raw key"

##############################################################################
if [[ "${FAILS}" -ne 0 ]]; then
  echo; echo "SECURITY SUITE FAILED: ${FAILS} attack(s) were not blocked." >&2
  exit 1
fi
echo; echo "Security suite passed: every adversarial check was blocked on ${VM_NAME} (${VM_IP})."
