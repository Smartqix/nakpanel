#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase12-verify.sh"
fi

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

assert_contains() {
  local file="$1" needle="$2"
  grep -Fq -- "${needle}" "${file}" || { echo "${file} is missing ${needle}" >&2; cat "${file}" >&2; exit 1; }
}

db_value() {
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}

post_as() {
  local actor="$1" label="$2" endpoint="$3"
  shift 3
  local status
  status="$(curl -sk -X POST -o "${tmpdir}/${label}.out" -w '%{http_code}' -b "${tmpdir}/${actor}.cookies" -c "${tmpdir}/${actor}.cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/${actor}.cookies")" "$@" "https://${VM_IP}:7443/${endpoint}")"
  [[ "${status}" == "303" ]] || { echo "${label} returned ${status}, want 303" >&2; cat "${tmpdir}/${label}.out" >&2; exit 1; }
}

wait_for_value() {
  local label="$1" query="$2" expected="$3" value=""
  for _ in $(seq 1 90); do
    value="$(db_value "${query}")"
    [[ "${value}" == "${expected}" ]] && return 0
    sleep 2
  done
  echo "${label}: got ${value}, want ${expected}" >&2
  exit 1
}

schema="$(db_value "SELECT (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='sites' AND column_name IN ('desired_status','desired_php_version','https_redirect','desired_https_redirect','settings_status','settings_error'))||':'||(SELECT COUNT(*) FROM information_schema.columns WHERE table_name='databases' AND column_name='site_id')||':'||(SELECT COUNT(*) FROM information_schema.tables WHERE table_name='dns_records')")"
[[ "${schema}" == "6:1:1" ]] || { echo "Phase 13 schema is incomplete: ${schema}" >&2; exit 1; }

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
if ! dpkg-query -W -f='${Status}' php8.2-fpm 2>/dev/null | grep -Fq 'install ok installed'; then
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update
  sudo apt-get install -y software-properties-common
  sudo add-apt-repository -y ppa:ondrej/php
  sudo apt-get update
  sudo apt-get install -y php8.2-fpm
fi
sudo systemctl enable --now php8.2-fpm
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

curl -sk --fail -c "${tmpdir}/admin.cookies" -b "${tmpdir}/admin.cookies" -L \
  -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/admin.html"
curl -sk --fail -b "${tmpdir}/admin.cookies" "https://${VM_IP}:7443/subscriptions" > "${tmpdir}/subscriptions.html"
for marker in 'Add subscription' 'Change Plan' 'Change Subscriber' 'Service Plans' 'data-np-subscription-filter' 'data-np-subscription-row' 'data-np-subscription-check' 'Resources'; do
  assert_contains "${tmpdir}/subscriptions.html" "${marker}"
done

reseller_id="$(db_value "SELECT id FROM reseller_accounts WHERE email='phase12-reseller@nakpanel.test'")"
reseller_plan_id="$(db_value "SELECT reseller_plan_id FROM reseller_subscriptions WHERE reseller_id=${reseller_id} AND status='active'")"
original_customer_id="$(db_value "SELECT id FROM customers WHERE email='phase12-customer@nakpanel.test'")"
subscription_id="$(db_value "SELECT id FROM subscriptions WHERE name='Phase12 Synced'")"
site_id="$(db_value "SELECT id FROM sites WHERE domain='phase12-reseller.test'")"
original_plan_id="$(db_value "SELECT id FROM plans WHERE name='Phase12 Reseller Hosting' AND reseller_id=${reseller_id}")"
[[ -n "${reseller_id}${original_customer_id}${subscription_id}${site_id}" ]] || { echo 'Phase 12 fixture is missing' >&2; exit 1; }

post_as admin phase13-provider-permissions reseller-plans -d "reseller_plan_id=${reseller_plan_id}" \
  -d 'name=Phase12 Agency' -d 'description=Bounded Phase 12 provider allocation' -d 'max_customers=2' \
  -d 'max_subscriptions=2' -d 'disk_mb=200' -d 'max_sites=4' -d 'max_databases=4' -d 'bandwidth_mb=-1' \
  -d 'max_mailboxes=0' -d 'max_backups=4' -d 'backup_storage_mb=200' -d 'max_subdomains=0' \
  -d 'max_domain_aliases=0' -d 'max_ftp_accounts=0' -d 'allow_custom_plans=true' -d 'allow_dns=true' \
  -d 'allow_tls=true' -d 'allow_backups=true' -d 'allow_php_settings=true' -d 'is_active=true'

# Restore ownership if a previous interrupted run stopped after subscriber transfer.
if [[ "$(db_value "SELECT customer_id FROM subscriptions WHERE id=${subscription_id}")" != "${original_customer_id}" ]]; then
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -v ON_ERROR_STOP=1 -d nakpanel -c "UPDATE subscriptions SET customer_id=${original_customer_id},customer_user_id=NULL WHERE id=${subscription_id}; UPDATE sites SET customer_id=${original_customer_id} WHERE subscription_id=${subscription_id}; UPDATE databases SET customer_id=${original_customer_id} WHERE subscription_id=${subscription_id}; UPDATE backups SET customer_id=${original_customer_id} WHERE subscription_id=${subscription_id};"
fi
multipass exec "${VM_NAME}" -- sudo -u postgres psql -v ON_ERROR_STOP=1 -d nakpanel -c "DELETE FROM restore_runs WHERE backup_id IN (SELECT id FROM backups WHERE site_id=${site_id}); DELETE FROM backups WHERE site_id=${site_id};"

curl -sk --fail -c "${tmpdir}/reseller.cookies" -b "${tmpdir}/reseller.cookies" -L \
  -d 'email=phase12-reseller@nakpanel.test' -d 'password=NakpanelPhase12!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/reseller.html"

target_customer_id="$(db_value "SELECT id FROM customers WHERE email='phase13-customer@nakpanel.test'")"
if [[ -z "${target_customer_id}" ]]; then
  post_as reseller phase13-customer customers -d 'customer_email=phase13-customer@nakpanel.test' -d 'customer_name=Phase Thirteen Customer' -d 'enable_login=true' -d 'password=NakpanelPhase13!2026'
  target_customer_id="$(db_value "SELECT id FROM customers WHERE email='phase13-customer@nakpanel.test'")"
fi

phase13_plan_id="$(db_value "SELECT id FROM plans WHERE name='Phase13 Domain Workspace' AND reseller_id=${reseller_id}")"
post_as reseller phase13-plan plans -d "plan_id=${phase13_plan_id:-0}" \
  -d 'name=Phase13 Domain Workspace' -d 'description=Plesk-style domain tools verification' \
  -d 'disk_mb=64' -d 'max_sites=2' -d 'max_databases=2' -d 'bandwidth_mb=-1' -d 'max_mailboxes=0' \
  -d 'backup_retention_days=7' -d 'php_allowlist=8.3,8.2' -d 'default_php_version=8.3' \
  -d 'php_max_children=2' -d 'php_memory_mb=128' -d 'site_disk_quota_mb=64' -d 'max_backups=2' \
  -d 'backup_storage_mb=128' -d 'allow_dns=true' -d 'allow_tls=true' -d 'allow_backups=true' \
  -d 'allow_php_settings=true' -d 'hosting_enabled=true' -d 'is_active=true'
phase13_plan_id="$(db_value "SELECT id FROM plans WHERE name='Phase13 Domain Workspace' AND reseller_id=${reseller_id}")"

post_as reseller phase13-change-plan subscriptions/bulk-plan -d "subscription_id=${subscription_id}" -d "plan_id=${phase13_plan_id}"
wait_for_value 'bulk plan change' "SELECT plan_id||':'||sync_status FROM subscriptions WHERE id=${subscription_id}" "${phase13_plan_id}:in_sync"

post_as reseller phase13-change-subscriber subscriptions/bulk-subscriber -d "subscription_id=${subscription_id}" -d "customer_id=${target_customer_id}"
wait_for_value 'transactional subscriber transfer' "SELECT s.customer_id||':'||d.customer_id FROM subscriptions s JOIN sites d ON d.subscription_id=s.id WHERE s.id=${subscription_id}" "${target_customer_id}:${target_customer_id}"

curl -sk --fail -b "${tmpdir}/reseller.cookies" "https://${VM_IP}:7443/subscriptions/${subscription_id}" > "${tmpdir}/subscription.html"
for marker in 'Websites &amp; Domains' 'phase12-reseller.test' '?tab=hosting' '?tab=php' '?tab=dns' '?tab=ssl' '?tab=databases' '?tab=backups'; do
  assert_contains "${tmpdir}/subscription.html" "${marker}"
done
for tab in overview hosting php dns ssl databases backups; do
  curl -sk --fail -b "${tmpdir}/reseller.cookies" "https://${VM_IP}:7443/sites/${site_id}?tab=${tab}" > "${tmpdir}/site-${tab}.html"
  assert_contains "${tmpdir}/site-${tab}.html" 'np-domain-tabs'
done

post_as reseller phase13-php "sites/${site_id}/php" -d 'desired_status=active' -d 'desired_php_version=8.2' -d 'desired_https_redirect=false'
wait_for_value 'PHP switching' "SELECT php_version||':'||settings_status FROM sites WHERE id=${site_id}" '8.2:in_sync'

post_as reseller phase13-certificate certificates -d 'domain=phase12-reseller.test' -d "site_id=${site_id}" -d 'issuer=local-self-signed'
wait_for_value 'local certificate issuance' "SELECT tls_status FROM sites WHERE id=${site_id}" 'active'
post_as reseller phase13-redirect "sites/${site_id}/hosting" -d 'desired_status=active' -d 'desired_php_version=8.2' -d 'desired_https_redirect=true'
wait_for_value 'HTTPS redirect convergence' "SELECT https_redirect::text||':'||settings_status FROM sites WHERE id=${site_id}" 'true:in_sync'

zone_id="$(db_value "SELECT id FROM dns_zones WHERE site_id=${site_id}")"
if [[ -z "${zone_id}" ]]; then
  post_as reseller phase13-dns-zone dns -d 'domain=phase12-reseller.test' -d "site_id=${site_id}" -d "address=${VM_IP}"
  wait_for_value 'DNS zone creation' "SELECT status FROM dns_zones WHERE site_id=${site_id}" 'active'
  zone_id="$(db_value "SELECT id FROM dns_zones WHERE site_id=${site_id}")"
fi
post_as reseller phase13-dns-record "sites/${site_id}/dns-records" -d 'host=api' -d 'record_type=A' -d 'value=192.0.2.55' -d 'ttl=3600'
wait_for_value 'DNS record rendering' "SELECT COUNT(*) FROM dns_records WHERE zone_id=${zone_id} AND host='api' AND value='192.0.2.55'" '1'
record_id="$(db_value "SELECT id FROM dns_records WHERE zone_id=${zone_id} AND host='api' AND value='192.0.2.55'")"
post_as reseller phase13-dns-delete "sites/${site_id}/dns-records/${record_id}/delete"
wait_for_value 'DNS record deletion' "SELECT COUNT(*) FROM dns_records WHERE id=${record_id}" '0'

post_as reseller phase13-database databases -d "subscription_id=${subscription_id}" -d "site_id=${site_id}" -d 'engine=mariadb' -d 'db_name=np_phase13' -d 'db_user=np_phase13_user'
wait_for_value 'domain database assignment' "SELECT site_id FROM databases WHERE db_name='np_phase13'" "${site_id}"
post_as reseller phase13-backup backups -d "subscription_id=${subscription_id}" -d "site_id=${site_id}" -d 'domain=phase12-reseller.test'
wait_for_value 'domain backup creation' "SELECT status FROM backups WHERE site_id=${site_id} ORDER BY id DESC LIMIT 1" 'active'
backup_id="$(db_value "SELECT id FROM backups WHERE site_id=${site_id} ORDER BY id DESC LIMIT 1")"
post_as reseller phase13-restore restores -d "backup_id=${backup_id}" -d "site_id=${site_id}"
wait_for_value 'domain backup restore' "SELECT status FROM restore_runs WHERE backup_id=${backup_id} ORDER BY id DESC LIMIT 1" 'active'

post_as reseller phase13-domain-suspend "sites/${site_id}/hosting" -d 'desired_status=suspended' -d 'desired_php_version=8.2' -d 'desired_https_redirect=true'
wait_for_value 'individual domain suspension' "SELECT status||':'||desired_status FROM sites WHERE id=${site_id}" 'suspended:suspended'
post_as reseller phase13-sub-suspend subscriptions/bulk-status -d "subscription_id=${subscription_id}" -d 'status=suspended'
post_as reseller phase13-sub-active subscriptions/bulk-status -d "subscription_id=${subscription_id}" -d 'status=active'
wait_for_value 'hierarchical desired status restore' "SELECT status||':'||desired_status FROM sites WHERE id=${site_id}" 'suspended:suspended'

curl -sk --fail -c "${tmpdir}/client.cookies" -b "${tmpdir}/client.cookies" -L \
  -d 'email=phase13-customer@nakpanel.test' -d 'password=NakpanelPhase13!2026' \
  "https://${VM_IP}:7443/login" > "${tmpdir}/client.html"
curl -sk --fail -b "${tmpdir}/client.cookies" "https://${VM_IP}:7443/subscriptions" > "${tmpdir}/client-subscriptions.html"
assert_contains "${tmpdir}/client-subscriptions.html" 'Phase12 Synced'
if grep -Fq 'Change Subscriber' "${tmpdir}/client-subscriptions.html"; then echo 'client exposed provider subscription actions' >&2; exit 1; fi
client_bulk_status="$(curl -sk -o /dev/null -w '%{http_code}' -b "${tmpdir}/client.cookies" -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/client.cookies")" -d "subscription_id=${subscription_id}" -d 'status=active' "https://${VM_IP}:7443/subscriptions/bulk-status")"
[[ "${client_bulk_status}" == '403' ]] || { echo "client bulk status returned ${client_bulk_status}, want 403" >&2; exit 1; }
csrf_status="$(curl -sk -o /dev/null -w '%{http_code}' -b "${tmpdir}/reseller.cookies" -d "subscription_id=${subscription_id}" -d 'status=active' "https://${VM_IP}:7443/subscriptions/bulk-status")"
[[ "${csrf_status}" == '403' ]] || { echo "CSRF check returned ${csrf_status}, want 403" >&2; exit 1; }

# Return the shared Phase 12 fixture to its original owner and runtime state.
post_as reseller phase13-owner-restore subscriptions/bulk-subscriber -d "subscription_id=${subscription_id}" -d "customer_id=${original_customer_id}"
post_as reseller phase13-plan-restore subscriptions/bulk-plan -d "subscription_id=${subscription_id}" -d "plan_id=${original_plan_id}"
post_as reseller phase13-runtime-restore "sites/${site_id}/hosting" -d 'desired_status=active' -d 'desired_php_version=8.3' -d 'desired_https_redirect=false'
wait_for_value 'fixture runtime restored' "SELECT status||':'||php_version||':'||https_redirect::text FROM sites WHERE id=${site_id}" 'active:8.3:false'
multipass exec "${VM_NAME}" -- sudo -u postgres psql -v ON_ERROR_STOP=1 -d nakpanel -c "DELETE FROM plans WHERE id=${phase13_plan_id}; DELETE FROM audit_events WHERE customer_id=${target_customer_id}; DELETE FROM customers WHERE id=${target_customer_id}; DELETE FROM users WHERE email='phase13-customer@nakpanel.test';"

echo "Phase 13 subscription and domain workspace verification passed for ${VM_NAME} (${VM_IP})."
