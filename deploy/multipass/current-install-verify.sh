#!/usr/bin/env bash
# Bootstrap the current stack, not historical UI/token contracts.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
require_nakpanel_vm_name "${VM_NAME}"
ensure_vm 4 6G 48G
sync_repo "${ROOT_DIR}"
assert_current_vm_identity
if [[ -n "${NAKPANEL_RELEASE_BUNDLE:-}" ]]; then
  : "${NAKPANEL_RELEASE_PUBLIC_KEY:?signed bundle requires an out-of-band public key}"
  : "${NAKPANEL_RELEASE_VERSION:?signed bundle requires an exact version}"
  verify_args=(--bundle "${NAKPANEL_RELEASE_BUNDLE}" --public-key "${NAKPANEL_RELEASE_PUBLIC_KEY}" --version "${NAKPANEL_RELEASE_VERSION}" --architecture "${NAKPANEL_MULTIPASS_ARCH}")
  if [[ "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" == 1 ]]; then verify_args+=(--allow-development); fi
  python3 "${ROOT_DIR}/deploy/release/verify.py" "${verify_args[@]}"
  staging="$(mktemp -d)"
  trap 'status=$?; rm -rf "${staging}"; exit "${status}"' EXIT
  COPYFILE_DISABLE=1 tar -C "${NAKPANEL_RELEASE_BUNDLE}" -cf "${staging}/release.tar" .
  multipass transfer "${staging}/release.tar" "${VM_NAME}:/tmp/nakpanel-release.tar"
  multipass transfer "${NAKPANEL_RELEASE_PUBLIC_KEY}" "${VM_NAME}:/tmp/nakpanel-release-public.pem"
  multipass_exec_short "${VM_NAME}" -- sudo bash -c 'set -e; test ! -e /tmp/nakpanel-release; install -d -m 0700 /tmp/nakpanel-release; tar --no-same-owner -xf /tmp/nakpanel-release.tar -C /tmp/nakpanel-release'
  rm -rf "${staging}"
  trap - EXIT
fi
multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se -- "${NAKPANEL_REMOTE_SRC}" "${IMAGE}" "${NAKPANEL_RELEASE_BUNDLE:+1}" "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" "${NAKPANEL_RELEASE_LEGACY_INSTALLER:-0}" "${NAKPANEL_QUALIFICATION_PHP_PROVIDER}" <<'REMOTE'
set -euo pipefail
cd "$1"
if ! id nakpanel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi
chown -R nakpanel:nakpanel "$1"
test ! -e /etc/nakpanel/version
export NAKPANEL_RELEASE_ALLOW_DEVELOPMENT="$4"
install_args=(--yes)
if [[ "$6" == sury ]]; then install_args+=(--php-provider sury); fi
if [[ "$3" == 1 ]]; then
  install_args+=(--bundle /tmp/nakpanel-release --release-public-key /tmp/nakpanel-release-public.pem)
  if [[ "$4" == 1 ]]; then install_args+=(--allow-development-bundle); fi
fi
if [[ "$5" == 1 ]]; then
  # The historical installer predates --bundle. The host already verified
  # every file and signature before staging this exact trusted artifact.
  chmod 0755 /tmp/nakpanel-release
  timeout 45m /tmp/nakpanel-release/deploy/install/install.sh --yes --bin-dir /tmp/nakpanel-release/bin
else
  timeout 45m deploy/install/install.sh "${install_args[@]}"
fi
systemctl is-active --quiet nakpanel nakpanel-agent nginx postgresql mariadb named stalwart-mail
/usr/local/bin/panelctl version
nginx -t
named-checkconf
sshd -t
REMOTE
VM_IP="$(vm_ip)"
test -n "${VM_IP}"
curl -skf --connect-timeout 5 --max-time 30 "https://${VM_IP}:7443/healthz" >/dev/null
tmpdir="$(mktemp -d)"
trap 'status=$?; rm -rf "${tmpdir}"; exit "${status}"' EXIT
base="https://${VM_IP}:7443"
db(){ multipass_exec_short "${VM_NAME}" -- sudo -u postgres psql -Atqd nakpanel -c "$1" | tr -d '\r'; }
wait_for(){
  local value=""
  for _ in $(seq 1 120); do
    value="$(db "$1")"
    [[ "${value}" == "$2" ]] && return
    sleep 2
  done
  echo "current-install: expected $2, observed ${value:-empty}" >&2; exit 1
}
curl -skfL --max-time 30 -c "${tmpdir}/cookies" -d email=admin@nakpanel.test \
  -d 'password=NakpanelAdmin!2026' "${base}/login" -o "${tmpdir}/login.html"
grep -q 'data-np-role="admin"' "${tmpdir}/login.html"
post(){
  local path="$1" code; shift
  code="$(curl -sk --max-time 30 -b "${tmpdir}/cookies" \
    -H "X-Nakpanel-CSRF: $(csrf_token "${tmpdir}/cookies")" -H 'X-Nakpanel-SPA: true' "$@" \
    -o "${tmpdir}/response" -w '%{http_code}' "${base}/${path}")"
  if [[ "${code}" != 303 && "${code}" != 202 ]]; then
    cat "${tmpdir}/response" >&2
    echo "current-install: ${path} returned ${code}" >&2; exit 1
  fi
}
# The modern native gates need an explicit migrated-runtime/mail/database
# baseline. Create it through product routes, not historical phase fixtures.
subscription_id="$(db "SELECT s.id FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE c.email='admin@nakpanel.test' AND s.status='active' ORDER BY s.id LIMIT 1")"
if [[ -z "${subscription_id}" && "${IMAGE}" == 26.04 ]]; then
  plan_id="$(db "SELECT id FROM plans WHERE reseller_id IS NULL AND lifecycle_status='active' AND default_php_version='8.5' AND php_allowlist='8.5' ORDER BY id LIMIT 1")"
  customer_id="$(db "SELECT id FROM customers WHERE email='admin@nakpanel.test' AND reseller_id IS NULL ORDER BY id LIMIT 1")"
  [[ "${plan_id}" =~ ^[0-9]+$ && "${customer_id}" =~ ^[0-9]+$ ]]
  post subscriptions -d customer_mode=existing -d "customer_id=${customer_id}" -d "plan_id=${plan_id}" -d subscription_name=NativeBootstrap
  subscription_id="$(db "SELECT id FROM subscriptions WHERE customer_id=${customer_id} AND name='NativeBootstrap'")"
  wait_for "SELECT sync_status FROM subscriptions WHERE id=${subscription_id}" in_sync
fi
[[ "${subscription_id}" =~ ^[0-9]+$ ]]
site_id="$(db "SELECT id FROM sites WHERE domain='current-bootstrap.test'")"
if [[ -z "${site_id}" ]]; then
  post sites -d "subscription_id=${subscription_id}" -d domain=current-bootstrap.test -d php_version=${NAKPANEL_BASELINE_PHP} -d issue_certificate=false
  site_id="$(db "SELECT id FROM sites WHERE domain='current-bootstrap.test'")"
fi
[[ "${site_id}" =~ ^[0-9]+$ ]]
wait_for "SELECT status||':'||php_version FROM sites WHERE id=${site_id}" active:${NAKPANEL_BASELINE_PHP}
if [[ "$(db "SELECT count(*) FROM dns_zones WHERE site_id=${site_id}")" == 0 ]]; then
  post dns -d domain=current-bootstrap.test -d "address=${VM_IP}" -d "site_id=${site_id}"
fi
wait_for "SELECT status FROM dns_zones WHERE site_id=${site_id}" active
test -n "$(dig +short "@${VM_IP}" current-bootstrap.test A)"
if [[ "$(db "SELECT tls_status FROM sites WHERE id=${site_id}")" != active ]]; then
  post certificates -d domain=current-bootstrap.test -d issuer=local-self-signed -d "site_id=${site_id}"
fi
wait_for "SELECT tls_status FROM sites WHERE id=${site_id}" active
curl -skf --max-time 20 --resolve "current-bootstrap.test:443:${VM_IP}" https://current-bootstrap.test/ >/dev/null
database_id="$(db "SELECT id FROM databases WHERE db_name='np_current_bootstrap'")"
if [[ -z "${database_id}" ]]; then
  post databases -d "subscription_id=${subscription_id}" -d "site_id=${site_id}" \
    -d db_name=np_current_bootstrap -d db_user=npu_current_bootstrap -d 'password=NakpanelBootstrap_2026'
  database_id="$(db "SELECT id FROM databases WHERE db_name='np_current_bootstrap'")"
fi
[[ "${database_id}" =~ ^[0-9]+$ ]]
wait_for "SELECT status FROM databases WHERE id=${database_id}" active
echo "Current installation verified on ${VM_NAME} (${VM_IP})."
