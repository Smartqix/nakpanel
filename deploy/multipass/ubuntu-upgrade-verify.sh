#!/usr/bin/env bash
# Genuine prior-release upgrade on Noble. Resolute is the first supported
# native release; its cell also proves a populated same-profile update.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
assert_current_vm_identity
: "${NAKPANEL_PRIOR_RELEASE_BUNDLE:?real prior release bundle is required}"
: "${NAKPANEL_PRIOR_RELEASE_PUBLIC_KEY:?prior release trust anchor is required}"
: "${NAKPANEL_PRIOR_RELEASE_VERSION:?prior application version is required}"
: "${NAKPANEL_RELEASE_BUNDLE:?candidate bundle is required}"
: "${NAKPANEL_RELEASE_PUBLIC_KEY:?candidate trust anchor is required}"
: "${NAKPANEL_RELEASE_VERSION:?candidate application version is required}"
prior_args=(--bundle "${NAKPANEL_PRIOR_RELEASE_BUNDLE}" --public-key "${NAKPANEL_PRIOR_RELEASE_PUBLIC_KEY}" --version "${NAKPANEL_PRIOR_RELEASE_VERSION}" --architecture "${NAKPANEL_MULTIPASS_ARCH}")
if [[ "${NAKPANEL_PRIOR_RELEASE_ALLOW_DEVELOPMENT:-0}" == 1 ]]; then prior_args+=(--allow-development); fi
python3 "${ROOT_DIR}/deploy/release/verify.py" "${prior_args[@]}"
python3 - "${NAKPANEL_PRIOR_RELEASE_BUNDLE}/manifest.json" "${NAKPANEL_RELEASE_BUNDLE}/manifest.json" <<'PY'
import json,sys
prior,current=[json.load(open(p)) for p in sys.argv[1:]]
assert prior['files'] != current['files'], 'prior and candidate artifacts must differ'
assert prior['commit']!=current['commit'] or current.get('development') is True, 'production prior release must have a distinct source commit'
PY
candidate_bundle="${NAKPANEL_RELEASE_BUNDLE}"
candidate_key="${NAKPANEL_RELEASE_PUBLIC_KEY}"
candidate_version="${NAKPANEL_RELEASE_VERSION}"
candidate_development="${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}"
upgrade_existing() {
  assert_current_vm_identity
  local workdir archive
  workdir="$(mktemp -d)"
  COPYFILE_DISABLE=1 tar -C "${candidate_bundle}" -cf "${workdir}/candidate.tar" .
  multipass transfer "${workdir}/candidate.tar" "${NAKPANEL_MULTIPASS_VM}:/tmp/nakpanel-candidate.tar"
  multipass transfer "${candidate_key}" "${NAKPANEL_MULTIPASS_VM}:/tmp/nakpanel-candidate-public.pem"
  rm -rf "${workdir}"
  sync_repo "${ROOT_DIR}"
  multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -se -- "${NAKPANEL_REMOTE_SRC}" "${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-0}" "${candidate_version}" <<'REMOTE'
set -euo pipefail
src="$1"
test ! -e /tmp/nakpanel-candidate
install -d -m 0700 /tmp/nakpanel-candidate
tar --no-same-owner -xf /tmp/nakpanel-candidate.tar -C /tmp/nakpanel-candidate
username=$(sudo -u postgres psql -Atqd nakpanel -c "SELECT a.username FROM subscription_system_accounts a JOIN sites s ON s.subscription_id=a.subscription_id WHERE s.domain='current-bootstrap.test'")
test -n "$username"
canary="/home/$username/domains/current-bootstrap.test/public_html/real-upgrade-canary.txt"
printf 'real-prior-upgrade-canary\n' >"$canary"
chown "$username:$username" "$canary"
mariadb np_current_bootstrap -e "CREATE TABLE IF NOT EXISTS real_upgrade_canary (value TEXT); DELETE FROM real_upgrade_canary; INSERT INTO real_upgrade_canary VALUES ('retained-real-prior-data')"
export NAKPANEL_RELEASE_ALLOW_DEVELOPMENT="$2"
args=(--yes --upgrade --force --bundle /tmp/nakpanel-candidate --release-public-key /tmp/nakpanel-candidate-public.pem)
if [[ "$2" == 1 ]]; then args+=(--allow-development-bundle); fi
# --force applies only to a populated upgrade (development builds may share
# VERSION). It is never added to the clean install gate.
"$src/deploy/install/install.sh" "${args[@]}"
installed_version="$(/usr/local/bin/panelctl version)"
test "${installed_version%%+*}" = "$3"
for artifact in panel agent panelctl; do
  installed="/usr/local/bin/$artifact"
  case "$artifact" in panel) installed=/usr/local/bin/nakpanel-panel;; agent) installed=/usr/local/bin/nakpanel-agent;; esac
  test "$(sha256sum /tmp/nakpanel-candidate/bin/"$artifact" | cut -d ' ' -f1)" = "$(sha256sum "$installed" | cut -d ' ' -f1)"
done
grep -Fxq real-prior-upgrade-canary "$canary"
test "$(mariadb -N np_current_bootstrap -e 'SELECT value FROM real_upgrade_canary')" = retained-real-prior-data
systemctl is-active --quiet nakpanel nakpanel-agent nginx mariadb postgresql named stalwart-mail
find /var/lib/nakpanel/upgrade-backups -type f -name '*.dump' | grep . >/dev/null
REMOTE
  local ip
  ip="$(vm_ip)"
  curl -skf --max-time 30 "https://${ip}:7443/healthz"
  curl -sf --max-time 30 -H 'Host: current-bootstrap.test' "http://${ip}/real-upgrade-canary.txt" | grep -Fxq real-prior-upgrade-canary
}
# Real historical upgrade always uses the OS that prior Nakpanel supported.
(
  # The historical guest may need its own pinned Noble cloud image even
  # when the native qualification source uses the Resolute alias/image.
  if [[ "${NAKPANEL_MULTIPASS_IMAGE}" == 24.04 ]]; then
    export NAKPANEL_MULTIPASS_IMAGE_SOURCE="${NAKPANEL_PRIOR_MULTIPASS_IMAGE_SOURCE:-${NAKPANEL_MULTIPASS_IMAGE_SOURCE:-}}"
    export NAKPANEL_MULTIPASS_IMAGE_SHA256="${NAKPANEL_PRIOR_MULTIPASS_IMAGE_SHA256:-${NAKPANEL_MULTIPASS_IMAGE_SHA256:-}}"
  else
    export NAKPANEL_MULTIPASS_IMAGE_SOURCE="${NAKPANEL_PRIOR_MULTIPASS_IMAGE_SOURCE:-}"
    export NAKPANEL_MULTIPASS_IMAGE_SHA256="${NAKPANEL_PRIOR_MULTIPASS_IMAGE_SHA256:-}"
  fi
  export NAKPANEL_MULTIPASS_IMAGE=24.04
  export NAKPANEL_QUALIFICATION_PHP_PROVIDER=native
  source "${SCRIPT_DIR}/common.sh"
  export NAKPANEL_MULTIPASS_VM="${NAKPANEL_MULTIPASS_SOURCE_VM:-${NAKPANEL_MULTIPASS_VM}}-prior24"
  if multipass info "${NAKPANEL_MULTIPASS_VM}" >/dev/null 2>&1; then echo 'prior release gate requires a fresh unique VM' >&2; exit 1; fi
  export NAKPANEL_RELEASE_BUNDLE="${NAKPANEL_PRIOR_RELEASE_BUNDLE}"
  export NAKPANEL_RELEASE_PUBLIC_KEY="${NAKPANEL_PRIOR_RELEASE_PUBLIC_KEY}"
  export NAKPANEL_RELEASE_VERSION="${NAKPANEL_PRIOR_RELEASE_VERSION}"
  export NAKPANEL_RELEASE_ALLOW_DEVELOPMENT="${NAKPANEL_PRIOR_RELEASE_ALLOW_DEVELOPMENT:-0}"
  export NAKPANEL_RELEASE_LEGACY_INSTALLER=1
  "${SCRIPT_DIR}/current-install-verify.sh"
  export NAKPANEL_RELEASE_ALLOW_DEVELOPMENT="${candidate_development}"
  upgrade_existing
  if [[ "${NAKPANEL_QUALIFICATION_RECLAIM_PRIOR:-0}" == 1 ]]; then
    destroy_owned_vm "${NAKPANEL_MULTIPASS_VM}" "${NAKPANEL_RUN_TOKEN}"
  fi
)
if [[ "${NAKPANEL_MULTIPASS_IMAGE}" == 26.04 ]]; then
  upgrade_existing
  echo 'PASS native26 populated candidate update; genuine historical upgrade executed on prior-supported24'
else
  echo 'PASS genuine populated prior release upgrade on24'
fi
