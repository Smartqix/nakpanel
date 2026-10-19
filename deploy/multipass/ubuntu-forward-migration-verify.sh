#!/usr/bin/env bash
# Isolated logical-transfer rehearsal. Publishing support requires reviewed
# native installation and data/protocol evidence for this exact fixture.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Validate every local input and driver capability before any Multipass action.
: "${NAKPANEL_FORWARD_ARCHIVE:?NAKPANEL_FORWARD_ARCHIVE is required}"
: "${NAKPANEL_FORWARD_KEY:?NAKPANEL_FORWARD_KEY is required}"
: "${NAKPANEL_FORWARD_TARGET_BUNDLE:?NAKPANEL_FORWARD_TARGET_BUNDLE signed directory is required}"
: "${NAKPANEL_FORWARD_TARGET_PUBLIC_KEY:?out-of-band target public key is required}"
: "${NAKPANEL_FORWARD_TARGET_VERSION:?exact target application version is required}"
export NAKPANEL_FORWARD_ALLOW_DEVELOPMENT="${NAKPANEL_FORWARD_ALLOW_DEVELOPMENT:-0}"
export NAKPANEL_FORWARD_FIXTURE_DRIVER="${NAKPANEL_FORWARD_FIXTURE_DRIVER:-${SCRIPT_DIR}/ubuntu-forward-migration-fixture.py}"
: "${NAKPANEL_MULTIPASS_SOURCE_VM:?owned source VM is required}"
: "${NAKPANEL_RUN_TOKEN:?explicit ownership run token is required}"
: "${NAKPANEL_MULTIPASS_ARCH:?explicit architecture is required}"
[[ -f "${NAKPANEL_FORWARD_ARCHIVE}" && -s "${NAKPANEL_FORWARD_KEY}" && -d "${NAKPANEL_FORWARD_TARGET_BUNDLE}" && -s "${NAKPANEL_FORWARD_TARGET_PUBLIC_KEY}" && -x "${NAKPANEL_FORWARD_FIXTURE_DRIVER}" ]] || { echo 'archive, key, signed target bundle, public key or executable fixture driver missing' >&2; exit 1; }
DRIVER="${NAKPANEL_FORWARD_FIXTURE_DRIVER}"
if [[ "${DRIVER}" == "${SCRIPT_DIR}/ubuntu-forward-migration-fixture.py" ]]; then
  : "${NAKPANEL_FORWARD_FIXTURE_JSON:?NAKPANEL_FORWARD_FIXTURE_JSON prepared private bundle is required}"
  "${DRIVER}" --validate "${NAKPANEL_FORWARD_FIXTURE_JSON}"
fi
capabilities="$("${DRIVER}" --capabilities)"
for capability in fixture-v1 install-native-target assert-source-readonly assert-baseline assert-migration-data assert-services assert-trusted-tls assert-reboot assert-no-source-writes; do
  grep -Fxq -- "${capability}" <<<"${capabilities}" || { echo "fixture driver lacks ${capability}; migration rehearsal unavailable" >&2; exit 1; }
done

# Seal and verify the signed target before even a source ownership probe. A
# changed original directory cannot replace this private authenticated copy.
STAGED_TARGET="$(python3 "${SCRIPT_DIR}/ubuntu-forward-migration-fixture.py" --stage-target-bundle "${NAKPANEL_FORWARD_TARGET_BUNDLE}" "${NAKPANEL_FORWARD_TARGET_PUBLIC_KEY}" "${NAKPANEL_FORWARD_TARGET_VERSION}" "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_FORWARD_ALLOW_DEVELOPMENT}")"
export NAKPANEL_FORWARD_TARGET_BUNDLE="${STAGED_TARGET}/bundle"
export NAKPANEL_FORWARD_TARGET_PUBLIC_KEY="${STAGED_TARGET}/public.pem"
created=0
cleanup() {
  local result=$?
  # Retain failed target guests for diagnosis. Never delete source/archive/key.
  if [[ "${created}" == 1 && "${result}" == 0 && "${NAKPANEL_FORWARD_KEEP_TARGET:-0}" != 1 ]]; then
    destroy_owned_vm "${NAKPANEL_MULTIPASS_VM}" "${NAKPANEL_RUN_TOKEN}" || result=1
  fi
  python3 "${SCRIPT_DIR}/ubuntu-forward-migration-fixture.py" --discard-target-bundle "${STAGED_TARGET}" || result=1
  exit "${result}"
}
trap cleanup EXIT

# Source-run environments may pin a Noble cloud image. A new target uses the
# Resolute alias or its own explicitly verified image, never the source image.
export NAKPANEL_MULTIPASS_IMAGE=26.04
export NAKPANEL_MULTIPASS_IMAGE_SOURCE="${NAKPANEL_FORWARD_TARGET_IMAGE_SOURCE:-}"
export NAKPANEL_MULTIPASS_IMAGE_SHA256="${NAKPANEL_FORWARD_TARGET_IMAGE_SHA256:-}"
source "${SCRIPT_DIR}/common.sh"
export NAKPANEL_MULTIPASS_VM="${NAKPANEL_MULTIPASS_DR_VM:-nakpanel-migration-${NAKPANEL_MULTIPASS_ARCH}-${NAKPANEL_RUN_TOKEN}}"
export NAKPANEL_MULTIPASS_DR_VM="${NAKPANEL_MULTIPASS_VM}"
assert_distinct_vm_names "${NAKPANEL_MULTIPASS_SOURCE_VM}" "${NAKPANEL_MULTIPASS_VM}"
validate_run_identity "${NAKPANEL_RUN_TOKEN}"
assert_disposable_name "${NAKPANEL_MULTIPASS_VM}"
require_multipass
assert_vm_identity "${NAKPANEL_MULTIPASS_SOURCE_VM}" 24.04 "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}"

umask 077
EVIDENCE="${NAKPANEL_FORWARD_EVIDENCE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/nakpanel-migration-evidence.XXXXXX")}"
mkdir -p "${EVIDENCE}"
chmod 700 "${EVIDENCE}"
fixture_sequence=0
fixture() {
  local stage="$1"
  assert_vm_identity "${NAKPANEL_MULTIPASS_SOURCE_VM}" 24.04 "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}"
  if [[ "${created}" == 1 ]]; then assert_vm_identity "${NAKPANEL_MULTIPASS_VM}" 26.04 "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}"; fi
  fixture_sequence=$((fixture_sequence + 1))
  "${DRIVER}" "${stage}" "${NAKPANEL_MULTIPASS_VM}" "${NAKPANEL_MULTIPASS_SOURCE_VM}" "${NAKPANEL_RUN_TOKEN}" "${NAKPANEL_FORWARD_TARGET_BUNDLE}" "${EVIDENCE}" >"${EVIDENCE}/${fixture_sequence}-${stage}.log" 2>&1
}
multipass_exec_short "${NAKPANEL_MULTIPASS_SOURCE_VM}" -- sudo bash -se <<'SOURCE_VERSIONS' >"${EVIDENCE}/source-versions.log"
set -euo pipefail
runuser -u postgres -- psql -Atqc 'SHOW server_version' | grep -E '^16\.'
mariadb -NBe 'SELECT VERSION()' | grep -E '^10\.11\.'
SOURCE_VERSIONS
fixture assert-source-readonly
# Refuse reuse: target must be a new ephemeral VM for this rehearsal.
if multipass info "${NAKPANEL_MULTIPASS_VM}" >/dev/null 2>&1; then echo 'migration target already exists; choose a new token/name' >&2; exit 1; fi
ensure_vm 4 8G 40G
created=1
fixture install-native-target
assert_vm_identity "${NAKPANEL_MULTIPASS_VM}" 26.04 "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}"

# The fixture must seed routines/events, nondefault collations, tenant grants,
# encrypted credentials, numeric identities, workers, OCI digest/volume state,
# real mail messages and trusted TLS. Driver comparisons verify this baseline.
fixture assert-baseline
REMOTE_DIR="/tmp/nakpanel-migration-${NAKPANEL_RUN_TOKEN}"
multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- mkdir -m 700 "${REMOTE_DIR}"
multipass transfer "${NAKPANEL_FORWARD_ARCHIVE}" "${NAKPANEL_MULTIPASS_VM}:${REMOTE_DIR}/source.nkbk"
multipass transfer "${NAKPANEL_FORWARD_KEY}" "${NAKPANEL_MULTIPASS_VM}:${REMOTE_DIR}/archive.key"
multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -se -- "${REMOTE_DIR}" <<'PREFLIGHT' >"${EVIDENCE}/preflight.json"
set -euo pipefail
chmod 700 "$1"
chmod 600 "$1/archive.key" "$1/source.nkbk"
chown -R root:root "$1"
# Real target observations, not package-name assumptions.
pg_restore --version >&2
runuser -u postgres -- psql -Atqc 'SHOW server_version' | grep -E '^18\.' >&2
mariadb -NBe 'SELECT VERSION()' | grep -E '^11\.8\.' >&2
panelctl restore-server --mode forward-migration --check-only --archive "$1/source.nkbk" --backup-key-file "$1/archive.key"
PREFLIGHT
# A missing source 8.3/8.4, mismatched Stalwart, old database client, incomplete
# provenance, or architecture mismatch stops above, before restore mutation.
multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo panelctl restore-server --mode forward-migration --experimental-forward-migration --yes --json --archive "${REMOTE_DIR}/source.nkbk" --backup-key-file "${REMOTE_DIR}/archive.key" >"${EVIDENCE}/restore.json"
multipass_exec_short "${NAKPANEL_MULTIPASS_VM}" -- sudo rm -f "${REMOTE_DIR}/archive.key"

validate_native_services() {
  assert_vm_identity "${NAKPANEL_MULTIPASS_VM}" 26.04 "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}"
  multipass exec "${NAKPANEL_MULTIPASS_VM}" -- sudo bash -se <<'VALIDATE'
set -euo pipefail
nginx -t
named-checkconf
sshd -t
proftpd -t -c /etc/nakpanel/proftpd/proftpd.conf
for fpm in /usr/sbin/php-fpm[0-9]*; do test -x "${fpm}"; "${fpm}" -t; done
systemctl is-active --quiet nakpanel.service nakpanel-agent.service nginx.service named.service stalwart-mail.service nakpanel-proftpd.service postgresql.service mariadb.service
quota_target="$(findmnt -n -o TARGET --target /home)"
quota_state="$(quotaon -p "${quota_target}" 2>&1 || true)"
grep -Eq 'user quota .* is on' <<<"${quota_state}"
VALIDATE
}
validate_native_services >"${EVIDENCE}/native-services.log" 2>&1
fixture assert-migration-data
fixture assert-services
fixture assert-trusted-tls
# Reboot is an independent persistence gate after all transfer checks pass.
assert_vm_identity "${NAKPANEL_MULTIPASS_VM}" 26.04 "${NAKPANEL_MULTIPASS_ARCH}" "${NAKPANEL_RUN_TOKEN}"
multipass restart "${NAKPANEL_MULTIPASS_VM}"
wait_for_cloud_init "${NAKPANEL_MULTIPASS_VM}"
validate_native_services >"${EVIDENCE}/after-reboot-services.log" 2>&1
fixture assert-reboot
fixture assert-migration-data
fixture assert-trusted-tls
fixture assert-no-source-writes
printf 'Forward migration rehearsal gates passed; evidence requires independent review: %s\n' "${EVIDENCE}"
