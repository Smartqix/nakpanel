#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/common.sh"
VM_NAME="${NAKPANEL_MULTIPASS_VM}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE}"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"

if [[ "${NAKPANEL_SKIP_PRIOR_PHASES:-0}" != "1" ]]; then
  "${ROOT_DIR}/deploy/multipass/phase16-verify.sh"
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
rm -rf /tmp/nakpanel-phase17-certs
mkdir -p /tmp/nakpanel-phase17-certs
cd /tmp/nakpanel-phase17-certs
openssl ecparam -genkey -name prime256v1 -out root.key
openssl req -x509 -new -key root.key -sha256 -days 365 -subj '/CN=Nakpanel Phase17 Root' -out root.crt \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl ecparam -genkey -name prime256v1 -out intermediate.key
openssl req -new -key intermediate.key -subj '/CN=Nakpanel Phase17 Intermediate' -out intermediate.csr
cat > intermediate.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial -days 180 -sha256 -extfile intermediate.ext -out intermediate.crt
openssl ecparam -genkey -name prime256v1 -out site.key
openssl req -new -key site.key -subj '/CN=phase15-account.test' -out site.csr
cat > site.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:phase15-account.test
EOF
openssl x509 -req -in site.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -days 10 -sha256 -extfile site.ext -out site.crt
openssl ecparam -genkey -name prime256v1 -out wrong.key
chmod 0644 site.crt intermediate.crt
chmod 0600 site.key wrong.key
sudo chown nakpanel:nakpanel site.key wrong.key
sudo install -m 0644 root.crt /usr/local/share/ca-certificates/nakpanel-phase17-root.crt
sudo update-ca-certificates
sudo systemctl restart nakpanel-agent.service nakpanel.service
REMOTE

db_value() {
  multipass exec "${VM_NAME}" -- sudo -u postgres psql -d nakpanel -tAc "$1" | tr -d '[:space:]'
}
cli() {
  multipass exec "${VM_NAME}" -- sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
    panelctl --actor phase17-verifier "$@"
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

multipass exec "${VM_NAME}" -- sudo systemctl stop nakpanel.service
cli ssl set-custom phase15-account.test --cert /tmp/nakpanel-phase17-certs/site.crt \
  --key /tmp/nakpanel-phase17-certs/site.key --chain /tmp/nakpanel-phase17-certs/intermediate.crt --yes | grep -Fq 'Custom certificate queued'
staging_path="$(db_value "SELECT args->>'staging_path' FROM river_job WHERE kind='install_custom_cert' ORDER BY id DESC LIMIT 1")"
[[ -n "${staging_path}" ]]
multipass exec "${VM_NAME}" -- bash -c "test \"\$(sudo stat -c '%U:%G:%a' '${staging_path}')\" = nakpanel:nakpanel:600"
[[ "$(db_value "SELECT COUNT(*) FROM river_job WHERE kind='install_custom_cert' AND (args ? 'certificate_pem' OR args ? 'private_key_pem' OR args ? 'chain_pem')")" == "0" ]]
multipass exec "${VM_NAME}" -- sudo systemctl start nakpanel.service
wait_for_value "SELECT tls_issuer||':'||tls_status||':'||tls_auto_renew FROM sites WHERE domain='phase15-account.test'" 'custom:active:false'
cert_path="$(db_value "SELECT tls_cert_path FROM sites WHERE domain='phase15-account.test'")"
key_path="$(db_value "SELECT tls_key_path FROM sites WHERE domain='phase15-account.test'")"
multipass exec "${VM_NAME}" -- bash -c "test \"\$(sudo stat -c '%a' '${cert_path}')\" = 600"
multipass exec "${VM_NAME}" -- bash -c "test \"\$(sudo stat -c '%a' '${key_path}')\" = 600"
multipass exec "${VM_NAME}" -- bash -c "test \"\$(sudo stat -c '%U:%G' '${cert_path}')\" = root:root"
multipass exec "${VM_NAME}" -- bash -c "test \"\$(sudo stat -c '%U:%G' '${key_path}')\" = root:root"
multipass exec "${VM_NAME}" -- bash -c "echo | openssl s_client -connect 127.0.0.1:443 -servername phase15-account.test 2>/dev/null | openssl x509 -noout -ext subjectAltName" | grep -Fq 'phase15-account.test'

before_cert="$(multipass exec "${VM_NAME}" -- sudo sha256sum "${cert_path}" | awk '{print $1}')"
before_key="$(multipass exec "${VM_NAME}" -- sudo sha256sum "${key_path}" | awk '{print $1}')"
if cli ssl set-custom phase15-account.test --cert /tmp/nakpanel-phase17-certs/site.crt \
  --key /tmp/nakpanel-phase17-certs/wrong.key --chain /tmp/nakpanel-phase17-certs/intermediate.crt --yes >/tmp/phase17-invalid.out 2>&1; then
  echo 'mismatched custom certificate key was accepted' >&2
  exit 1
fi
grep -Fq 'does not match certificate' /tmp/phase17-invalid.out
[[ "$(multipass exec "${VM_NAME}" -- sudo sha256sum "${cert_path}" | awk '{print $1}')" == "${before_cert}" ]]
[[ "$(multipass exec "${VM_NAME}" -- sudo sha256sum "${key_path}" | awk '{print $1}')" == "${before_key}" ]]

sudo_restart_output="$(multipass exec "${VM_NAME}" -- sudo systemctl restart nakpanel.service 2>&1)" || { echo "${sudo_restart_output}" >&2; exit 1; }
wait_for_value "SELECT COUNT(*) FROM notifications WHERE kind='certificate_expiring' AND resolved_at IS NULL AND customer_id=(SELECT customer_id FROM sites WHERE domain='phase15-account.test')" '1'
[[ "$(db_value "SELECT COUNT(*) FROM river_job WHERE args::text LIKE '%PRIVATE KEY%'")" == "0" ]]
[[ "$(db_value "SELECT COUNT(*) FROM audit_events WHERE metadata::text LIKE '%PRIVATE KEY%'")" == "0" ]]
[[ "$(db_value "SELECT COUNT(*) FROM river_job WHERE kind='issue_cert' AND args->>'issuer'='custom'")" == "0" ]]

VM_IP="$(vm_ip)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
curl -sk --fail -c "${tmpdir}/cookies" -L -d 'email=admin@nakpanel.test' -d 'password=NakpanelAdmin!2026' "https://${VM_IP}:7443/login" >/dev/null
site_id="$(db_value "SELECT id FROM sites WHERE domain='phase15-account.test'")"
curl -sk --fail -b "${tmpdir}/cookies" "https://${VM_IP}:7443/sites/${site_id}?tab=ssl" | grep -Fq 'Upload custom certificate'

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail
cd "${NAKPANEL_REMOTE_SRC:-/tmp/nakpanel-src}"
go test ./internal/certificates ./internal/agent/ops ./internal/control/provision ./internal/control/http ./cmd/panelctl -count=1
REMOTE
echo "Phase 17 custom TLS verification passed for ${VM_NAME} (${VM_IP})."
