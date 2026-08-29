#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "phase26-install.sh must be run as root" >&2
  exit 1
fi

ROOT_DIR="${NAKPANEL_SOURCE_DIR:-$(pwd -P)}"
DB_DSN="${NAKPANEL_DATABASE_URL:-postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable}"
HEALTH_URL="${NAKPANEL_HEALTH_URL:-https://127.0.0.1:7443/healthz}"
KEY_FILE="${NAKPANEL_SECRET_KEY_FILE:-/etc/nakpanel/secret-keys.json}"
KEY_DIR="$(dirname "${KEY_FILE}")"

if [[ "${KEY_DIR}" != "/etc/nakpanel" || "$(basename "${KEY_FILE}")" != "secret-keys.json" ]]; then
  echo "NAKPANEL_SECRET_KEY_FILE must be /etc/nakpanel/secret-keys.json for the privileged installer" >&2
  exit 1
fi

for artifact in panel agent panelctl; do
  if [[ ! -x "${ROOT_DIR}/bin/${artifact}" ]]; then
    echo "missing ${ROOT_DIR}/bin/${artifact}; run make build first" >&2
    exit 1
  fi
done

id nakpanel >/dev/null 2>&1 || {
  echo "nakpanel system user is required" >&2
  exit 1
}

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/lib/nakpanel/upgrade-backups/phase26-${stamp}"
stage_dir="$(mktemp -d /var/lib/nakpanel/phase26-stage.XXXXXX)"
schema_migrated=0
secrets_migrated=0
completed=0

backup_if_present() {
  local source="$1" name="$2"
  [[ -e "${source}" ]] && cp -a "${source}" "${backup_dir}/${name}"
}

restore_if_present() {
  local backup="$1" destination="$2"
  [[ -e "${backup}" ]] && install -m 0755 "${backup}" "${destination}"
}

cleanup() {
  local status=$?
  if [[ "${completed}" != "1" ]]; then
    echo "Phase 26 installation failed; applying the safest available recovery." >&2
    if [[ "${schema_migrated}" == "0" ]]; then
      restore_if_present "${backup_dir}/nakpanel-panel" /usr/local/bin/nakpanel-panel
      restore_if_present "${backup_dir}/nakpanel-agent" /usr/local/bin/nakpanel-agent
      restore_if_present "${backup_dir}/panelctl" /usr/local/bin/panelctl
      [[ -e "${backup_dir}/nakpanel.service" ]] && cp -a "${backup_dir}/nakpanel.service" /etc/systemd/system/nakpanel.service
      [[ -e "${backup_dir}/nakpanel-agent.service" ]] && cp -a "${backup_dir}/nakpanel-agent.service" /etc/systemd/system/nakpanel-agent.service
    else
      # The database schema has committed even if secret migration failed.
      # Older binaries are not compatible with that state, so retain the full
      # Phase 26 binary set and leave recovery to the operator.
      install -m 0755 "${stage_dir}/nakpanel-panel" /usr/local/bin/nakpanel-panel || true
      install -m 0755 "${stage_dir}/nakpanel-agent" /usr/local/bin/nakpanel-agent || true
      install -m 0755 "${stage_dir}/panelctl" /usr/local/bin/panelctl || true
    fi
    systemctl daemon-reload || true
    systemctl restart nakpanel-agent.service || true
    systemctl restart nakpanel.service || true
  fi
  rm -rf "${stage_dir}"
  exit "${status}"
}
trap cleanup EXIT

install -d -o root -g nakpanel -m 0750 "${backup_dir}"
backup_if_present /usr/local/bin/nakpanel-panel nakpanel-panel
backup_if_present /usr/local/bin/nakpanel-agent nakpanel-agent
backup_if_present /usr/local/bin/panelctl panelctl
backup_if_present /etc/systemd/system/nakpanel.service nakpanel.service
backup_if_present /etc/systemd/system/nakpanel-agent.service nakpanel-agent.service
backup_if_present "${KEY_FILE}" secret-keys.json
sudo -u nakpanel pg_dump --format=custom "${DB_DSN}" >"${backup_dir}/nakpanel-before-phase26.dump"
chmod 0640 "${backup_dir}/nakpanel-before-phase26.dump"

install -m 0755 "${ROOT_DIR}/bin/panel" "${stage_dir}/nakpanel-panel"
install -m 0755 "${ROOT_DIR}/bin/agent" "${stage_dir}/nakpanel-agent"
install -m 0755 "${ROOT_DIR}/bin/panelctl" "${stage_dir}/panelctl"

systemctl stop nakpanel.service
install -m 0755 "${stage_dir}/nakpanel-agent" /usr/local/bin/nakpanel-agent
install -m 0755 "${stage_dir}/panelctl" /usr/local/bin/panelctl
install -m 0644 "${ROOT_DIR}/deploy/systemd/nakpanel-agent.service" /etc/systemd/system/nakpanel-agent.service
install -m 0644 "${ROOT_DIR}/deploy/systemd/nakpanel.service" /etc/systemd/system/nakpanel.service

install -d -o root -g nakpanel -m 0750 "${KEY_DIR}"
if [[ ! -s "${KEY_FILE}" ]]; then
  /usr/local/bin/panelctl secret-key init --path "${KEY_FILE}"
fi
chown nakpanel:nakpanel "${KEY_FILE}"
chmod 0600 "${KEY_FILE}"

systemctl daemon-reload
systemctl restart nakpanel-agent.service

sudo -u nakpanel env DB_DSN="${DB_DSN}" make -C "${ROOT_DIR}" goose-up
schema_migrated=1
sudo -u nakpanel env \
  NAKPANEL_DATABASE_URL="${DB_DSN}" \
  NAKPANEL_SECRET_KEY_FILE="${KEY_FILE}" \
  /usr/local/bin/panelctl secret-key migrate --path "${KEY_FILE}"
secrets_migrated=1

install -m 0755 "${stage_dir}/nakpanel-panel" /usr/local/bin/nakpanel-panel
systemctl enable nakpanel-agent.service nakpanel.service
systemctl restart nakpanel.service

for _ in $(seq 1 60); do
  if curl --silent --show-error --fail --insecure "${HEALTH_URL}" | grep -q "ok"; then
    completed=1
    echo "Phase 26 installed successfully. Backup: ${backup_dir}"
    exit 0
  fi
  sleep 2
done

echo "Phase 26 health check did not become ready: ${HEALTH_URL}" >&2
exit 1
