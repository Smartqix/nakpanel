#!/usr/bin/env bash
# nakpanel unified installer for Ubuntu 24.04.
#
#   Fresh install:  sudo deploy/install/install.sh
#   Upgrade:        sudo deploy/install/install.sh --yes        (auto-detected)
#   Restore (DR):   sudo deploy/install/install.sh --restore ARCHIVE --backup-key-file FILE --yes
#
# The mode is auto-detected from the installed binaries; --fresh/--upgrade
# force it. Upgrades take a full pre-upgrade backup (binaries, units,
# /etc/nakpanel, pg_dump) and roll back automatically when migrations or the
# post-upgrade health gate fail: before the schema migrates the old binaries
# are restored byte-identically, after it migrates the database is restored
# from the pre-upgrade dump (--rollback-schema manual opts into an operator
# handoff instead).
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "install.sh must be run as root" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
cd "${ROOT_DIR}"

export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"

DB_DSN="${NAKPANEL_DATABASE_URL:-postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable}"
HEALTH_URL="${NAKPANEL_HEALTH_URL:-https://127.0.0.1:7443/healthz}"
KEY_FILE="/etc/nakpanel/secret-keys.json"
VERSION_FILE="/etc/nakpanel/version"
UPGRADE_BACKUP_ROOT="/var/lib/nakpanel/upgrade-backups"
UPGRADE_BACKUPS_KEPT=5

MODE=""
BIN_DIR=""
RESTORE_ARCHIVE=""
BACKUP_KEY_FILE=""
ADMIN_EMAIL=""
ADMIN_PASSWORD_FILE=""
FORCE=0
ALLOW_DOWNGRADE=0
ASSUME_YES=0
ROLLBACK_SCHEMA="auto"

usage() {
  cat <<'USAGE'
Usage: install.sh [--fresh|--upgrade] [--bin-dir DIR] [--restore ARCHIVE --backup-key-file FILE]
                  [--admin-email EMAIL --admin-password-file FILE]
                  [--force] [--allow-downgrade] [--yes] [--rollback-schema auto|manual]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fresh) MODE="fresh" ;;
    --upgrade) MODE="upgrade" ;;
    --bin-dir) BIN_DIR="$2"; shift ;;
    --restore) RESTORE_ARCHIVE="$2"; shift ;;
    --backup-key-file) BACKUP_KEY_FILE="$2"; shift ;;
    --admin-email) ADMIN_EMAIL="$2"; shift ;;
    --admin-password-file) ADMIN_PASSWORD_FILE="$2"; shift ;;
    --force) FORCE=1 ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
    --yes) ASSUME_YES=1 ;;
    --rollback-schema) ROLLBACK_SCHEMA="$2"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "install.sh: unknown flag $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

if [[ "${ROLLBACK_SCHEMA}" != "auto" && "${ROLLBACK_SCHEMA}" != "manual" ]]; then
  echo "--rollback-schema must be auto or manual" >&2
  exit 1
fi
if [[ -n "${RESTORE_ARCHIVE}" && -z "${BACKUP_KEY_FILE}" ]]; then
  echo "--restore requires --backup-key-file" >&2
  exit 1
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "install.sh supports Ubuntu 24.04 (detected ${ID:-unknown})" >&2
    exit 1
  fi
  if [[ "${VERSION_ID:-}" != "24.04" ]]; then
    echo "warning: tested on Ubuntu 24.04, detected ${VERSION_ID:-unknown}" >&2
  fi
fi

TARGET_VERSION="$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")"
if [[ -z "${TARGET_VERSION}" ]]; then
  echo "VERSION file is empty" >&2
  exit 1
fi

installed_version=""
if [[ -x /usr/local/bin/panelctl ]]; then
  installed_full="$(/usr/local/bin/panelctl version 2>/dev/null || true)"
  installed_version="${installed_full%%+*}"
fi
if [[ -z "${installed_version}" && -r "${VERSION_FILE}" ]]; then
  installed_version="$(sed -n 's/^version=//p' "${VERSION_FILE}" | head -n1)"
fi
have_binaries=0
if [[ -x /usr/local/bin/nakpanel-panel || -x /usr/local/bin/nakpanel-agent || -x /usr/local/bin/panelctl ]]; then
  have_binaries=1
fi
if [[ -z "${installed_version}" && "${have_binaries}" == "1" ]]; then
  installed_version="unversioned"
fi

if [[ -z "${MODE}" ]]; then
  if [[ "${have_binaries}" == "1" ]]; then
    MODE="upgrade"
  else
    MODE="fresh"
  fi
fi
if [[ "${MODE}" == "fresh" && "${have_binaries}" == "1" && "${FORCE}" != "1" ]]; then
  echo "an existing installation was detected; use --upgrade (or --force to reinstall fresh)" >&2
  exit 1
fi

if [[ "${MODE}" == "upgrade" && -n "${installed_version}" && "${installed_version}" != "unversioned" && "${installed_version}" != "dev" ]]; then
  if [[ "${installed_version}" == "${TARGET_VERSION}" && "${FORCE}" != "1" ]]; then
    echo "nakpanel ${TARGET_VERSION} is already installed; nothing to do (use --force to re-run)"
    exit 0
  fi
  lowest="$(printf '%s\n%s\n' "${installed_version}" "${TARGET_VERSION}" | sort -V | head -n1)"
  if [[ "${lowest}" == "${TARGET_VERSION}" && "${installed_version}" != "${TARGET_VERSION}" && "${ALLOW_DOWNGRADE}" != "1" ]]; then
    echo "refusing downgrade from ${installed_version} to ${TARGET_VERSION} (use --allow-downgrade to override)" >&2
    exit 1
  fi
fi

if [[ "${MODE}" == "upgrade" && "${ASSUME_YES}" != "1" ]]; then
  printf 'Upgrade nakpanel %s -> %s? [y/N] ' "${installed_version:-unknown}" "${TARGET_VERSION}"
  read -r reply
  if [[ "${reply}" != "y" && "${reply}" != "Y" ]]; then
    echo "aborted" >&2
    exit 1
  fi
fi

# Test-only fault injection used by the reliability gate's rollback drills.
maybe_fault() {
  if [[ "${NAKPANEL_INSTALL_FAULT:-}" == "$1" ]]; then
    echo "install.sh: injected fault '$1' (test hook)" >&2
    return 1
  fi
  return 0
}

ensure_build_prereqs() {
  # Migrations run via `make goose-up`/`river-up` (which shell out to `go
  # run`), so make must be present even for --bin-dir installs. curl is used
  # by the Go toolchain download and the health gate.
  if ! command -v make >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    apt-get update
    apt-get install -y make curl ca-certificates
  fi
}

ensure_go_toolchain() {
  local arch goarch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64) goarch="amd64" ;;
    aarch64|arm64) goarch="arm64" ;;
    *) echo "unsupported architecture: ${arch}" >&2; return 1 ;;
  esac
  if ! command -v go >/dev/null 2>&1 || ! go version | grep -Eq 'go1\.(23|24|25|26)'; then
    curl -fsSL --retry 3 --retry-delay 2 "https://go.dev/dl/go1.23.12.linux-${goarch}.tar.gz" -o /tmp/go.tgz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tgz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    rm -f /tmp/go.tgz
  fi
}

build_binaries() {
  local src_owner src_home
  src_owner="$(stat -c %U "${ROOT_DIR}")"
  if [[ "${src_owner}" == "root" ]]; then
    env HOME=/root PATH="${PATH}" make -C "${ROOT_DIR}" build
  else
    src_home="$(getent passwd "${src_owner}" | cut -d: -f6)"
    sudo -u "${src_owner}" env HOME="${src_home:-/tmp}" PATH="${PATH}" make -C "${ROOT_DIR}" build
  fi
}

stage_dir="$(mktemp -d /tmp/nakpanel-install-stage.XXXXXX)"
migration_stage=""

stage_binaries() {
  local source_dir="$1"
  for artifact in panel agent panelctl; do
    if [[ ! -x "${source_dir}/${artifact}" ]]; then
      echo "missing ${source_dir}/${artifact}" >&2
      return 1
    fi
  done
  install -m 0755 "${source_dir}/panel" "${stage_dir}/nakpanel-panel"
  install -m 0755 "${source_dir}/agent" "${stage_dir}/nakpanel-agent"
  install -m 0755 "${source_dir}/panelctl" "${stage_dir}/panelctl"
}

install_agent_and_ctl() {
  install -m 0755 "${stage_dir}/nakpanel-agent" /usr/local/bin/nakpanel-agent
  install -m 0755 "${stage_dir}/panelctl" /usr/local/bin/panelctl
  install -m 0644 "${ROOT_DIR}/deploy/systemd/nakpanel-agent.service" /etc/systemd/system/nakpanel-agent.service
  install -m 0644 "${ROOT_DIR}/deploy/systemd/nakpanel.service" /etc/systemd/system/nakpanel.service
}

install_panel_binary() {
  if [[ "${NAKPANEL_INSTALL_FAULT:-}" == "unhealthy-panel" ]]; then
    # Test hook: install a panel that immediately exits so the health gate
    # times out and the rollback path is exercised end to end.
    printf '#!/bin/sh\nexit 1\n' >/usr/local/bin/nakpanel-panel
    chmod 0755 /usr/local/bin/nakpanel-panel
  else
    install -m 0755 "${stage_dir}/nakpanel-panel" /usr/local/bin/nakpanel-panel
  fi
}

run_component_installers() {
  bash "${SCRIPT_DIR}/phase8-install.sh"
  bash "${SCRIPT_DIR}/phase21-25-install.sh"
  bash "${SCRIPT_DIR}/phase30-install.sh"
}

# The mail installer adds `include "/etc/bind/nakpanel/named.conf"` to BIND's
# config, but that aggregate is only written when the first DNS zone is
# provisioned. Create a valid empty include so named survives a restart on a
# zone-less install (and so the DR restore can start named before reconcile).
ensure_dns_include_target() {
  local aggregate=/etc/bind/nakpanel/named.conf
  install -d -o root -g bind -m 0775 /etc/bind/nakpanel 2>/dev/null || install -d /etc/bind/nakpanel
  if [[ ! -s "${aggregate}" ]]; then
    printf '// Generated by nakpanel. Include this file from /etc/bind/named.conf.local.\n' >"${aggregate}"
  fi
  chgrp bind "${aggregate}" 2>/dev/null || true
  chmod 0644 "${aggregate}"
}

harden_etc_nakpanel() {
  install -d /etc/nakpanel
  chown root:nakpanel /etc/nakpanel
  chmod 0750 /etc/nakpanel
}

# prepare_panel_prerequisites installs just enough (PostgreSQL, the nakpanel
# system user, and its state directory) that the schema can be migrated before
# the component installers start the panel service.
prepare_panel_prerequisites() {
  apt-get update
  apt-get install -y postgresql postgresql-contrib
  systemctl enable --now postgresql
  if ! id nakpanel >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
  fi
  install -d -o nakpanel -g nakpanel -m 0750 /var/lib/nakpanel
}

bootstrap_postgres() {
  if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'nakpanel'" | grep -qx 1; then
    sudo -u postgres createuser nakpanel
  fi
  if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'nakpanel'" | grep -qx 1; then
    sudo -u postgres createdb -O nakpanel nakpanel
  fi
}

bootstrap_secret_key() {
  harden_etc_nakpanel
  if [[ ! -s "${KEY_FILE}" ]]; then
    /usr/local/bin/panelctl secret-key init --path "${KEY_FILE}"
  fi
  chown nakpanel:nakpanel "${KEY_FILE}"
  chmod 0600 "${KEY_FILE}"
}

prepare_migration_root() {
  migration_root="${ROOT_DIR}"
  if ! sudo -u nakpanel test -r "${ROOT_DIR}/go.mod" 2>/dev/null; then
    migration_stage="$(mktemp -d /var/lib/nakpanel/migrate-stage.XXXXXX)"
    cp -a "${ROOT_DIR}/go.mod" "${ROOT_DIR}/go.sum" "${ROOT_DIR}/Makefile" "${migration_stage}/"
    cp -a "${ROOT_DIR}/migrations" "${migration_stage}/migrations"
    [[ -f "${ROOT_DIR}/VERSION" ]] && cp -a "${ROOT_DIR}/VERSION" "${migration_stage}/"
    chown -R nakpanel:nakpanel "${migration_stage}"
    migration_root="${migration_stage}"
  fi
}

run_goose_up() {
  sudo -u nakpanel env HOME=/var/lib/nakpanel PATH="${PATH}" DB_DSN="${DB_DSN}" make -C "${migration_root}" goose-up
}

run_river_up() {
  sudo -u nakpanel env HOME=/var/lib/nakpanel PATH="${PATH}" DB_DSN="${DB_DSN}" make -C "${migration_root}" river-up
}

setup_fail2ban() {
  apt-get install -y fail2ban
  install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d
  install -m 0644 "${ROOT_DIR}/deploy/fail2ban/nakpanel-login.conf" /etc/fail2ban/filter.d/nakpanel-login.conf
  if [[ ! -s /etc/fail2ban/jail.d/nakpanel.local ]]; then
    cat >/etc/fail2ban/jail.d/nakpanel.local <<'EOF'
# Managed by nakpanel. The panel's security settings re-render this file.
[DEFAULT]
banaction = nftables-multiport
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
backend = systemd

[nakpanel-login]
enabled = true
backend = systemd
filter = nakpanel-login
port = 7443
EOF
  fi
  systemctl enable --now fail2ban
  systemctl restart fail2ban
}

ensure_admin() {
  if [[ -z "${ADMIN_EMAIL}" ]]; then
    return 0
  fi
  if [[ -z "${ADMIN_PASSWORD_FILE}" ]]; then
    echo "--admin-email requires --admin-password-file" >&2
    return 1
  fi
  sudo -u nakpanel env NAKPANEL_DATABASE_URL="${DB_DSN}" \
    /usr/local/bin/panelctl --actor installer admin ensure \
    --email "${ADMIN_EMAIL}" --password-file "${ADMIN_PASSWORD_FILE}"
}

health_gate() {
  local expected_version="$1" body version_re
  version_re="${expected_version//./\\.}"
  for _ in $(seq 1 60); do
    body="$(curl --silent --fail --insecure "${HEALTH_URL}" 2>/dev/null || true)"
    if [[ "$(printf '%s\n' "${body}" | head -n1)" == "ok" ]]; then
      if [[ -z "${expected_version}" ]] || printf '%s\n' "${body}" | grep -Eq "^version=${version_re}(\+|$)"; then
        if systemctl is-active --quiet nakpanel-agent.service; then
          return 0
        fi
      fi
    fi
    sleep 2
  done
  return 1
}

write_version_file() {
  local previous="$1" full commit
  full="$(/usr/local/bin/panelctl version 2>/dev/null || echo "${TARGET_VERSION}")"
  commit="unknown"
  if [[ "${full}" == *"+"* ]]; then
    commit="${full#*+}"
  fi
  harden_etc_nakpanel
  cat >"${VERSION_FILE}" <<EOF
version=${TARGET_VERSION}
previous_version=${previous:-none}
commit=${commit}
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  chmod 0644 "${VERSION_FILE}"
}

run_restore() {
  if [[ -z "${RESTORE_ARCHIVE}" ]]; then
    return 0
  fi
  /usr/local/bin/panelctl --actor installer restore-server \
    --archive "${RESTORE_ARCHIVE}" --backup-key-file "${BACKUP_KEY_FILE}" --yes
}

cleanup_stages() {
  rm -rf "${stage_dir}"
  if [[ -n "${migration_stage}" ]]; then
    rm -rf "${migration_stage}"
  fi
}

# ---------------------------------------------------------------------------
# Fresh installation
# ---------------------------------------------------------------------------
fresh_install() {
  trap 'status=$?; cleanup_stages; exit "${status}"' EXIT

  ensure_build_prereqs
  ensure_go_toolchain
  if [[ -n "${BIN_DIR}" ]]; then
    stage_binaries "${BIN_DIR}"
  else
    build_binaries
    stage_binaries "${ROOT_DIR}/bin"
  fi
  install_agent_and_ctl
  install_panel_binary

  # The component installers (phase7) start the panel service, so the database
  # and keyring must be ready first — otherwise the panel boots against an
  # unmigrated database and crashes. Prepare Postgres, the keyring, and the
  # schema before anything starts the panel.
  prepare_panel_prerequisites
  harden_etc_nakpanel
  bootstrap_postgres
  bootstrap_secret_key
  prepare_migration_root
  run_goose_up
  run_river_up

  run_component_installers
  harden_etc_nakpanel
  bootstrap_secret_key
  bash "${SCRIPT_DIR}/phase18-install.sh"
  ensure_dns_include_target
  setup_fail2ban
  ensure_admin

  systemctl daemon-reload
  systemctl enable nakpanel-agent.service nakpanel.service
  systemctl restart nakpanel-agent.service
  systemctl restart nakpanel.service
  if ! health_gate "${TARGET_VERSION}"; then
    echo "install.sh: panel did not become healthy at ${HEALTH_URL}" >&2
    exit 1
  fi
  write_version_file ""
  run_restore
  echo "nakpanel ${TARGET_VERSION} installed successfully."
}

# ---------------------------------------------------------------------------
# Upgrade with pre-upgrade backup and automatic rollback
# ---------------------------------------------------------------------------
backup_dir=""
schema_migrated=0
completed=0
dump_taken=0

backup_if_present() {
  local source="$1" name="$2"
  [[ -e "${source}" ]] && cp -a "${source}" "${backup_dir}/${name}"
  return 0
}

restore_if_present() {
  local backup="$1" destination="$2"
  [[ -e "${backup}" ]] && install -m 0755 "${backup}" "${destination}"
  return 0
}

restore_unit_if_present() {
  local backup="$1" destination="$2"
  [[ -e "${backup}" ]] && cp -a "${backup}" "${destination}"
  return 0
}

take_upgrade_backup() {
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -o root -g nakpanel -m 0750 "${UPGRADE_BACKUP_ROOT}"
  backup_dir="${UPGRADE_BACKUP_ROOT}/${TARGET_VERSION}-${stamp}"
  install -d -o root -g nakpanel -m 0750 "${backup_dir}"
  backup_if_present /usr/local/bin/nakpanel-panel nakpanel-panel
  backup_if_present /usr/local/bin/nakpanel-agent nakpanel-agent
  backup_if_present /usr/local/bin/panelctl panelctl
  backup_if_present /etc/systemd/system/nakpanel.service nakpanel.service
  backup_if_present /etc/systemd/system/nakpanel-agent.service nakpanel-agent.service
  backup_if_present /etc/systemd/system/stalwart-mail.service stalwart-mail.service
  if [[ -d /etc/nakpanel ]]; then
    tar -czf "${backup_dir}/etc-nakpanel.tar.gz" -C /etc nakpanel
  fi
  {
    echo "previous_version=${installed_version:-unknown}"
    echo "target_version=${TARGET_VERSION}"
    echo "created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"${backup_dir}/manifest"
  prune_upgrade_backups
}

# take_upgrade_database_dump is called only once the panel is stopped, so the
# dump is a faithful snapshot of the state a rollback would restore.
take_upgrade_database_dump() {
  local dump="${backup_dir}/nakpanel-before-upgrade.dump"
  sudo -u nakpanel pg_dump --format=custom "${DB_DSN}" >"${dump}"
  # The shell redirect runs as root, so the dump is root:root; group it to
  # nakpanel so the rollback's pg_restore (which runs as the nakpanel role)
  # can read it back.
  chown root:nakpanel "${dump}"
  chmod 0640 "${dump}"
  # A dump that cannot be listed cannot be restored. Finding that out here,
  # while the old database is still intact, is the difference between an
  # aborted upgrade and an unrecoverable one.
  if ! sudo -u nakpanel pg_restore --list "${dump}" >/dev/null 2>&1; then
    echo "install.sh: pre-upgrade dump is unreadable; refusing to migrate" >&2
    return 1
  fi
  dump_taken=1
}

prune_upgrade_backups() {
  local dir count=0
  # Newest first by name-embedded timestamp fallback to mtime via ls -t.
  while IFS= read -r dir; do
    count=$((count + 1))
    if [[ "${count}" -gt "${UPGRADE_BACKUPS_KEPT}" ]]; then
      rm -rf "${UPGRADE_BACKUP_ROOT:?}/${dir}"
    fi
  done < <(ls -1t "${UPGRADE_BACKUP_ROOT}" 2>/dev/null)
}

restore_previous_files() {
  restore_if_present "${backup_dir}/nakpanel-panel" /usr/local/bin/nakpanel-panel
  restore_if_present "${backup_dir}/nakpanel-agent" /usr/local/bin/nakpanel-agent
  restore_if_present "${backup_dir}/panelctl" /usr/local/bin/panelctl
  restore_unit_if_present "${backup_dir}/nakpanel.service" /etc/systemd/system/nakpanel.service
  restore_unit_if_present "${backup_dir}/nakpanel-agent.service" /etc/systemd/system/nakpanel-agent.service
  restore_unit_if_present "${backup_dir}/stalwart-mail.service" /etc/systemd/system/stalwart-mail.service
  if [[ -e "${backup_dir}/etc-nakpanel.tar.gz" ]]; then
    tar -xzf "${backup_dir}/etc-nakpanel.tar.gz" -C /etc || {
      echo "install.sh: could not restore /etc/nakpanel from the backup set" >&2
      return 1
    }
  fi
  return 0
}

rollback_database_from_dump() {
  local dump="${backup_dir}/nakpanel-before-upgrade.dump"
  # Never drop a live database before proving the replacement is restorable:
  # if this check fails there is nothing to roll back to, and the running
  # database (already migrated, but intact) is the better of the two states.
  if [[ "${dump_taken}" != "1" || ! -s "${dump}" ]]; then
    echo "install.sh: no usable pre-upgrade dump; leaving the database untouched" >&2
    return 1
  fi
  if ! sudo -u nakpanel pg_restore --list "${dump}" >/dev/null 2>&1; then
    echo "install.sh: pre-upgrade dump is unreadable; leaving the database untouched" >&2
    return 1
  fi
  systemctl stop nakpanel.service 2>/dev/null || true
  systemctl stop nakpanel-agent.service 2>/dev/null || true
  # Give lingering connections a moment to drain; dropdb --force terminates
  # whatever remains (Stalwart's read-only directory connections included).
  for _ in $(seq 1 5); do
    remaining="$(sudo -u postgres psql -tAc "SELECT count(*) FROM pg_stat_activity WHERE datname='nakpanel'" 2>/dev/null || echo 0)"
    [[ "${remaining}" == "0" ]] && break
    sleep 2
  done
  sudo -u postgres dropdb --force --if-exists nakpanel
  sudo -u postgres createdb -O nakpanel nakpanel
  if ! sudo -u nakpanel pg_restore --exit-on-error -d "${DB_DSN}" "${dump}"; then
    echo "install.sh: CRITICAL: pre-upgrade database restore FAILED." >&2
    echo "install.sh: the database is empty; restore manually from ${dump}" >&2
    return 1
  fi
}

cleanup_upgrade() {
  local status=$?
  if [[ "${completed}" != "1" ]]; then
    echo "install.sh: upgrade failed; applying automatic recovery" >&2
    if [[ "${schema_migrated}" == "0" ]]; then
      if [[ -n "${backup_dir}" && -d "${backup_dir}" ]]; then
        # Never let a failure inside recovery abort the trap before the
        # services are restarted and the operator is told what happened.
        restore_previous_files || echo "install.sh: some files could not be restored from ${backup_dir}" >&2
        echo "install.sh: pre-migration failure; previous installation restored from ${backup_dir}" >&2
      else
        echo "install.sh: pre-migration failure before any backup was taken; nothing was changed." >&2
      fi
      systemctl daemon-reload || true
      systemctl restart nakpanel-agent.service || true
      systemctl restart nakpanel.service || true
    elif [[ "${ROLLBACK_SCHEMA}" == "auto" ]]; then
      echo "install.sh: post-migration failure; restoring database from pre-upgrade dump" >&2
      if ! rollback_database_from_dump; then
        echo "install.sh: database rollback did not run; the new schema is still in place." >&2
        echo "install.sh: keeping the new binaries (older ones cannot serve the migrated schema)." >&2
        install -m 0755 "${stage_dir}/nakpanel-panel" /usr/local/bin/nakpanel-panel 2>/dev/null || true
        install -m 0755 "${stage_dir}/nakpanel-agent" /usr/local/bin/nakpanel-agent 2>/dev/null || true
        install -m 0755 "${stage_dir}/panelctl" /usr/local/bin/panelctl 2>/dev/null || true
        systemctl daemon-reload || true
        systemctl restart nakpanel-agent.service || true
        systemctl restart nakpanel.service || true
        echo "install.sh: backup set: ${backup_dir:-<none>} (see docs/RECOVERY.md)" >&2
        cleanup_stages
        exit "${status}"
      fi
      restore_previous_files
      systemctl daemon-reload || true
      systemctl restart nakpanel-agent.service || true
      systemctl restart nakpanel.service || true
      if [[ -n "${installed_version}" && "${installed_version}" != "unversioned" ]] && health_gate "${installed_version}"; then
        echo "install.sh: rollback complete; nakpanel ${installed_version} is healthy again" >&2
      else
        echo "install.sh: rollback did not converge; operator attention required." >&2
        echo "install.sh: backup set: ${backup_dir} (see docs/RECOVERY.md)" >&2
      fi
    else
      # Manual mode: the schema has committed, so keep the new binaries (the
      # old ones are incompatible with the migrated schema) and hand off.
      install -m 0755 "${stage_dir}/nakpanel-panel" /usr/local/bin/nakpanel-panel || true
      install -m 0755 "${stage_dir}/nakpanel-agent" /usr/local/bin/nakpanel-agent || true
      install -m 0755 "${stage_dir}/panelctl" /usr/local/bin/panelctl || true
      systemctl daemon-reload || true
      systemctl restart nakpanel-agent.service || true
      systemctl restart nakpanel.service || true
      echo "install.sh: schema migrated before the failure; new binaries kept." >&2
      echo "install.sh: backup set: ${backup_dir} (see docs/RECOVERY.md)" >&2
    fi
  fi
  cleanup_stages
  exit "${status}"
}

upgrade_install() {
  trap cleanup_upgrade EXIT

  ensure_build_prereqs
  ensure_go_toolchain
  if [[ -n "${BIN_DIR}" ]]; then
    stage_binaries "${BIN_DIR}"
  else
    build_binaries
    stage_binaries "${ROOT_DIR}/bin"
  fi

  # Back up the binaries/units/config first so a failure during the component
  # installers can still be undone. The database dump is deliberately NOT
  # taken here: the component installers below restart the panel, and a dump
  # taken before minutes of live customer writes would silently discard them
  # if the rollback ever replayed it.
  take_upgrade_backup

  systemctl stop nakpanel.service 2>/dev/null || true
  install_agent_and_ctl
  systemctl daemon-reload
  systemctl restart nakpanel-agent.service

  maybe_fault before-migrate

  run_component_installers
  ensure_dns_include_target
  harden_etc_nakpanel
  bootstrap_secret_key
  setup_fail2ban

  # The panel is stopped here and stays stopped until the health gate, so the
  # database is genuinely quiescent for the dump and the migrations. Only now
  # is a dump a faithful rollback target.
  systemctl stop nakpanel.service 2>/dev/null || true
  take_upgrade_database_dump

  prepare_migration_root
  run_goose_up
  schema_migrated=1
  run_river_up
  # Runs after migrations so the Stalwart directory views exist before their
  # SELECT grant is applied; on the pre-migration ordering the grant was
  # silently skipped and mail auth broke after the upgrade.
  bash "${SCRIPT_DIR}/phase18-install.sh"
  sudo -u nakpanel env \
    NAKPANEL_DATABASE_URL="${DB_DSN}" \
    NAKPANEL_SECRET_KEY_FILE="${KEY_FILE}" \
    /usr/local/bin/panelctl secret-key migrate --path "${KEY_FILE}"

  maybe_fault after-migrate

  install_panel_binary
  systemctl enable nakpanel-agent.service nakpanel.service
  systemctl restart nakpanel.service

  if ! health_gate "${TARGET_VERSION}"; then
    echo "install.sh: panel did not become healthy on ${TARGET_VERSION}" >&2
    exit 1
  fi
  write_version_file "${installed_version}"
  # Set last: until the version file is written the upgrade is not complete,
  # and the trap must still be allowed to recover.
  completed=1
  echo "nakpanel upgraded to ${TARGET_VERSION} successfully. Backup: ${backup_dir}"
}

if [[ "${MODE}" == "fresh" ]]; then
  fresh_install
else
  upgrade_install
fi
