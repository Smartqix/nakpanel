#!/usr/bin/env bash
# Resolute's upstream webmail pin. Noble keeps its existing distribution package.
NAKPANEL_ROUNDCUBE_VERSION=1.6.19
NAKPANEL_ROUNDCUBE_SHA256=c47fd99cd7cbb7aee2557d8ca614a4c51e91f6fa3767ca4ce32c6126f9ebff5b
NAKPANEL_ROUNDCUBE_KEY_SHA256=6cd4ac8548ca5a374408d0b45b652d97014a6674ddf467b06d969a9e7e3e312b

nakpanel_verify_roundcube_release() {
  local archive="$1" signature="$2" keyring hash key
  hash="$(python3 - "${archive}" <<'PY'
import hashlib, sys
with open(sys.argv[1], 'rb') as stream: print(hashlib.sha256(stream.read()).hexdigest())
PY
)"
  [[ "${hash}" == "${NAKPANEL_ROUNDCUBE_SHA256}" ]] || { echo 'Roundcube SHA-256 differs from pinned upstream release' >&2; return 1; }
  key="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/roundcube-release-key.asc"
  hash="$(python3 - "${key}" <<'PY'
import hashlib, sys
with open(sys.argv[1], 'rb') as stream: print(hashlib.sha256(stream.read()).hexdigest())
PY
)"
  [[ "${hash}" == "${NAKPANEL_ROUNDCUBE_KEY_SHA256}" ]] || { echo 'Roundcube signing key differs from pin' >&2; return 1; }
  keyring="$(mktemp -d /tmp/nakpanel-roundcube-gpg.XXXXXX)"
  chmod 0700 "${keyring}"
  if ! gpg --batch --homedir "${keyring}" --import "${key}" >/dev/null 2>&1 ||
     ! gpg --batch --homedir "${keyring}" --verify "${signature}" "${archive}"; then
    rm -rf "${keyring}"
    echo 'Roundcube signature verification failed' >&2
    return 1
  fi
  rm -rf "${keyring}"
}

nakpanel_prepare_roundcube_artifact() {
  local base archive signature
  if [[ -z "${NAKPANEL_ROUNDCUBE_STAGE:-}" ]]; then
    NAKPANEL_ROUNDCUBE_STAGE="$(mktemp -d /tmp/nakpanel-roundcube.XXXXXX)"
    chmod 0700 "${NAKPANEL_ROUNDCUBE_STAGE}"
  fi
  archive="${NAKPANEL_ROUNDCUBE_STAGE}/roundcube.tar.gz"
  signature="${archive}.asc"
  base="https://github.com/roundcube/roundcubemail/releases/download/${NAKPANEL_ROUNDCUBE_VERSION}/roundcubemail-${NAKPANEL_ROUNDCUBE_VERSION}-complete.tar.gz"
  if [[ ! -s "${archive}" || ! -s "${signature}" ]]; then
    curl -fSL --retry 3 --proto '=https' "${base}" -o "${archive}"
    curl -fSL --retry 3 --proto '=https' "${base}.asc" -o "${signature}"
  fi
  nakpanel_verify_roundcube_release "${archive}" "${signature}" || return 1
  export NAKPANEL_ROUNDCUBE_STAGE
}

nakpanel_install_roundcube() (
  set -euo pipefail
  local own_stage=0 archive target unpack
  [[ -n "${NAKPANEL_ROUNDCUBE_STAGE:-}" ]] || own_stage=1
  nakpanel_prepare_roundcube_artifact
  archive="${NAKPANEL_ROUNDCUBE_STAGE}/roundcube.tar.gz"
  target="/opt/nakpanel/roundcube/${NAKPANEL_ROUNDCUBE_VERSION}"
  unpack="$(mktemp -d /tmp/nakpanel-roundcube-unpack.XXXXXX)"
  trap 'status=$?; rm -rf "${unpack}"; if [[ "${own_stage}" == 1 ]]; then rm -rf "${NAKPANEL_ROUNDCUBE_STAGE}"; fi; exit "${status}"' EXIT
  # Verify archive layout before even the temporary extraction.
  python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/archive_policy.py" "${archive}" "roundcubemail-${NAKPANEL_ROUNDCUBE_VERSION}"
  tar -xzf "${archive}" --strip-components=1 --no-same-owner -C "${unpack}"
  rm -rf "${unpack}/installer"
  install -d -o root -g root -m 0755 /opt/nakpanel/roundcube /usr/share
  install -d -o root -g www-data -m 0750 /etc/roundcube
  install -d -o www-data -g www-data -m 0750 /var/lib/roundcube /var/lib/roundcube/temp /var/log/roundcube
  if [[ ! -e "${target}" ]]; then
    chown -R root:root "${unpack}"
    chmod -R u=rwX,go=rX "${unpack}"
    mv "${unpack}" "${target}"
  fi
  if [[ -e /usr/share/roundcube && ! -L /usr/share/roundcube ]]; then
    echo 'refusing to replace an existing unmanaged Roundcube directory' >&2; exit 1
  fi
  ln -sfn "${target}" /usr/share/roundcube
  if [[ ! -e /etc/roundcube/debian-db-roundcube.php ]]; then
    cat >/etc/roundcube/debian-db-roundcube.php <<'PHP'
<?php
$config['db_dsnw'] = 'sqlite:////var/lib/roundcube/roundcube.sqlite';
$config['temp_dir'] = '/var/lib/roundcube/temp';
$config['log_dir'] = '/var/log/roundcube';
PHP
    chown root:www-data /etc/roundcube/debian-db-roundcube.php
    chmod 0640 /etc/roundcube/debian-db-roundcube.php
  fi
  if [[ ! -e /var/lib/roundcube/roundcube.sqlite ]]; then
    sqlite3 /var/lib/roundcube/roundcube.sqlite <"${target}/SQL/sqlite.initial.sql"
    chown www-data:www-data /var/lib/roundcube/roundcube.sqlite
    chmod 0660 /var/lib/roundcube/roundcube.sqlite
  fi
  ln -sfn /etc/roundcube/config.inc.php "${target}/config/config.inc.php"
  "/usr/bin/php${NAKPANEL_INTERNAL_PHP_VERSION}" -l "${target}/program/lib/Roundcube/bootstrap.php"
)
