#!/usr/bin/env bash
# Shared installation contract. Ubuntu metadata is parsed as data, never sourced.

nakpanel_os_release_value() {
  awk -F= -v key="$2" '$1 == key { value=substr($0,length(key)+2); gsub(/^["\047]|["\047]$/, "", value); print value; exit }' "$1"
}

nakpanel_load_platform() {
  local metadata="${1:-/etc/os-release}" arch="${2:-}"
  [[ -r "${metadata}" ]] || { echo "platform: missing OS metadata: ${metadata}" >&2; return 1; }
  NAKPANEL_OS_ID="$(nakpanel_os_release_value "${metadata}" ID)"
  NAKPANEL_OS_VERSION="$(nakpanel_os_release_value "${metadata}" VERSION_ID)"
  NAKPANEL_OS_CODENAME="$(nakpanel_os_release_value "${metadata}" VERSION_CODENAME)"
  if [[ -z "${arch}" ]]; then
    arch="$(dpkg --print-architecture)" || return 1
  fi
  case "${arch}" in amd64|arm64) NAKPANEL_PLATFORM_ARCH="${arch}" ;; *) echo "platform: unsupported architecture ${arch}" >&2; return 1 ;; esac
  case "${NAKPANEL_OS_ID}/${NAKPANEL_OS_VERSION}/${NAKPANEL_OS_CODENAME}" in
    ubuntu/26.04/resolute)
      NAKPANEL_PLATFORM_ID=ubuntu-26.04-sury
      NAKPANEL_INTERNAL_PHP_VERSION=8.5
      NAKPANEL_HOSTING_PHP_VERSIONS=(8.3 8.4 8.5)
      # PostgreSQL18 itself provides contrib; the old metapackage is absent.
      NAKPANEL_POSTGRES_PACKAGES=(postgresql postgresql-18)
      ;;
    *) echo "platform: unsupported OS ${NAKPANEL_OS_ID:-unknown} ${NAKPANEL_OS_VERSION:-unknown} ${NAKPANEL_OS_CODENAME:-unknown}; require Ubuntu 26.04/resolute" >&2; return 1 ;;
  esac
  export NAKPANEL_PLATFORM_ID NAKPANEL_PLATFORM_ARCH NAKPANEL_INTERNAL_PHP_VERSION
  NAKPANEL_PLATFORM_PHP_PROVIDER=sury
}

nakpanel_select_php_provider() {
  case "${1:-sury}" in
    native)
      NAKPANEL_PLATFORM_ID=ubuntu-26.04-native
      NAKPANEL_HOSTING_PHP_VERSIONS=(8.5)
      ;;
    sury)
      [[ "${NAKPANEL_OS_VERSION}" == 26.04 && "${NAKPANEL_OS_CODENAME}" == resolute ]] || {
        echo 'platform: the Surý provider requires Ubuntu 26.04/resolute' >&2; return 1;
      }
      NAKPANEL_PLATFORM_ID=ubuntu-26.04-sury
      NAKPANEL_HOSTING_PHP_VERSIONS=(8.3 8.4 8.5)
      ;;
    *) echo 'platform: PHP provider must be native or sury' >&2; return 1 ;;
  esac
  NAKPANEL_PLATFORM_PHP_PROVIDER="${1:-sury}"
}

# Only an existing trusted record can select an installed optional provider.
# Environment variables never enroll a machine or rewrite a profile.
nakpanel_installed_php_provider() {
  python3 - "$1" <<'PY'
import json, os, stat, sys
try:
    info = os.lstat(sys.argv[1])
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('installation state must be a root-owned regular file without group/world writes')
    with open(sys.argv[1]) as stream: data = json.load(stream)
    profile = data.get('profile')
    if profile not in ('ubuntu-26.04-native', 'ubuntu-26.04-sury'):
        raise ValueError('unknown installed profile')
    print('sury' if profile == 'ubuntu-26.04-sury' else 'native')
except (OSError, ValueError, AttributeError) as error:
    sys.exit('platform: ' + str(error))
PY
}

nakpanel_check_platform_state() {
  local state="${1:-/etc/nakpanel/platform.json}"
  [[ -e "${state}" || -L "${state}" ]] || return 0
  python3 - "${state}" "${NAKPANEL_OS_ID}" "${NAKPANEL_OS_VERSION}" "${NAKPANEL_OS_CODENAME}" "${NAKPANEL_PLATFORM_ARCH}" "${NAKPANEL_PLATFORM_ID}" "${NAKPANEL_INTERNAL_PHP_VERSION}" "${NAKPANEL_HOSTING_PHP_VERSIONS[@]}" <<'PY'
import json, os, stat, sys
try:
    path, osid, version, codename, arch, profile, php, *hosting = sys.argv[1:]
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('installation state must be a root-owned regular file without group/world writes')
    with open(path) as stream:
        actual = json.load(stream)
    expected = dict(os_id=osid, version_id=version, codename=codename, architecture=arch,
                    profile=profile, internal_php_version=php, hosting_php_versions=hosting)
    if any(actual.get(key) != value for key, value in expected.items()):
        raise ValueError('installed OS/profile differs from host; in-place OS upgrade is unsupported')
    if 'bootstrap_pending' in actual and type(actual['bootstrap_pending']) is not bool:
        raise ValueError('invalid platform bootstrap marker')
except (OSError, ValueError, TypeError, AttributeError) as error:
    print('platform: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY
}

nakpanel_platform_bootstrap_pending() {
  local state="${1:-/etc/nakpanel/platform.json}"
  python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/platform_state.py" pending "${state}"
}

nakpanel_require_platform() {
  nakpanel_load_platform /etc/os-release || return 1
  local provider=sury requested="${1:-}"
  if [[ -e /etc/nakpanel/platform.json || -L /etc/nakpanel/platform.json ]]; then
    provider="$(nakpanel_installed_php_provider /etc/nakpanel/platform.json)" || return 1
    if [[ -n "${requested}" && "${requested}" != "${provider}" ]]; then
      echo 'platform: changing the installed PHP provider is unsupported; use a fresh target and reviewed migration' >&2
      return 1
    fi
  elif [[ -n "${requested}" ]]; then
    provider="${requested}"
  fi
  nakpanel_select_php_provider "${provider}" || return 1
  nakpanel_check_platform_state /etc/nakpanel/platform.json || return 1
  local binaries=0 database=0 observed
  if [[ "${NAKPANEL_OS_VERSION}" == 26.04 && ! -e /etc/nakpanel/platform.json ]]; then
    if [[ -e /usr/local/bin/nakpanel-panel || -e /usr/local/bin/nakpanel-agent || -e /usr/local/bin/panelctl ]]; then binaries=1; fi
    if command -v psql >/dev/null 2>&1 && id postgres >/dev/null 2>&1; then
      if ! observed="$(sudo -u postgres psql -XqtAc "SELECT 1 FROM pg_database WHERE datname='nakpanel'" 2>/dev/null)"; then
        echo 'platform: cannot establish absence of an existing panel database' >&2
        return 1
      fi
      [[ "${observed//[[:space:]]/}" != 1 ]] || database=1
    fi
  fi
  nakpanel_check_legacy_installation /etc/nakpanel/platform.json "${binaries}" "${database}"
}

nakpanel_check_legacy_installation() {
  local state="$1" binaries="$2" database="$3"
  if [[ "${NAKPANEL_OS_VERSION}" == 26.04 && ! -e "${state}" ]] &&
     [[ "${binaries}" != 0 || "${database}" != 0 ]]; then
    echo 'platform: existing unrecorded installation on Resolute; an in-place OS upgrade is unsupported; use qualified forward migration' >&2
    return 1
  fi
}

nakpanel_write_platform_state() {
  local pending="${1:-false}" state=/etc/nakpanel/platform.json
  [[ "${pending}" == true || "${pending}" == false ]] || return 1
  python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/platform_state.py" "${pending}" "${NAKPANEL_OS_ID}" "${NAKPANEL_OS_VERSION}" "${NAKPANEL_OS_CODENAME}" "${NAKPANEL_PLATFORM_ARCH}" "${NAKPANEL_PLATFORM_ID}" "${NAKPANEL_INTERNAL_PHP_VERSION}" "${NAKPANEL_HOSTING_PHP_VERSIONS[@]}"
}

nakpanel_php_packages() {
  local version extension
  for version in "${NAKPANEL_HOSTING_PHP_VERSIONS[@]}"; do
    for extension in cli fpm bcmath curl gd imagick intl mbstring mysql redis soap xml zip common readline apcu; do
      printf 'php%s-%s\n' "${version}" "${extension}"
    done
  done
  printf 'php%s-sqlite3\n' "${NAKPANEL_INTERNAL_PHP_VERSION}"
}

nakpanel_preflight_host() {
  python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/host_preflight.py" "${NAKPANEL_PLATFORM_ID}"
}

nakpanel_preflight_packages() {
  local package candidate policy
  local required=("${NAKPANEL_POSTGRES_PACKAGES[@]}" mariadb-server nginx bind9 adminer ufw
    acl ca-certificates curl python3 gnupg clamav clamav-freshclam quota goaccess
    openssh-server proftpd-core proftpd-mod-crypto podman slirp4netns uidmap skopeo jq git
    fuse-overlayfs mariadb-client netcat-openbsd redis-tools sqlite3)
  while IFS= read -r package; do required+=("${package}"); done < <(nakpanel_php_packages)
  for package in "${required[@]}"; do
    # Consume the producer completely: apt-cache can otherwise receive SIGPIPE
    # when awk exits at Candidate under the installer's pipefail setting.
    policy="$(apt-cache policy "${package}")"
    candidate="$(awk '/^[[:space:]]*Candidate:/ {print $2; exit}' <<<"${policy}")"
    [[ -n "${candidate}" && "${candidate}" != '(none)' ]] || {
      echo "platform: required package has no candidate: ${package}" >&2; return 1;
    }
    if ! python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/package_policy.py" "${NAKPANEL_OS_CODENAME}" "${NAKPANEL_PLATFORM_PHP_PROVIDER}" "${package}" <<<"${policy}"; then
      echo "platform: unapproved candidate for ${package}" >&2
      return 1
    fi
  done
  apt-get --simulate install --no-install-recommends "${required[@]}" >/dev/null
  printf 'platform: package transaction resolved for %s/%s\n' "${NAKPANEL_PLATFORM_ID}" "${NAKPANEL_PLATFORM_ARCH}"
}

nakpanel_prepare_package_sources() {
  apt-get update
  # Bootstrap only signed distribution tooling, before replacing app files or DBs.
  apt-get install -y --no-install-recommends ca-certificates curl gnupg python3
  if [[ "${NAKPANEL_PLATFORM_ID}" == ubuntu-26.04-sury ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/sury.sh"
    sury_prepare_source ubuntu-26.04-sury
    apt-get update
  fi
  nakpanel_preflight_packages
}
