#!/usr/bin/env bash
# Sourcing has no side effects. Parent platform selection owns fresh enrollment;
# later upgrades may refresh this source only for the already recorded profile.
sury_prepare_source() (
  set -euo pipefail
  [[ "${1:-}" == ubuntu-26.04-sury ]] || { echo 'explicit ubuntu-26.04-sury profile required' >&2; exit 1; }
  [[ "${EUID}" == 0 ]] || { echo 'Sury source preparation requires root' >&2; exit 1; }
  local architecture here work name
  here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  for name in python3 curl gpgv install mv cmp dpkg mktemp rm cat; do command -v "${name}" >/dev/null || { echo "Sury source preparation requires ${name}" >&2; exit 1; }; done
  python3 "${here}/sury_verify.py" identity /etc/os-release
  architecture="$(dpkg --print-architecture)"
  [[ "${architecture}" == amd64 || "${architecture}" == arm64 ]] || { echo 'unsupported Sury host architecture' >&2; exit 1; }
  python3 "${here}/sury_verify.py" key "${here}/sury-php-archive-keyring.gpg"
  work="$(mktemp -d /tmp/nakpanel-sury-source.XXXXXX)"
  trap 'rm -rf "${work}"' EXIT
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 https://packages.sury.org/debsuryorg-archive-keyring.deb -o "${work}/keyring.deb"
  # Do not dpkg-install: upstream keyring package also adds global APT trust.
  python3 "${here}/sury_verify.py" extract-key "${work}/keyring.deb" "${work}/sury.gpg"
  cmp "${here}/sury-php-archive-keyring.gpg" "${work}/sury.gpg"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 https://packages.sury.org/php/dists/resolute/InRelease -o "${work}/InRelease"
  gpgv --status-fd 1 --keyring "${work}/sury.gpg" "${work}/InRelease" > "${work}/signature.status"
  python3 "${here}/sury_verify.py" status "${work}/signature.status"
  python3 "${here}/sury_verify.py" release "${work}/InRelease" "${architecture}"
  cat > "${work}/source" <<'EOF'
Types: deb
URIs: https://packages.sury.org/php/
Suites: resolute
Components: main
Architectures: amd64 arm64
Signed-By: /usr/share/keyrings/nakpanel-sury-php.gpg
EOF
  cat > "${work}/preferences" <<'EOF'
Package: php-common php8.3-* php8.4-* php8.5-*
Pin: release o=deb.sury.org,n=resolute
Pin-Priority: 500

Package: *
Pin: origin packages.sury.org
Pin-Priority: -1
EOF
  # Activate source last: every earlier step is read-only, and scoped preferences
  # plus the verified repository-specific key exist before APT can use it.
  install -d -o root -g root -m0755 /usr/share/keyrings /etc/apt/preferences.d /etc/apt/sources.list.d
  install -o root -g root -m0644 "${work}/sury.gpg" "/usr/share/keyrings/nakpanel-sury-php.gpg.new.$$"
  mv -f "/usr/share/keyrings/nakpanel-sury-php.gpg.new.$$" /usr/share/keyrings/nakpanel-sury-php.gpg
  install -o root -g root -m0644 "${work}/preferences" "/etc/apt/preferences.d/nakpanel-php-resolute.new.$$"
  mv -f "/etc/apt/preferences.d/nakpanel-php-resolute.new.$$" /etc/apt/preferences.d/nakpanel-php-resolute
  install -o root -g root -m0644 "${work}/source" "/etc/apt/sources.list.d/nakpanel-php-resolute.sources.new.$$"
  mv -f "/etc/apt/sources.list.d/nakpanel-php-resolute.sources.new.$$" /etc/apt/sources.list.d/nakpanel-php-resolute.sources
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  [[ "${1:-}" == prepare && "$#" == 2 ]] || { echo 'usage: sury.sh prepare ubuntu-26.04-sury' >&2; exit 2; }
  sury_prepare_source "$2"
fi
