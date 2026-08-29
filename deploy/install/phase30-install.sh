#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "phase30-install.sh must be run as root" >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "phase30-install.sh requires Ubuntu 24.04" >&2
  exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
  echo "phase30-install.sh supports Ubuntu 24.04 only (detected ${ID:-unknown} ${VERSION_ID:-unknown})" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

PHP_VERSIONS=(8.3 8.4 8.5)
if [[ -n "${NAKPANEL_PHP_VERSIONS:-}" ]]; then
  read -r -a PHP_VERSIONS <<<"${NAKPANEL_PHP_VERSIONS}"
fi
if [[ "${#PHP_VERSIONS[@]}" -eq 0 ]]; then
  echo "NAKPANEL_PHP_VERSIONS requested no PHP runtimes" >&2
  exit 1
fi
for version in "${PHP_VERSIONS[@]}"; do
  case "${version}" in
    8.3|8.4|8.5) ;;
    *) echo "unsupported requested PHP runtime: ${version}" >&2; exit 1 ;;
  esac
done

apt-get update
apt-get install -y ca-certificates curl gnupg software-properties-common
add-apt-repository --yes ppa:ondrej/php

# Ubuntu 24.04 writes PPA sources in deb822 format. Refuse a source that does
# not bind its signing key, rather than accepting an implicitly trusted PPA.
ppa_source="$(grep -Rils 'ppa.launchpadcontent.net/ondrej/php' /etc/apt/sources.list.d | head -n1 || true)"
if [[ -z "${ppa_source}" ]] || ! grep -qsE '^(Signed-By:|deb .*signed-by=)' "${ppa_source}"; then
  echo "ppa:ondrej/php was added without a Signed-By key binding" >&2
  exit 1
fi

apt-get update
packages=()
for version in "${PHP_VERSIONS[@]}"; do
  packages+=(
    "php${version}-cli"
    "php${version}-fpm"
    "php${version}-bcmath"
    "php${version}-curl"
    "php${version}-gd"
    "php${version}-imagick"
    "php${version}-intl"
    "php${version}-mbstring"
    "php${version}-mysql"
    "php${version}-redis"
    "php${version}-soap"
    "php${version}-xml"
    "php${version}-zip"
    "php${version}-common"
    "php${version}-opcache"
    "php${version}-readline"
    "php${version}-apcu"
  )
done
apt-get install -y "${packages[@]}"

COMPOSER_VERSION=2.8.11
WP_CLI_VERSION=2.12.0
artifact_dir="$(mktemp -d /tmp/nakpanel-phase30-artifacts.XXXXXX)"
cleanup() {
  rm -rf "${artifact_dir}"
}
trap cleanup EXIT

curl -fsSL --retry 3 --retry-delay 2 \
  "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar" \
  -o "${artifact_dir}/composer.phar"
curl -fsSL --retry 3 --retry-delay 2 \
  "https://getcomposer.org/download/${COMPOSER_VERSION}/composer.phar.sha256sum" \
  -o "${artifact_dir}/composer.phar.sha256sum"
(cd "${artifact_dir}" && sha256sum --check composer.phar.sha256sum)

curl -fsSL --retry 3 --retry-delay 2 \
  "https://github.com/wp-cli/wp-cli/releases/download/v${WP_CLI_VERSION}/wp-cli-${WP_CLI_VERSION}.phar" \
  -o "${artifact_dir}/wp-cli-${WP_CLI_VERSION}.phar"
curl -fsSL --retry 3 --retry-delay 2 \
  "https://github.com/wp-cli/wp-cli/releases/download/v${WP_CLI_VERSION}/wp-cli-${WP_CLI_VERSION}.phar.sha512" \
  -o "${artifact_dir}/wp-cli-${WP_CLI_VERSION}.phar.sha512"
wp_cli_sha512="$(tr -d '[:space:]' <"${artifact_dir}/wp-cli-${WP_CLI_VERSION}.phar.sha512")"
if [[ ! "${wp_cli_sha512}" =~ ^[a-f0-9]{128}$ ]]; then
  echo "WP-CLI ${WP_CLI_VERSION} supplied a malformed SHA-512 digest" >&2
  exit 1
fi
printf '%s  %s\n' "${wp_cli_sha512}" "wp-cli-${WP_CLI_VERSION}.phar" >"${artifact_dir}/wp-cli.sha512.check"
(cd "${artifact_dir}" && sha512sum --check wp-cli.sha512.check)

install -d -o root -g root -m 0755 /usr/local/lib/nakpanel /etc/wp-cli
install -o root -g root -m 0555 "${artifact_dir}/composer.phar" /usr/local/lib/nakpanel/composer.phar
install -o root -g root -m 0555 "${artifact_dir}/wp-cli-${WP_CLI_VERSION}.phar" /usr/local/lib/nakpanel/wp-cli.phar
chmod 0555 /usr/local/lib/nakpanel/composer.phar /usr/local/lib/nakpanel/wp-cli.phar

cat >/usr/local/bin/composer <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  case "${arg}" in
    self-update|selfupdate)
      echo "composer self-update is disabled; use the nakpanel installer" >&2
      exit 64
      ;;
  esac
done
exec /usr/bin/php /usr/local/lib/nakpanel/composer.phar "$@"
EOF
chown root:root /usr/local/bin/composer
chmod 0755 /usr/local/bin/composer

cat >/usr/local/bin/wp <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
saw_cli=0
for arg in "$@"; do
  if [[ "${arg}" == "cli" ]]; then
    saw_cli=1
  elif [[ "${saw_cli}" == "1" && "${arg}" == "update" ]]; then
    echo "wp cli update is disabled; use the nakpanel installer" >&2
    exit 64
  fi
done
export WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1
exec /usr/bin/php /usr/local/lib/nakpanel/wp-cli.phar "$@"
EOF
chown root:root /usr/local/bin/wp
chmod 0755 /usr/local/bin/wp

cat >/etc/wp-cli/config.yml <<'EOF'
color: false
EOF
chown root:root /etc/wp-cli/config.yml
chmod 0644 /etc/wp-cli/config.yml

required_extensions=(
  bcmath curl dom exif fileinfo gd imagick intl mbstring mysqli openssl redis
  SimpleXML soap xml zip "Zend OPcache"
)

validate_php_runtime() {
  local version="$1" php fpm config loaded actual extension
  php="$(command -v "php${version}" || true)"
  fpm="$(command -v "php-fpm${version}" || true)"
  if [[ -z "${php}" || -z "${fpm}" ]]; then
    echo "PHP ${version} is incomplete: CLI or FPM binary is missing" >&2
    return 1
  fi
  actual="$("${php}" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
  if [[ "${actual}" != "${version}" ]]; then
    echo "PHP ${version} CLI reported ${actual:-no version}" >&2
    return 1
  fi
  loaded="$("${php}" -r 'foreach (array_merge(get_loaded_extensions(), get_loaded_extensions(true)) as $extension) { echo $extension, PHP_EOL; }')"
  for extension in "${required_extensions[@]}"; do
    if ! grep -Fqix "${extension}" <<<"${loaded}"; then
      echo "PHP ${version} is missing required extension ${extension}" >&2
      return 1
    fi
  done
  config="$(mktemp "/tmp/nakpanel-php${version}-fpm.XXXXXX.conf")"
  cat >"${config}" <<EOF
[global]
pid = ${config}.pid
error_log = /dev/stderr
daemonize = no

[nakpanel-probe]
user = www-data
group = www-data
listen = ${config}.sock
pm = static
pm.max_children = 1
EOF
  if ! "${fpm}" -t -y "${config}"; then
    echo "PHP ${version} FPM rejected the isolated validation config" >&2
    rm -f "${config}"
    return 1
  fi
  rm -f "${config}"
}

for version in "${PHP_VERSIONS[@]}"; do
  validate_php_runtime "${version}"
done

composer_version="$(composer --no-plugins --no-scripts --version --no-ansi)"
if [[ ! "${composer_version}" =~ Composer\ version\ 2\. ]]; then
  echo "Composer 2 validation failed: ${composer_version}" >&2
  exit 1
fi
wp_version="$(wp --version --allow-root)"
if [[ "${wp_version}" != "WP-CLI ${WP_CLI_VERSION}" ]]; then
  echo "WP-CLI validation failed: ${wp_version}" >&2
  exit 1
fi

echo "Phase 30 PHP runtimes, Composer, and WP-CLI are installed and validated."
