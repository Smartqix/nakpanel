#!/usr/bin/env bash
set -euo pipefail
umask 077

# Standalone opt-in installer. Does not alter the panel or public nginx services.
[[ ${EUID} -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ ${1:-} == --yes ]] || { echo 'Usage: database-manager-install.sh --yes' >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "${SCRIPT_DIR}/platform.sh"
nakpanel_require_platform
command -v nginx >/dev/null || { echo 'Install the panel nginx runtime first.' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
VERSION=5.2.3
SHA256=57881348297c4412f86c410547cf76b4d8a236574dd2c6b7d6a2beebe7fc44e3
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl xz-utils openssl "php${NAKPANEL_INTERNAL_PHP_VERSION}-fpm" "php${NAKPANEL_INTERNAL_PHP_VERSION}-mysql" "php${NAKPANEL_INTERNAL_PHP_VERSION}-mbstring" "php${NAKPANEL_INTERNAL_PHP_VERSION}-xml" "php${NAKPANEL_INTERNAL_PHP_VERSION}-curl" "php${NAKPANEL_INTERNAL_PHP_VERSION}-zip"
getent group nakpanel-dbmgr >/dev/null || groupadd --system nakpanel-dbmgr
id nakpanel-dbmgr >/dev/null 2>&1 || useradd --system --gid nakpanel-dbmgr --home-dir /nonexistent --shell /usr/sbin/nologin nakpanel-dbmgr
id nakpanel >/dev/null
usermod -a -G nakpanel-dbmgr nakpanel
install -d -m 0755 /opt/nakpanel-database-manager
install -d -o root -g nakpanel-dbmgr -m 0750 /etc/nakpanel-database-manager
install -d -o nakpanel-dbmgr -g nakpanel-dbmgr -m 0700 /var/lib/nakpanel-database-manager/{grants,tmp}
ARCHIVE="phpMyAdmin-${VERSION}-all-languages.tar.xz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "https://files.phpmyadmin.net/phpMyAdmin/${VERSION}/${ARCHIVE}" -o "$WORK/$ARCHIVE"
printf '%s  %s\n' "$SHA256" "$WORK/$ARCHIVE" | sha256sum --check --status
tar -xJf "$WORK/$ARCHIVE" -C "$WORK" --no-same-owner
SOURCE="$WORK/phpMyAdmin-${VERSION}-all-languages"
rm -rf "$SOURCE/setup" "$SOURCE/examples" "$SOURCE/test"
install -o root -g root -m 0644 "$ROOT/deploy/database-manager/config.inc.php" "$SOURCE/config.inc.php"
chown -R root:root "$SOURCE"
chmod -R u=rwX,go=rX "$SOURCE"
if [[ ! -e /opt/nakpanel-database-manager/$VERSION ]]; then
    mv "$SOURCE" "/opt/nakpanel-database-manager/$VERSION"
else
    install -o root -g root -m 0644 "$SOURCE/config.inc.php" "/opt/nakpanel-database-manager/$VERSION/config.inc.php"
fi
ln -sfn "$VERSION" /opt/nakpanel-database-manager/current
for file in adapter.php prepend.php signon.php health.php php-fpm.conf nginx.conf; do
    install -o root -g nakpanel-dbmgr -m 0640 "$ROOT/deploy/database-manager/$file" "/etc/nakpanel-database-manager/$file"
done
if [[ ! -f /etc/nakpanel/database-manager.key ]]; then
    openssl rand -hex 32 > "$WORK/proxy.key"
    install -o root -g nakpanel -m 0640 "$WORK/proxy.key" /etc/nakpanel/database-manager.key
fi
install -o root -g nakpanel-dbmgr -m 0640 /etc/nakpanel/database-manager.key /etc/nakpanel-database-manager/proxy.key
if [[ ! -f /etc/nakpanel-database-manager/cookie.key ]]; then
    openssl rand -hex 16 > "$WORK/cookie.key"
    install -o root -g nakpanel-dbmgr -m 0640 "$WORK/cookie.key" /etc/nakpanel-database-manager/cookie.key
fi
sed "s#@PHP_FPM_BINARY@#/usr/sbin/php-fpm${NAKPANEL_INTERNAL_PHP_VERSION}#g" "$ROOT/deploy/systemd/nakpanel-database-manager.service.tmpl" > "$WORK/nakpanel-database-manager.service"
install -m 0644 "$WORK/nakpanel-database-manager.service" /etc/systemd/system/
install -m 0644 "$ROOT/deploy/systemd/nakpanel-database-manager-http.service" /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/nakpanel.service.d
install -m 0644 "$ROOT/deploy/database-manager/panel-runtime.conf" /etc/systemd/system/nakpanel.service.d/database-manager.conf
install -m 0644 "$ROOT/deploy/database-manager/tmpfiles.conf" /etc/tmpfiles.d/nakpanel-database-manager.conf
systemd-tmpfiles --create /etc/tmpfiles.d/nakpanel-database-manager.conf
"/usr/sbin/php-fpm${NAKPANEL_INTERNAL_PHP_VERSION}" --test --fpm-config /etc/nakpanel-database-manager/php-fpm.conf
systemctl daemon-reload
systemctl enable --now nakpanel-database-manager.service nakpanel-database-manager-http.service
printf '%s\n' 'Runtime installed at 127.0.0.1:9082. Configure the panel bridge/key and restart the panel separately.'
