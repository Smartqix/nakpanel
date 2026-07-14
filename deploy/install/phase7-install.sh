#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "phase7-install.sh must be run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  adminer \
  bind9 \
  ca-certificates \
  curl \
  mariadb-server \
  nginx \
  php8.3-fpm \
  postgresql \
  postgresql-contrib \
  roundcube \
  ufw

if ! id nakpanel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi

install -d -o nakpanel -g nakpanel -m 0750 /var/lib/nakpanel
install -d -o nakpanel -g nakpanel -m 0750 /var/lib/nakpanel/tls
install -d -o nakpanel -g nakpanel -m 0700 /var/lib/nakpanel/tls-staging
install -d -o nakpanel -g nakpanel -m 0750 /var/lib/nakpanel/backups
install -d -m 0755 /etc/bind/nakpanel/zones
install -d -m 0755 /etc/bind/nakpanel/zones.d

systemctl enable --now postgresql mariadb nginx php8.3-fpm named.service

if command -v ufw >/dev/null 2>&1; then
  ufw allow 7443/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 53/tcp
  ufw allow 53/udp
fi

if [[ ! -x /usr/local/bin/nakpanel-panel || ! -x /usr/local/bin/nakpanel-agent || ! -x /usr/local/bin/panelctl ]]; then
  echo "install /usr/local/bin/nakpanel-panel, /usr/local/bin/nakpanel-agent, and /usr/local/bin/panelctl before starting nakpanel services" >&2
  exit 1
fi

install -m 0644 deploy/systemd/nakpanel-agent.service /etc/systemd/system/nakpanel-agent.service
install -m 0644 deploy/systemd/nakpanel.service /etc/systemd/system/nakpanel.service
systemctl daemon-reload
systemctl enable --now nakpanel-agent.service nakpanel.service

echo "Phase 7 packages and nakpanel services are installed."
