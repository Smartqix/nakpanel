#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "phase21-25-install.sh must be run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  acl \
  git \
  mariadb-client \
  netcat-openbsd \
  openssh-server \
  php8.3-cli \
  podman \
  uidmap \
  slirp4netns \
  fuse-overlayfs \
  proftpd-core \
  proftpd-mod-crypto \
  redis-tools \
  skopeo \
  jq

install -d -o root -g root -m 0755 /etc/nakpanel
install -d -o root -g root -m 0700 /etc/nakpanel/proftpd
install -d -o root -g root -m 0700 /etc/nakpanel/ssh/authorized_keys
install -d -o root -g root -m 0700 /etc/nakpanel/valkey
install -d -o root -g www-data -m 0710 /etc/nginx/nakpanel/protected
install -d -o root -g root -m 0700 /var/lib/nakpanel/git
install -d -o root -g root -m 0700 /var/lib/nakpanel/staging
install -d -o root -g root -m 0711 /var/lib/nakpanel/containers
install -d -o root -g root -m 0711 /run/nakpanel-containers
install -d -o root -g root -m 0755 /usr/lib/nakpanel
# Ubuntu's slirp4netns sandbox cannot remount /tmp in some nested VM
# environments. Keep the rootless network namespace and all container
# hardening, but omit only that helper-level sandbox flag.
cat >/usr/lib/nakpanel/slirp4netns <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
filtered=()
for arg in "$@"; do
  [[ "${arg}" == "--enable-sandbox" ]] || filtered+=("${arg}")
done
exec /usr/bin/slirp4netns "${filtered[@]}"
EOF
chown root:root /usr/lib/nakpanel/slirp4netns
chmod 0755 /usr/lib/nakpanel/slirp4netns
cat >/etc/tmpfiles.d/nakpanel-containers.conf <<'EOF'
d /run/nakpanel-containers 0711 root root -
# Rootful Podman and crun keep volatile state outside /run/podman. These
# directories must exist before hardened cache units construct their private
# mount namespace during early boot.
d /run/libpod 0751 root root -
d /run/crun 0755 root root -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/nakpanel-containers.conf
install -d -o root -g root -m 0755 /etc/nginx/nakpanel/applications
install -d -o root -g root -m 0755 /var/log/nakpanel
install -d -o root -g root -m 0755 /var/log/nakpanel/applications
install -d -o root -g root -m 0755 /var/log/nakpanel/tasks
install -d -o root -g root -m 0755 /var/log/php-fpm
install -d -o root -g root -m 0755 /var/log/proftpd
install -d -o www-data -g www-data -m 0750 /var/cache/nginx/nakpanel

if [[ ! -f /etc/nakpanel/mysql-agent.cnf ]]; then
  cat >/etc/nakpanel/mysql-agent.cnf <<'EOF'
[client]
user=root
protocol=socket
EOF
fi
chown root:root /etc/nakpanel/mysql-agent.cnf
chmod 0600 /etc/nakpanel/mysql-agent.cnf

# Nakpanel owns a separate, generated ProFTPD unit. The distro service must
# never race it for port 21 or load an unrelated configuration.
systemctl disable --now proftpd.service 2>/dev/null || true

agent_env=/etc/nakpanel/agent.env
touch "${agent_env}"
chmod 0600 "${agent_env}"
chown root:root "${agent_env}"
set_agent_env() {
  local key="$1" value="$2"
  sed -i "/^${key}=/d" "${agent_env}"
  printf '%s=%s\n' "${key}" "${value}" >>"${agent_env}"
}
set_agent_env NAKPANEL_FTPS_TLS_CERT "${NAKPANEL_FTPS_TLS_CERT:-/var/lib/nakpanel/tls/panel.crt}"
set_agent_env NAKPANEL_FTPS_TLS_KEY "${NAKPANEL_FTPS_TLS_KEY:-/var/lib/nakpanel/tls/panel.key}"
if [[ -n "${NAKPANEL_FTPS_PUBLIC_ADDRESS:-}" ]]; then
  set_agent_env NAKPANEL_FTPS_PUBLIC_ADDRESS "${NAKPANEL_FTPS_PUBLIC_ADDRESS}"
fi
valkey_image="${NAKPANEL_VALKEY_IMAGE:-}"
if [[ -z "${valkey_image}" ]]; then
  # Re-runs reuse the digest already pinned in agent.env so upgrades never
  # depend on registry availability for an image that is already cached.
  valkey_image="$(sed -n 's/^NAKPANEL_VALKEY_IMAGE=//p' "${agent_env}" | head -n1)"
fi
if [[ -z "${valkey_image}" ]]; then
  valkey_digest="$(skopeo inspect docker://docker.io/valkey/valkey:8.1-alpine | jq -r '.Digest')"
  valkey_image="docker.io/valkey/valkey@${valkey_digest}"
fi
if [[ ! "${valkey_image}" =~ ^docker\.io/valkey/valkey@sha256:[a-f0-9]{64}$ ]]; then
  echo "NAKPANEL_VALKEY_IMAGE must pin the official docker.io/valkey/valkey image by sha256 digest" >&2
  exit 1
fi
# Resolve and cache the immutable image while installation still has an
# operator-visible network failure path. Runtime units never pull images.
if ! podman image exists "${valkey_image}"; then
  podman pull "${valkey_image}"
fi
set_agent_env NAKPANEL_VALKEY_IMAGE "${valkey_image}"

if command -v ufw >/dev/null 2>&1; then
  ufw allow 21/tcp
  ufw allow 49152:49252/tcp
fi

install -m 0644 deploy/systemd/nakpanel-agent.service /etc/systemd/system/nakpanel-agent.service
systemctl daemon-reload
systemctl enable --now ssh.service
systemctl restart nakpanel-agent.service

echo "Phase 21-25 hosting toolkit packages and agent configuration are installed."
