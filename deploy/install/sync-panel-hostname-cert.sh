#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [--check] <panel-hostname>" >&2
  exit 2
}

check_only=false
if [[ "${1:-}" == "--check" ]]; then
  check_only=true
  shift
fi
[[ $# -eq 1 ]] || usage
hostname="${1,,}"
[[ "$hostname" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$hostname" == *.* && "$hostname" != *..* ]] || usage
[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }

source_dir="/var/lib/nakpanel/certs/${hostname}"
cert="${source_dir}/fullchain.pem"
key="${source_dir}/privkey.pem"
dest_dir=/var/lib/nakpanel/tls
dest="${dest_dir}/panel.pem"

for path in "$cert" "$key"; do
  [[ -f "$path" && ! -L "$path" && $(stat -c '%u' "$path") == 0 ]] || {
    echo "hostname certificate source is missing or unsafe: $path" >&2
    exit 1
  }
done
[[ $(stat -c '%a' "$key") =~ ^(600|400)$ ]] || {
  echo "hostname certificate key must be private" >&2
  exit 1
}

openssl x509 -in "$cert" -noout -checkhost "$hostname" | grep -q 'does match certificate' || {
  echo "hostname certificate does not cover ${hostname}" >&2
  exit 1
}
openssl x509 -in "$cert" -noout -checkend 86400 | grep -q 'will not expire' || {
  echo "hostname certificate expires within 24 hours" >&2
  exit 1
}
openssl verify -purpose sslserver -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted "$cert" "$cert" >/dev/null || {
  echo "hostname certificate is not trusted" >&2
  exit 1
}
cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
key_pub=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum)
[[ "$cert_pub" == "$key_pub" ]] || {
  echo "hostname certificate and key do not match" >&2
  exit 1
}

if "$check_only"; then
  echo "trusted hostname certificate is valid for ${hostname}"
  exit 0
fi

[[ -d "$dest_dir" && ! -L "$dest_dir" ]] || {
  echo "panel TLS directory is missing or unsafe" >&2
  exit 1
}
[[ ! -e "$dest" || ( -f "$dest" && ! -L "$dest" ) ]] || {
  echo "managed panel certificate path is unsafe" >&2
  exit 1
}
umask 077
candidate=$(mktemp "${dest_dir}/.panel.pem.XXXXXXXX")
backup=''
cleanup() {
  rm -f "$candidate"
  if [[ -n "$backup" ]]; then rm -f "$backup"; fi
}
trap cleanup EXIT
cat "$cert" >"$candidate"
printf '\n' >>"$candidate"
cat "$key" >>"$candidate"
chown nakpanel:nakpanel "$candidate"
chmod 0600 "$candidate"
if [[ -f "$dest" ]] && cmp -s "$candidate" "$dest"; then
  echo "panel hostname certificate is current"
  exit 0
fi
if [[ -f "$dest" ]]; then
  backup=$(mktemp "${dest_dir}/.panel.previous.XXXXXXXX")
  cp -p "$dest" "$backup"
fi
mv -f "$candidate" "$dest"

healthy() {
  local response
  response=$(curl --fail --silent --show-error --max-time 3 \
    --resolve "${hostname}:7443:127.0.0.1" \
    "https://${hostname}:7443/healthz" 2>/dev/null) || return 1
  [[ "$response" == $'ok\nversion='* ]]
}

if systemctl restart nakpanel.service; then
  for _ in {1..15}; do
    if healthy; then
      echo "panel hostname certificate activated for ${hostname}"
      exit 0
    fi
    sleep 1
  done
fi

echo "panel failed the trusted TLS health check; restoring previous certificate" >&2
if [[ -n "$backup" ]]; then
  mv -f "$backup" "$dest"
  backup=''
else
  rm -f "$dest"
fi
systemctl restart nakpanel.service || true
exit 1
