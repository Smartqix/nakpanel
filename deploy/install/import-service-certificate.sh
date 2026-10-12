#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# -eq 2 && ${EUID} -eq 0 ]] || { echo "usage (root): $0 <hostname> <certbot-lineage>" >&2; exit 2; }
hostname="${1,,}"
[[ "$hostname" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$hostname" == *.* && "$hostname" != *..* ]] || exit 2
lineage=$(realpath -e "$2")
[[ "$lineage" == /etc/letsencrypt/live/* && -d "$lineage" && $(stat -c '%u' "$lineage") == 0 ]] || exit 1
cert=$(realpath -e "$lineage/fullchain.pem")
key=$(realpath -e "$lineage/privkey.pem")
for file in "$cert" "$key"; do
  [[ "$file" == /etc/letsencrypt/archive/* && -f "$file" && $(stat -c '%u' "$file") == 0 ]] || exit 1
done
[[ $(stat -c '%a' "$key") =~ ^(600|400)$ ]] || exit 1
openssl x509 -in "$cert" -noout -checkhost "$hostname" | grep -q 'does match certificate'
openssl x509 -in "$cert" -noout -checkend 86400 | grep -q 'will not expire'
openssl verify -purpose sslserver -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted "$cert" "$cert" >/dev/null
cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
key_pub=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum)
[[ "$cert_pub" == "$key_pub" ]] || exit 1
exec 8>/run/nakpanel-service-cert-import.lock
flock -w 60 8
dest="/var/lib/nakpanel/certs/$hostname"
if [[ ! -e "$dest" ]]; then mkdir -m 0700 "$dest"; fi
[[ -d "$dest" && ! -L "$dest" && $(stat -c '%u' "$dest") == 0 ]] || exit 1
backup=$(mktemp -d "$dest/.import.XXXXXXXX")
installed=false
for name in fullchain.pem privkey.pem; do
  if [[ -e "$dest/$name" || -L "$dest/$name" ]]; then
    [[ -f "$dest/$name" && ! -L "$dest/$name" && $(stat -c '%u' "$dest/$name") == 0 ]] || { rm -rf "$backup"; exit 1; }
    cp -p "$dest/$name" "$backup/$name.previous"
  fi
done
rollback() {
  local status=$?
  if [[ $status -ne 0 && "$installed" == true ]]; then
    for name in fullchain.pem privkey.pem; do
      if [[ -f "$backup/$name.previous" ]]; then mv -f "$backup/$name.previous" "$dest/$name"; else rm -f "$dest/$name"; fi
    done
  fi
  rm -rf "$backup"
  exit "$status"
}
trap rollback EXIT
install -m 0644 "$cert" "$backup/fullchain.pem"
install -m 0600 "$key" "$backup/privkey.pem"
installed=true
mv -f "$backup/fullchain.pem" "$dest/fullchain.pem"
mv -f "$backup/privkey.pem" "$dest/privkey.pem"
/usr/local/libexec/nakpanel/sync-service-certificates "$hostname"
