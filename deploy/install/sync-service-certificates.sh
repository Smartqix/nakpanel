#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# -eq 1 && ${EUID} -eq 0 ]] || { echo "usage (root): $0 <hostname>" >&2; exit 2; }
hostname="${1,,}"
[[ "$hostname" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$hostname" == *.* && "$hostname" != *..* ]] || exit 2
exec 9>/run/nakpanel-service-cert.lock
flock -w 60 9
/usr/local/libexec/nakpanel/sync-panel-hostname-cert --check "$hostname" >/dev/null
source_dir="/var/lib/nakpanel/certs/${hostname}"
ftps_dir="/etc/nakpanel/service-tls/${hostname}"
mail_dir=/etc/stalwart/tls

safe_directory() {
  [[ -d "$1" && ! -L "$1" && $(stat -c '%u' "$1") == 0 && $(stat -c '%a' "$1") =~ ^(700|750|755|710)$ ]] || {
    echo "unsafe service TLS directory: $1" >&2; exit 1;
  }
}
safe_directory /etc/nakpanel
safe_directory /etc/stalwart
safe_directory "$mail_dir"
if [[ ! -e /etc/nakpanel/service-tls ]]; then mkdir -m 0700 /etc/nakpanel/service-tls; fi
safe_directory /etc/nakpanel/service-tls
if [[ ! -e "$ftps_dir" ]]; then mkdir -m 0700 "$ftps_dir"; fi
safe_directory "$ftps_dir"
sources=("$source_dir/fullchain.pem" "$source_dir/privkey.pem" "$source_dir/fullchain.pem" "$source_dir/privkey.pem")
targets=("$mail_dir/cert.pem" "$mail_dir/key.pem" "$ftps_dir/fullchain.pem" "$ftps_dir/privkey.pem")
backup=$(mktemp -d /etc/nakpanel/.service-tls.XXXXXXXX)
changed=false
mail_changed=false
ftp_changed=false
installed=false
mail_active=false
ftp_active=false
systemctl is-active --quiet stalwart-mail.service && mail_active=true
systemctl is-active --quiet nakpanel-proftpd.service && ftp_active=true
for i in "${!targets[@]}"; do
  target="${targets[$i]}"
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -f "$target" && ! -L "$target" && $(stat -c '%u' "$target") == 0 ]] || { rm -rf "$backup"; echo "unsafe service TLS file" >&2; exit 1; }
    cp -p "$target" "$backup/$i.previous"
  fi
  cp "${sources[$i]}" "$backup/$i.candidate"
  chown root:root "$backup/$i.candidate"
  chmod 0600 "$backup/$i.candidate"
  if [[ ! -f "$target" ]] || ! cmp -s "$backup/$i.candidate" "$target" || [[ $(stat -c '%a' "$target") != 600 ]]; then
    changed=true
    if [[ $i -lt 2 ]]; then mail_changed=true; else ftp_changed=true; fi
  fi
done
rollback() {
  local status=$?
  if [[ $status -ne 0 && "$installed" == true ]]; then
    for i in "${!targets[@]}"; do
      if [[ -f "$backup/$i.previous" ]]; then mv -f "$backup/$i.previous" "${targets[$i]}"; else rm -f "${targets[$i]}"; fi
    done
    if "$mail_active" && "$mail_changed"; then systemctl restart stalwart-mail.service || true; fi
    if "$ftp_active" && "$ftp_changed"; then systemctl reload-or-restart nakpanel-proftpd.service || true; fi
    echo "service certificate activation failed; previous files restored" >&2
  fi
  rm -rf "$backup"
  exit "$status"
}
trap rollback EXIT
if "$changed"; then
  installed=true
  for i in "${!targets[@]}"; do mv -f "$backup/$i.candidate" "${targets[$i]}"; done
  if "$ftp_active" && "$ftp_changed"; then proftpd -t -c /etc/nakpanel/proftpd/proftpd.conf; fi
  if "$mail_active" && "$mail_changed"; then systemctl restart stalwart-mail.service; fi
  if "$ftp_active" && "$ftp_changed"; then systemctl reload-or-restart nakpanel-proftpd.service; fi
fi
expected=$(openssl x509 -in "$source_dir/fullchain.pem" -noout -fingerprint -sha256)
probe() {
  local port="$1" protocol="$2" actual
  local args=(-connect "127.0.0.1:$port" -servername "$hostname" -verify_hostname "$hostname" -verify_return_error -CAfile /etc/ssl/certs/ca-certificates.crt)
  if [[ -n "$protocol" ]]; then args+=(-starttls "$protocol"); fi
  for _ in {1..15}; do
    if timeout 5 openssl s_client "${args[@]}" </dev/null >"$backup/probe" 2>"$backup/probe-errors"; then
      actual=$(openssl x509 -in "$backup/probe" -noout -fingerprint -sha256) || return 1
      [[ "$actual" == "$expected" ]] && return 0
    fi
    sleep 1
  done
  echo "trusted service TLS probe failed on port $port" >&2
  return 1
}
if "$mail_active"; then probe 993 ''; probe 587 smtp; fi
if "$ftp_active"; then probe 21 ftp; fi
echo "trusted mail/FTPS certificate synchronized for $hostname"
