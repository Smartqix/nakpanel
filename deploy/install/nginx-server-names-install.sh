#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
  echo "nginx-server-names-install.sh must run as root" >&2
  exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
target=/etc/nginx/conf.d/nakpanel-server-names.conf
template="${SCRIPT_DIR}/../nginx/nakpanel-server-names.conf"
test -f "${template}"
[[ ! -L "${target}" ]] || { echo 'Refusing a symlink at the managed nginx configuration' >&2; exit 1; }
install -d -m 0755 /etc/nginx/conf.d
tmpdir="$(mktemp -d /etc/nginx/conf.d/.nakpanel-server-names.XXXXXX)"
previous=false
if [[ -e "${target}" ]]; then
  test -f "${target}"
  cp -p "${target}" "${tmpdir}/previous"
  previous=true
fi
changed=false
rollback(){
  if [[ "${changed}" == true ]]; then
    if [[ "${previous}" == true ]]; then mv -f "${tmpdir}/previous" "${target}"; else rm -f "${target}"; fi
    nginx -t && { if systemctl is-active --quiet nginx; then systemctl reload nginx; fi; } || true
  fi
}
cleanup(){
  local status=$?
  trap - EXIT
  if [[ "${status}" != 0 ]]; then rollback; fi
  rm -rf "${tmpdir}"
  exit "${status}"
}
trap cleanup EXIT
install -o root -g root -m 0644 "${template}" "${tmpdir}/candidate"
mv -f "${tmpdir}/candidate" "${target}"
changed=true
nginx -t
if systemctl is-active --quiet nginx; then systemctl reload nginx; fi
changed=false
echo 'Validated nginx hostname capacity configuration installed.'
