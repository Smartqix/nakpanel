#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "phase8-install.sh must be run as root" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
cd "${ROOT_DIR}"

"${SCRIPT_DIR}/phase7-install.sh"

export DEBIAN_FRONTEND=noninteractive
apt-get update
quota_packages=(quota)
if apt-cache show "linux-modules-extra-$(uname -r)" >/dev/null 2>&1; then
  quota_packages+=("linux-modules-extra-$(uname -r)")
fi
apt-get install -y "${quota_packages[@]}"
modprobe quota_v2 >/dev/null 2>&1 || true

ensure_quota_fstab() {
  local target="$1"
  local source="$2"
  local fstype="$3"
  local tmp
  tmp="$(mktemp)"
  if awk -v target="${target}" '$2 == target { found = 1 } END { exit found ? 0 : 1 }' /etc/fstab; then
    awk -v target="${target}" '
      BEGIN { OFS = "\t" }
      $2 == target {
        if ($4 == "defaults") {
          $4 = "defaults,usrquota,grpquota"
        } else {
          if ($4 !~ /(^|,)usrquota(,|$)/) $4 = $4 ",usrquota"
          if ($4 !~ /(^|,)grpquota(,|$)/) $4 = $4 ",grpquota"
        }
      }
      { print }
    ' /etc/fstab >"${tmp}"
    cat "${tmp}" >/etc/fstab
  else
    cat /etc/fstab >"${tmp}"
    printf '%s\t%s\t%s\tdefaults,usrquota,grpquota\t0\t1\n' "${source}" "${target}" "${fstype}" >>"${tmp}"
    cat "${tmp}" >/etc/fstab
  fi
  rm -f "${tmp}"
}

quota_target="$(findmnt -n -o TARGET --target /home)"
if [[ -z "${quota_target}" ]]; then
  echo "could not find filesystem for /home" >&2
  exit 1
fi
quota_source="$(findmnt -n -o SOURCE --target /home)"
quota_fstype="$(findmnt -n -o FSTYPE --target /home)"
ensure_quota_fstab "${quota_target}" "${quota_source}" "${quota_fstype}"

if ! findmnt -n -o OPTIONS --target /home | tr ',' '\n' | grep -qx 'usrquota'; then
  mount -o remount,usrquota,grpquota "${quota_target}"
fi

quota_state="$(quotaon -p "${quota_target}" 2>/dev/null || true)"
if ! grep -Eq 'user quota .* is on' <<<"${quota_state}"; then
  if ! quotacheck -ugm "${quota_target}"; then
    quotacheck -cugm "${quota_target}"
  fi
  quotaon -uv "${quota_target}"
fi

systemctl start nginx php8.3-fpm
systemctl restart nakpanel-agent.service nakpanel.service

echo "Phase 8 quota tooling is installed and nakpanel services restarted."
