#!/usr/bin/env bash
# Sourcing this helper has no effects. The caller has loaded platform.sh.
nakpanel_install_roundcube_maintenance() (
  set -euo pipefail
  # Re-resolve the actual OS and trusted installed descriptor; never select the
  # maintenance CLI from tenant/PATH PHP or an inherited internal-version env.
  nakpanel_require_platform
  case "${NAKPANEL_PLATFORM_ID}" in
    ubuntu-24.04|ubuntu-26.04-native|ubuntu-26.04-sury) ;;
    *) echo 'unsupported Roundcube maintenance profile' >&2; exit 1 ;;
  esac
  [[ "${NAKPANEL_INTERNAL_PHP_VERSION}" =~ ^[0-9]+\.[0-9]+$ ]] || exit 1
  local script_dir temporary
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  umask 077
  temporary="$(mktemp -d)"
  trap 'rm -rf "${temporary}"' EXIT
  sed "s/@NAKPANEL_INTERNAL_PHP_VERSION@/${NAKPANEL_INTERNAL_PHP_VERSION}/g" \
    "${script_dir}/../systemd/roundcube-gc.service.d/nakpanel.conf" >"${temporary}/nakpanel.conf"
  install -d -o root -g root -m 0755 /etc/systemd/system/roundcube-gc.service.d
  install -o root -g root -m 0644 "${temporary}/nakpanel.conf" \
    /etc/systemd/system/roundcube-gc.service.d/nakpanel.conf
  if [[ "${NAKPANEL_PLATFORM_ID}" != ubuntu-24.04 ]]; then
    # Upstream Resolute installs have no distribution-owned base unit/timer.
    # Noble keeps its package's base unit, hardening and timer unchanged.
    sed "s/@NAKPANEL_INTERNAL_PHP_VERSION@/${NAKPANEL_INTERNAL_PHP_VERSION}/g" \
      "${script_dir}/../systemd/roundcube-gc.service" >"${temporary}/roundcube-gc.service"
    install -o root -g root -m 0644 "${temporary}/roundcube-gc.service" \
      /etc/systemd/system/roundcube-gc.service
    install -o root -g root -m 0644 "${script_dir}/../systemd/roundcube-gc.timer" \
      /etc/systemd/system/roundcube-gc.timer
  fi
  systemctl daemon-reload
  if [[ "${NAKPANEL_PLATFORM_ID}" != ubuntu-24.04 ]]; then
    systemctl enable --now roundcube-gc.timer
  fi
  # A missing config is an explicit unit condition, so the pre-configure_mail
  # install can succeed. Once configured, a genuine GC failure must propagate.
  systemctl start roundcube-gc.service
)
