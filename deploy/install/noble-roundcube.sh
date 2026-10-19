#!/usr/bin/env bash
# Ubuntu's Roundcube package creates its database during its first installation.
# Source this helper before that installation; sourcing alone has no effects.

nakpanel_noble_roundcube_debconf_value() {
  local answer result=0
  answer="$(printf 'GET roundcube-core/%s\n' "$1" | debconf-communicate roundcube-core 2>/dev/null)" || result=$?
  case "$answer" in
    '0 '*) printf '%s' "${answer#0 }" ;;
    '10 '*) return 0 ;; # The question has not been registered on a fresh host.
    *)
      echo "Cannot inspect the existing Roundcube debconf configuration (exit ${result})." >&2
      return 1
      ;;
  esac
}

nakpanel_prepare_noble_roundcube() {
  NAKPANEL_NOBLE_ROUNDCUBE_PACKAGES=(roundcube roundcube-core)
  local path package_status choice dbconfig_install
  # Any prior configuration or data belongs to the operator. In particular,
  # never convert an installed MariaDB, PostgreSQL, SQLite, or custom backend.
  for path in /etc/roundcube /etc/dbconfig-common/roundcube.conf /var/lib/roundcube; do
    if [[ -e "$path" || -L "$path" ]]; then return 0; fi
  done
  package_status="$(dpkg-query -W -f='${db:Status-Status}' roundcube-core 2>/dev/null)" || package_status='not-installed'
  if [[ -n "$package_status" && "$package_status" != not-installed ]]; then return 0; fi

  choice="$(nakpanel_noble_roundcube_debconf_value database-type)" || return 1
  if [[ -n "$choice" ]]; then
    # Preserve an administrator's preseed, while supplying its SQLite provider
    # when no package has been installed yet (also supports interrupted setup).
    if [[ "$choice" == sqlite3 ]]; then NAKPANEL_NOBLE_ROUNDCUBE_PACKAGES+=(roundcube-sqlite3); fi
    return 0
  fi
  dbconfig_install="$(nakpanel_noble_roundcube_debconf_value dbconfig-install)" || return 1
  if [[ "$dbconfig_install" == false ]]; then return 0; fi

  printf '%s\n' \
    'roundcube-core roundcube-core/database-type select sqlite3' \
    'roundcube-core roundcube-core/dbconfig-install boolean true' | debconf-set-selections
  NAKPANEL_NOBLE_ROUNDCUBE_PACKAGES+=(roundcube-sqlite3)
}
