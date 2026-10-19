#!/usr/bin/env bash
# Inert when sourced. Parent installer owns preflight ordering and stage cleanup.
nakpanel_stalwart_architecture() {
  local architecture
  case "$(uname -m)" in
    x86_64) architecture=amd64 ;;
    aarch64|arm64) architecture=arm64 ;;
    *) echo 'unsupported Stalwart host architecture' >&2; return 1 ;;
  esac
  if [[ -n "${NAKPANEL_PLATFORM_ARCH:-}" && "${NAKPANEL_PLATFORM_ARCH}" != "${architecture}" ]]; then
    echo 'Stalwart host/platform architecture mismatch' >&2; return 1
  fi
  printf '%s\n' "${architecture}"
}

nakpanel_prepare_stalwart_artifact() {
  local here architecture archive url
  here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || return 1
  architecture="$(nakpanel_stalwart_architecture)" || return 1
  if [[ -z "${NAKPANEL_STALWART_STAGE:-}" ]]; then
    NAKPANEL_STALWART_STAGE="$(mktemp -d /tmp/nakpanel-stalwart.XXXXXX)" || return 1
    chmod 0700 "${NAKPANEL_STALWART_STAGE}" || return 1
    python3 "${here}/stalwart_artifact.py" stage "${NAKPANEL_STALWART_STAGE}" || return 1
    url="$(python3 "${here}/stalwart_artifact.py" url "${architecture}")" || return 1
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "${url}" -o "${NAKPANEL_STALWART_STAGE}/stalwart-mail.tar.gz" || return 1
  fi
  # An inherited or reused stage is always checked again; never redownload over
  # invalid supplied bytes or treat an environment path as proof of verification.
  python3 "${here}/stalwart_artifact.py" stage "${NAKPANEL_STALWART_STAGE}" || return 1
  archive="${NAKPANEL_STALWART_STAGE}/stalwart-mail.tar.gz"
  python3 "${here}/stalwart_artifact.py" verify "${archive}" "${architecture}" || return 1
  export NAKPANEL_STALWART_STAGE
}

nakpanel_install_stalwart() (
  set -euo pipefail
  [[ "${EUID}" == 0 ]] || { echo 'Stalwart installation requires root' >&2; exit 1; }
  local here architecture temporary own_stage=0
  here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  architecture="$(nakpanel_stalwart_architecture)"
  [[ -n "${NAKPANEL_STALWART_STAGE:-}" ]] || own_stage=1
  nakpanel_prepare_stalwart_artifact
  install -d -o root -g root -m0755 /usr/local/bin
  temporary="$(mktemp -d /usr/local/bin/.nakpanel-stalwart.XXXXXX)"
  trap 'rm -rf "${temporary}"; if [[ "${own_stage}" == 1 ]]; then rm -rf "${NAKPANEL_STALWART_STAGE}"; fi' EXIT
  # Revalidate the same opened archive bytes while extracting a single regular
  # binary. Rename on the destination filesystem publishes complete mode0755.
  python3 "${here}/stalwart_artifact.py" extract "${NAKPANEL_STALWART_STAGE}/stalwart-mail.tar.gz" "${architecture}" "${temporary}/stalwart-mail"
  mv -f "${temporary}/stalwart-mail" /usr/local/bin/stalwart-mail
)
