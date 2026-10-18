#!/usr/bin/env bash
# Build from a clean checkout. Signing key must be supplied out of band.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"
architecture_selection="${NAKPANEL_RELEASE_ARCHITECTURES-amd64 arm64}"
case "${architecture_selection}" in
  amd64|arm64|'amd64 arm64'|'arm64 amd64') ;;
  *) echo 'invalid release architectures: use amd64, arm64, or a space-separated pair without duplicates' >&2; exit 1 ;;
esac
read -r -a release_architectures <<< "${architecture_selection}"
: "${NAKPANEL_RELEASE_SIGNING_KEY:?set NAKPANEL_RELEASE_SIGNING_KEY to an RSA PEM private key}"
[[ -f "${NAKPANEL_RELEASE_SIGNING_KEY}" ]] || { echo 'signing key missing' >&2; exit 1; }
GO_VERSION="$(cat deploy/release/GO_VERSION)"
[[ "$(go env GOVERSION)" == "go${GO_VERSION}" ]] || { echo "release requires Go ${GO_VERSION}" >&2; exit 1; }
export GOTOOLCHAIN=local
DEVELOPMENT=false
if [[ -n "$(git status --porcelain)" ]]; then
  [[ "${NAKPANEL_RELEASE_ALLOW_DIRTY:-0}" == 1 ]] || { echo 'release requires a clean checkout' >&2; exit 1; }
  DEVELOPMENT=true
fi
OUTPUT="${1:-${ROOT}/dist}"
mkdir -p "${OUTPUT}"
OUTPUT="$(cd "${OUTPUT}" && pwd)"
VERSION="$(tr -d '[:space:]' < VERSION)"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo 'invalid VERSION' >&2; exit 1; }
COMMIT="$(git rev-parse HEAD)"
# Generation deliberately runs once for both architectures. Do not bypass it.
make generate
if [[ "${DEVELOPMENT}" == false ]]; then
  git diff --exit-code -- internal/control/web internal/control/store || { echo 'generated assets stale; regenerate and commit first' >&2; exit 1; }
else
  echo 'development snapshot: regenerated assets are included; committed-code gate deferred' >&2
fi
LDFLAGS="-X github.com/nakroteck/nakpanel/internal/version.Version=${VERSION} -X github.com/nakroteck/nakpanel/internal/version.Commit=${COMMIT}"
for architecture in "${release_architectures[@]}"; do
  bundle="${OUTPUT}/nakpanel-${VERSION}-linux-${architecture}"
  [[ ! -e "${bundle}" ]] || { echo "output already exists: ${bundle}" >&2; exit 1; }
  mkdir -p "${bundle}/bin"
  for command in panel agent panelctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" GOAMD64=v1 GOARM64=v8.0 \
      go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o "${bundle}/bin/${command}" "./cmd/${command}"
    python3 deploy/release/verify.py --architecture "${architecture}" --elf "${bundle}/bin/${command}"
    go version -m "${bundle}/bin/${command}" > "${bundle}/bin/${command}.buildinfo"
  done
  # All installation/configuration assets and pinned migration entry points.
  cp VERSION Makefile go.mod go.sum "${bundle}/"
  cp -R migrations "${bundle}/migrations"
  python3 deploy/release/manifest.py "${ROOT}" "${bundle}" "${VERSION}" "${COMMIT}" "${architecture}" "${DEVELOPMENT}"
  openssl dgst -sha256 -sign "${NAKPANEL_RELEASE_SIGNING_KEY}" -out "${bundle}/manifest.sig" "${bundle}/manifest.json"
  # Derive a temporary public key only to check this build; do not ship trust anchors.
  public_key="$(mktemp)"
  openssl pkey -in "${NAKPANEL_RELEASE_SIGNING_KEY}" -pubout -out "${public_key}" 2>/dev/null
  extra=()
  [[ "${DEVELOPMENT}" == false ]] || extra+=(--allow-development)
  python3 deploy/release/verify.py --bundle "${bundle}" --public-key "${public_key}" --version "${VERSION}" --architecture "${architecture}" "${extra[@]}"
  rm -f "${public_key}"
  tar -C "${OUTPUT}" -czf "${bundle}.tar.gz" "$(basename "${bundle}")"
done
