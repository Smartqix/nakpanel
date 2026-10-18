#!/usr/bin/env bash
# Invoke only inside a disposable native Resolute VM/container with preinstalled
# dependencies. No APT changes, global PHP alternatives, or service activation.
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ "${NAKPANEL_ISOLATED_PHP_BUILDER:-}" == 1 ]] || { echo 'requires disposable isolated native builder' >&2; exit 1; }
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID}" == ubuntu && "${VERSION_ID}" == 26.04 && "${VERSION_CODENAME}" == resolute ]] || { echo 'requires native Ubuntu 26.04 Resolute' >&2; exit 1; }
architecture="$(dpkg --print-architecture)"
case "${architecture}:$(uname -m)" in amd64:x86_64|arm64:aarch64) ;; *) echo 'native amd64/arm64 only; no cross-distro or emulated build' >&2; exit 1 ;; esac
minor="${1:?usage: build-native.sh 8.3|8.4 output-directory}"
[[ "${minor}" == 8.3 || "${minor}" == 8.4 ]] || exit 1
output="${2:?output directory required}"
mkdir -p "${output}"; output="$(cd "${output}" && pwd)"
: "${NAKPANEL_BUILDER_ID:?identify the managed isolated builder}"
: "${NAKPANEL_BUILDER_IMAGE_DIGEST:?pin the isolated native builder image sha256 digest}"
[[ "${NAKPANEL_BUILDER_IMAGE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'invalid builder image digest' >&2; exit 1; }
: "${PHP_RELEASE_KEYRING:?supply separately verified PHP release signer keyring}"
prefix="/opt/nakpanel/php/${minor}"
[[ ! -e "${prefix}" ]] || { echo 'private prefix already exists; use a fresh builder' >&2; exit 1; }
export SOURCE_DATE_EPOCH=1790208000 TZ=UTC LC_ALL=C
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
sources="${work}/sources"; evidence="${work}/evidence"; stage="${work}/stage"
mkdir -p "${sources}" "${evidence}" "${stage}/opt/nakpanel/php"
python3 "${HERE}/fetch.py" --minor "${minor}" --output "${sources}" --php-keyring "${PHP_RELEASE_KEYRING}"
version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["php"][sys.argv[2]]["version"])' "${HERE}/sources.lock.json" "${minor}")"
export CFLAGS="-O2 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -ffile-prefix-map=${work}=."
export CXXFLAGS="${CFLAGS}" LDFLAGS='-Wl,-z,relro,-z,now'
export EXTENSION_DIR="${prefix}/lib/php/extensions"
tar -xf "${sources}/php-${version}.tar.xz" -C "${work}" --no-same-owner --no-same-permissions
cd "${work}/php-${version}"
./configure --prefix="${prefix}" --with-config-file-path="${prefix}/etc/cli" \
 --with-config-file-scan-dir="${prefix}/etc/cli/conf.d" --with-libdir="lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)" \
 --disable-phpdbg --without-pear --enable-fpm --with-fpm-systemd --with-fpm-user=www-data --with-fpm-group=www-data \
 --enable-bcmath --with-curl --enable-exif --enable-gd --with-jpeg --with-webp --with-freetype --with-avif \
 --with-password-argon2 --with-gettext --with-iconv --with-openssl --with-zlib --enable-intl --enable-mbstring \
 --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd --with-pdo-pgsql --with-pgsql --with-pdo-sqlite --with-sqlite3 \
 --enable-soap --with-zip --with-readline --enable-opcache --enable-pcntl --enable-sockets
cp config.nice "${evidence}/config.nice"
cp LICENSE "${evidence}/PHP-LICENSE"
cp Zend/LICENSE "${evidence}/Zend-LICENSE"
make -j"$(nproc)"
# Installing only into the absent private prefix in this disposable builder lets
# phpize/php-config resolve the installed headers without temporary path rewrites.
make install
mkdir -p "${prefix}/etc/cli/conf.d" "${prefix}/etc/fpm/conf.d" "${prefix}/etc/fpm/pool.d"
cp php.ini-production "${prefix}/etc/cli/php.ini"
cp php.ini-production "${prefix}/etc/fpm/php.ini"
for extension in redis imagick apcu; do
  ext_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["extensions"][sys.argv[2]]["version"])' "${HERE}/sources.lock.json" "${extension}")"
  tar -xf "${sources}/${extension}-${ext_version}.tgz" -C "${work}" --no-same-owner --no-same-permissions
  cd "${work}/${extension}-${ext_version}"
  for license in LICENSE COPYING; do if [[ -f "${license}" ]]; then cp "${license}" "${evidence}/${extension}-${license}"; fi; done
  "${prefix}/bin/phpize"
  ./configure --with-php-config="${prefix}/bin/php-config"
  make -j"$(nproc)"; make install
  for sapi in cli fpm; do printf 'extension=%s.so\n' "${extension}" > "${prefix}/etc/${sapi}/conf.d/20-${extension}.ini"; done
done
for sapi in cli fpm; do printf 'zend_extension=%s/lib/php/extensions/opcache.so\n' "${prefix}" > "${prefix}/etc/${sapi}/conf.d/10-opcache.ini"; done
# No default tenant pool is activated by this package. The runtime descriptor
# provisions isolated pools and units after qualification and registration.
printf '[global]\ninclude=%s/etc/fpm/pool.d/*.conf\n' "${prefix}" > "${prefix}/etc/fpm/php-fpm.conf"
PHP_INI_SCAN_DIR="${prefix}/etc/cli/conf.d" "${prefix}/bin/php" -c "${prefix}/etc/cli/php.ini" -r '
$required=json_decode(file_get_contents($argv[1]),true)["required_extensions"];
foreach($required as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR,"Missing extension: $extension\n"); exit(1); } }
echo PHP_VERSION," CLI extensions verified\n";
' "${HERE}/sources.lock.json" | tee "${evidence}/cli-extension-test.txt"
# Record every native tool/library package and derive real ELF library deps.
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > "${evidence}/build-dependencies.txt"
cc --version > "${evidence}/compiler.txt"
cp "${HERE}/sources.lock.json" "${evidence}/sources.lock.json"
cp "${sources}/php-signature-status.txt" "${evidence}/php-signature-status.txt"
cp "${sources}/php-${version}.tar.xz.asc" "${evidence}/php-source.asc"
cp "${PHP_RELEASE_KEYRING}" "${evidence}/php-release-keyring.gpg"
mkdir -p "${work}/debian"
printf 'Source: nakpanel-php\nSection: web\nPriority: optional\nMaintainer: Nakpanel Release Engineering <releases@nakpanel.invalid>\n\nPackage: nakpanel-php%s\nArchitecture: any\nDescription: Private PHP runtime\n' "${minor//./}" > "${work}/debian/control"
cd "${work}"
elf_args=()
while IFS= read -r -d '' file; do elf_args+=("-e${file}"); done < <(find "${prefix}" -type f \( -name php -o -name php-fpm -o -name '*.so' \) -print0)
dpkg-shlibdeps -O "${elf_args[@]}" | sed -n 's/^shlibs:Depends=//p' > "${work}/dependencies.txt"
python3 "${HERE}/provenance.py" --prefix "${prefix}" --evidence "${evidence}" --architecture "${architecture}" --version "${version}"
cp -a "${prefix}" "${stage}/opt/nakpanel/php/"
cp -R "${evidence}" "${output}/evidence-${minor}-${architecture}"
python3 "${HERE}/package.py" --stage "${stage}" --minor "${minor}" --version "${version}" --architecture "${architecture}" --dependencies "${work}/dependencies.txt" --evidence "${evidence}" --output "${output}"
echo 'BUILD CANDIDATE ONLY: FPM/FastCGI, isolation, Composer/WP-CLI, workers, update/rollback and both-architecture qualification remain required.'
