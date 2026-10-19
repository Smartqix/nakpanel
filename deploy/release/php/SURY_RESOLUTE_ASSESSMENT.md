# Signed Sury Resolute assessment — 2026-10-18

The earlier PPA-only check was incomplete: Ondrej's Launchpad Resolute path is
404, but the canonical [Sury PHP repository](https://packages.sury.org/php/)
serves a signed native Resolute distribution. This provides a credible maintained
external supply route for an **explicit fresh-host `ubuntu-26.04-sury` opt-in**.
The default native 8.5 profile and existing Noble/provider assignments stay
unchanged. Owned PHP builds can remain an optional fallback rather than a
necessary production repository service. Full parity still requires native
application/isolation/update qualification for the optional profile.

## Verified trust and artifacts

The [official source instructions](https://packages.sury.org/php/README.txt)
identify the upstream keyring package and repository-specific Signed-By path.
Downloaded evidence is at `/tmp/nakpanel-sury-resolute-assessment`.

| Item | Verified value |
| --- | --- |
| Official keyring `.deb` version | 2025.11.18 |
| `.deb` SHA256 | `7511384559c9ddf1d5ce5f60be429ae9d4e7d01d9480d6f1b7a30c0810cf8b60` |
| PHP keyring SHA256 | `b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c` |
| Primary fingerprint | `15058500A0235D97F5D10063B188E2B695BD4743` |
| Verified latest key renewal | 2025-11-17; expires 2028-02-04 |
| InRelease SHA256 | `edb2c103e800a113ad7cf0cf5460330abeb81188a3ca5c0c37d64feabc51d996` |
| Release date / identity | 2026-10-14; Origin `deb.sury.org`, Suite/Codename `resolute` |
| Advertised architectures | amd64, arm64, armhf (Nakpanel permits the first two) |
| amd64 Packages.xz SHA256 | `74195862ce25bbad35630f7d292ac8854cda5746106aea8ce8ac389956eba92e` |
| arm64 Packages.xz SHA256 | `9cd3951c63e1dc5ca6e802509ca8dc4d1b58f291037d37bd4098b1178745de2a` |

OpenPGP cryptographic verification checked the exact pinned primary and the latest
valid signed self-certification (the key retains older expired renewals). Both
compressed and uncompressed package-index lengths/SHA256 match authenticated
Release metadata. The actual fresh Resolute guest also passed real `gpgv` and
helper status/identity checks. The PHP-specific key, generic archive key and
`apt.gpg` are byte-identical for this snapshot.

**Do not dpkg-install the bootstrap keyring blindly:** its payload also contains
`/etc/apt/trusted.gpg.d/debsuryorg-archive.gpg`. The helper extracts and pins only
the PHP public key, installs it in `/usr/share/keyrings/nakpanel-sury-php.gpg`, and
binds one `.sources` entry through Signed-By. Hash/fingerprint changes require
review and an explicit pin update; this code does not silently rotate trust.

## Package and dependency coverage

Both signed indexes contain PHP **8.3.35, 8.4.26 and 8.5.11** CLI/FPM plus all
18 assessed package families: cli, fpm, bcmath, curl, gd, imagick, intl, mbstring,
mysql, redis, soap, xml, zip, common, readline, apcu, pgsql and sqlite3. PHP 8.3/8.4
have separate opcache packages; PHP 8.5 bundles OPcache. Versions explicitly name
`ubuntu26.04`; no Noble or Plesk artifact is involved.

Twenty-two actual CLI/FPM/common/opcache `.deb` downloads matched their signed
index SHA256 and sizes. All twelve actual CLI/FPM ELF headers match their claimed
amd64/arm64 architecture. Full lists and hashes are saved as
`downloaded-packages.json` and `elf-inspection.json` in the evidence directory.

Dependencies use native Resolute ABI names, including libxml2-16, libssl3t64,
libicu78, ImageMagick7, libcurl4t64, libzip5 and libc6 (8.5 requires >=2.43).
The independently built Resolute guest inventory already contains compatible
Ubuntu versions for these, libedit2, libsodium23, libxslt1.1, lz4/zstd and ucf.
Ubuntu's [libgd3 2.3.3-13ubuntu2](https://packages.ubuntu.com/resolute/libgd3)
satisfies the PHP >=2.3.3 dependency on both architectures. The live APT policy
selects this Ubuntu libgd3, while Sury's newer libgd3 is denied at priority -1.

## Controlled preparation and qualification

`deploy/install/sury.sh` is inert when sourced. The caller gates fresh enrollment
or a matching already-trusted profile, then calls
`sury_prepare_source ubuntu-26.04-sury`. OS metadata is parsed as data; actual OS,
version/codename and host architecture are checked. Before any source activation,
it verifies the pinned official `.deb`, extracted key/fingerprint, GPG signature
and exact Release identity. It writes PHP-only allow-first preferences at 500
(`php-common php8.3-* php8.4-* php8.5-*`, exact Release origin/codename) and denies
all other packages from packages.sury.org at -1. Parent package policy additionally
requires the exact HTTPS URI `/php`, selected candidate block and PHP package name.
The source is atomically activated last; no global trust or package install occurs
inside the helper.

Fresh native APT validation caught a real policy parser bug: a selected PHP
version can show priority 500 while its underlying repository line shows -1.
The parent's red/green fix accepts signed priority syntax only within the selected
candidate version and retains the exact URI/provider/package restrictions.

Fresh arm64 guest: `nakpanel-26-04-arm64-20261018170007-9bb317fa`; environment
record `/tmp/nakpanel-sury-php-run.env`. It is reserved for parent full-app reuse;
no panel binaries, database or platform installation state has been created here.
All three versions passed actual APT install, distro-descriptor CLI/INI/extensions,
isolated nonroot FPM/FastCGI/open_basedir, Composer @php workers and WP-CLI --info.
PHP 8.5 Composer emits a deprecation notice but succeeds; output is retained.
Guest handed over running for parent full application qualification. Evidence:
`/tmp/nakpanel-sury-native-evidence-20261018.tar.gz`, SHA256
`e7cf34c6d3ba2cf2be7a042a2725ae9eb6d21468498477a2efbf0bd3368496da`.
These are package/tool smokes; full details/limits appear in the Task 9 report. amd64 metadata/ELF coverage is
verified, but its native application run remains a separate qualification gate.

Sury provides maintained signed supply; the public project does not promise a
response SLA. The operator assigned Nakpanel project maintainers through GitHub
as the update owner; [PHP update operations](../../../docs/PHP_SECURITY_MAINTENANCE.md)
records monitoring, response targets, package retention and recovery requirements.
Actual security-patch/failed-update rehearsal and the full advertised native
profile/architecture matrix remain required before production parity claims.
