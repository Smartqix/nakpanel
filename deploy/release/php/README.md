# Private Resolute PHP candidates — optional fallback

An initial check found Ondrej's Launchpad Resolute path returned HTTP 404. A
broader verification subsequently identified the canonical signed Sury Resolute
repository with PHP 8.3/8.4/8.5 for amd64 and arm64. See
[SURY_RESOLUTE_ASSESSMENT.md](SURY_RESOLUTE_ASSESSMENT.md) for pinned trust,
package/dependency evidence and the separate fresh-host opt-in profile. The
private recipes below remain **unqualified optional fallback machinery**; an
owned production APT service is not required if the maintained external profile
passes qualification. Default native and existing Noble profiles remain intact.

`sources.lock.json` freezes PHP 8.3.35 and 8.4.26 (2026-09-24 security releases),
redis 6.3.0, imagick 3.8.1 and APCu 5.1.28, source URLs/digests/licenses, required
extensions and an empty patch list. PHP digests come from official release JSON:
https://www.php.net/releases/index.php?json&version=8.3 and
https://www.php.net/releases/index.php?json&version=8.4 . PECL archive SHA256s
were calculated from HTTPS upstream downloads; no independent upstream PECL
signature is claimed. Review these trust limits before qualification. PHP
signatures additionally require an independently verified PHP signer keyring;
branch-specific primary fingerprints are pinned from php.net’s official downloads
page, including validation of signing subkeys against their primary key.

Run `build-native.sh 8.3 OUTPUT` and `build-native.sh 8.4 OUTPUT` in a fresh,
disposable **native** Resolute builder for each amd64 and arm64 target. The
builder must have `build-dependencies.txt` installed in its own image. It must
supply `NAKPANEL_ISOLATED_PHP_BUILDER=1`, a stable `NAKPANEL_BUILDER_ID`, an exact
`NAKPANEL_BUILDER_IMAGE_DIGEST=sha256:...`, and `PHP_RELEASE_KEYRING`. The script
checks actual OS/codename/architecture and refuses existing private prefixes.
It does not install dependencies or change system services/alternatives.

Each package is named `nakpanel-php83` or `nakpanel-php84`, keeps CLI, FPM,
headers, modules and SAPI configuration under `/opt/nakpanel/php/8.3` or `8.4`,
and obtains native ELF library dependencies through `dpkg-shlibdeps`. There are
no `/usr/bin/php*`, `/etc/php/*`, distro units or global alternatives. Fixed
extension path is `PREFIX/lib/php/extensions`; CLI/FPM have separate php.ini,
conf.d and pool configuration matching the runtime descriptor. Generated CLI
extension tests must pass. `smoke-native.sh` additionally exercises separate CLI
and FPM INI files, all required modules, a dedicated FPM account and hardened
transient unit, and a real FastCGI request with filesystem/exec restrictions.
These are smoke tests rather than full application/tenant qualification.
The configured runtime resolver currently rejects these unqualified providers.

Evidence includes compiler versions/configure flags, complete dpkg native
library/build-tool inventory, verified PHP signer status, upstream source
licenses/digests, file-level SPDX 2.3 SBOM and in-toto/SLSA-shaped provenance.
Timestamps and path mapping reduce accidental nondeterminism; bit-for-bit
reproducibility has not been established. Builder image and native library
snapshot pins need independent reconstruction and two-build comparison.

`package.py` emits a real Debian ar package plus SHA256 and packages provenance
with it. `sign-candidates.sh OUTPUT` requires a supplied managed RSA signing key
and signs the inventory of all candidates/evidence. The manually requested CI
job depends on dedicated ephemeral native Resolute runners and configured
keyring/image/signing secrets; those services are not provisioned here.
`repository.sh CANDIDATES NEW_OUTPUT QUALIFICATION.json` creates signed APT
metadata offline, requires a supplied GPG identity, and refuses incomplete
qualification. It does not upload. Qualification must list exact `.deb` SHA256s
for both versions and architectures, a real `security_update_owner`, a
`security_response_policy`, and successful per-architecture checks named
`configuration`, `fastcgi`, `cli`, `composer`, `wp_cli`, `workers`,
`tenant_isolation`, `security_patch_delivery` and `failed_update_recovery`.
A release review must confirm that each check exercised **both** PHP versions.

The operator assigned Nakpanel project maintainers through GitHub as the update
owner. [PHP update operations](../../../docs/PHP_SECURITY_MAINTENANCE.md) defines
monitoring and internal response targets. Before rollout, rehearse an upstream
security patch, native rebuild/requalification, signed metadata refresh, staged
delivery, failed install and tested package rollback. No production delivery
endpoint is established by this code; policy assignment does not qualify one.
The scoped example `nakpanel-php.pref` permits only the two owned package names
and forbids this origin from supplying global libraries. Use a repository-specific
`Signed-By` trust key; do not add global APT trust or broad package pins.

The package `prerm remove` calls `panelctl runtime-provider-in-use --provider
nakpanel --php-version X.Y`; only successful exact `unused` output permits
removal. Actual DB current/desired/managed/retained runtime references and the
root-owned installed internal PHP profile protect the runtime; missing DB,
unknown profile or legacy incomplete backup inventory blocks removal. Legacy
hosts without a profile protect their internal PHP 8.3. Version-only site rows
protect any provider for that version conservatively. Upgrade/deconfigure paths
remain available for dpkg recovery. Quiesce tenant mutations for the full
check/remove transaction: the CLI check alone does not lock future assignments.
A qualified migration and provider registration/maintenance gate are prerequisites
to enabling these private runtimes.

Local tests validate package structure/private paths, fail-closed removal and
manifest integrity. Native arm64 qualification uses a separately owned disposable
Multipass Resolute builder. PHP 8.3.35 and 8.4.26 compiled with their required extensions,
produced dpkg-installable packages, and passed CLI/INI/extension and isolated
FPM/FastCGI smoke. Both also ran the pinned Composer and WP-CLI PHARs through
their private interpreters and a non-root Composer `@php` worker. These limited native smoke
tests do not qualify production provider activation: full application/worker,
isolation, security-patch and failed-update tests, plus the entire native amd64
matrix, remain required. See the Task 9 execution report for exact evidence.
