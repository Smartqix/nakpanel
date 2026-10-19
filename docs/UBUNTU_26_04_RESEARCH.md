# Ubuntu 26.04 support research and proposed design

Research date: 18 October 2026. Repository baseline: `ef8b5a7ebc0462cb90a1ae5b8fa98e4a3af46466`.

Nakpanel can plausibly support Ubuntu 26.04 alongside Ubuntu 24.04, but the present installer cannot safely establish that support. Retain the Go panel and agent, add explicit platform profiles and a shared PHP runtime descriptor, and qualify both releases against the same product and recovery requirements. Full PHP 8.3/8.4/8.5 parity on 26.04 is currently blocked through Nakpanel's existing package provider. Plesk demonstrates another route: maintaining actual packages for each supported distribution. A native PHP 8.5 profile is the smaller first milestone, after its internal webmail dependencies are repaired and tested.

This records the research baseline before implementation. The user subsequently authorized implementation; consult [native qualification](PLATFORM_QUALIFICATION.md) for the implemented gates and current evidence requirements. Observations below describe that baseline and do not establish production readiness.

An implementation-time refresh found a distinct Surý repository at `packages.sury.org/php/dists/resolute/`, while the Launchpad Resolute PPA still returns 404. Its signed package inventory and runtime compatibility require separate verification; absence of the old PPA alone no longer establishes absence of an upstream provider. The native 8.5 profile remains independent of that provider. [Current repository suites](https://packages.sury.org/php/dists/), [provider installation instructions](https://packages.sury.org/php/README.txt).

## How Plesk supports multiple operating systems

Plesk uses a tested platform matrix, distribution-specific packages and registered runtime locations. Its public installer index has separate `dist-deb-Ubuntu-24.04-x86_64` and `dist-deb-Ubuntu-26.04-x86_64` trees. Its PHP 8.4 index separately contains Ubuntu 26.04 packages, including `plesk-php84-fpm_8.4.26-ubuntu.26.04.260928.0615_amd64.deb` and matching extensions. These indexes were read directly over HTTP on the research date; no package was installed. This is direct evidence that Plesk supplies PHP beyond the distribution's default through its own builds. [Plesk 18.0.81 packages](https://autoinstall.plesk.com/PSA_18.0.81/), [Plesk PHP 8.4 Ubuntu 26.04 packages](https://autoinstall.plesk.com/PHP84_17/dist-deb-Ubuntu-26.04-x86_64/packages/)

Plesk's PHP handler registry records an ID, CLI/FPM paths, `php.ini`, SAPI, service and pool directory. It can report handlers/extensions as JSON and prevents removing a custom handler used by plans or websites. This separates a site's selected runtime from assumptions about the OS default. Nakpanel should adopt the descriptor pattern while preserving its own site isolation and readiness rules. [PHP handler interface](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/php_handler-php-handlers.72490/)

Support is still conditional. Plesk added Ubuntu 26.04 in 18.0.81 and documents unavailable features such as SOGo and Mailman. Its requirements explicitly list Ubuntu 22.04 for ARM; that does not establish Ubuntu 24.04/26.04 ARM support. Nakpanel needs its own release/architecture/feature matrix. [Ubuntu 26.04 support](https://support.plesk.com/hc/en-us/articles/40102608347031-Is-Ubuntu-26-04-supported-by-Plesk), [system requirements](https://docs.plesk.com/release-notes/obsidian/system-requirements/)

Plesk also separates panel updates from system-package updates, using native package managers and normally retaining each package's original repository. Its Ubuntu 24.04-to-26.04 upgrade is a separate staged procedure with prerequisites and recovery boundaries. Fresh OS support does not make an installed host safe to upgrade in place. These are useful lifecycle patterns for Nakpanel, without adopting Plesk packages or changing our security model. [Package update policy](https://docs.plesk.com/en-US/obsidian/administrator-guide/server-administration/plesk-for-linux-system-updates.75822/), [distribution upgrade procedure](https://support.plesk.com/hc/en-us/articles/12377714344983-How-to-perform-dist-upgrade-procedure-on-Linux-server-with-Plesk)

## What Go provides, and what Nakpanel must provide

Go targets a kernel family and architecture, such as `linux/amd64` or `linux/arm64`; it does not have separate Noble and Resolute compilation targets. Nakpanel already uses Linux build constraints for operations such as agent peer credentials. Keep one codebase and use runtime profiles for distribution package/path differences. Go's compatibility promise concerns Go programs and interfaces; it does not make external PHP, database, service or package-manager contracts identical. [Go targets](https://go.dev/doc/install/source), [build constraints](https://pkg.go.dev/cmd/go#hdr-Build_constraints), [Go compatibility](https://go.dev/doc/go1compat)

The ordinary Makefile leaves CGO selection implicit. Native CGO builds can acquire C-library dependencies. A build with `CGO_ENABLED=0` avoids cgo code, but its real output still needs inspection. [CGO build behavior](https://pkg.go.dev/cmd/cgo)

The unchanged repository source was successfully cross-built on this research date with the installed `go1.26.4 darwin/arm64` toolchain:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -o "$probe_dir/" ./cmd/panel ./cmd/agent ./cmd/panelctl
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build -trimpath -o "$probe_dir/" ./cmd/panel ./cmd/agent ./cmd/panelctl
```

Each command used a separate temporary output directory outside the repository. Both commands exited successfully. `file` identified all three amd64 artifacts as statically linked x86-64 ELF executables and all three arm64 artifacts as statically linked AArch64 ELF executables. Existing generated sources were used; the release generation pipeline was not exercised. This proves current-source static cross-build feasibility, not Ubuntu execution, release reproducibility or full support.

The recommended release model is one verified panel/agent/panelctl bundle per architecture, with the same artifact digest tested on both Ubuntu releases. Keep an explicit CPU baseline and a maintained pinned Go toolchain. Static executables still need compatible kernels, CA trust files, DNS configuration and host tools. Pure-Go DNS and user/group lookup differ from libc/NSS behavior; test lookup and supplemental groups under the actual hardened services before adopting the build policy. [DNS resolution](https://pkg.go.dev/net#hdr-Name_Resolution), [user lookup implementations](https://pkg.go.dev/os/user)

The existing installer still invokes Goose and River through `go run`, including with `--bin-dir`. Shipping the three binaries therefore does not yet remove production compiler/network dependencies. A later release-packaging improvement can bundle pinned migration executables and SQL assets; preserve existing migration ordering and rollback tests when doing so. No database-migration subcommand currently exists in `panelctl`. [Migration execution](/Users/rickynkansah/Projects/nakpanel/deploy/install/install.sh:347), [pinned migration tools](/Users/rickynkansah/Projects/nakpanel/Makefile:57)

## Reuse map for the existing system

| Existing Nakpanel component | Reuse directly | Missing compatibility layer |
| --- | --- | --- |
| Separate Go panel, privileged agent and panelctl; hardened systemd units | Keep process boundaries and Unix-socket authorization | Explicit portable build/release policy; qualify the same artifact on both releases |
| PHP CLI/FPM version, extension and isolated-start probes | Keep `RuntimeCapabilityProbe` and existing readiness reporting | Feed a shared descriptor into both discovery and every execution/rendering path |
| `RuntimeCapabilities.PHPRuntimes` and `PHPVersions` | Keep existing wire contracts and ready-runtime list | Report validated profile inventory and use it consistently in plan defaults |
| Immutable plans and plan activation readiness validation | Keep entitlement and fail-closed checks | Guarded fresh-profile defaults; no silent edits to current subscriptions |
| Bash phase installers and native configuration validators | Keep package/service integration and validators | One early OS/architecture/profile resolver plus package-origin preflight |
| Backup, restore, upgrade fault drills and Multipass fixtures | Extend the current test and recovery machinery | Provenance, safe test ownership and explicit native matrix |

The PHP descriptor is the most important runtime gap. Discovery currently stores absolute CLI/FPM paths, but site FPM units reconstruct `/usr/sbin/php-fpmX.Y`, pool directories reconstruct `/etc/php/X.Y`, and application/Composer commands reconstruct `/usr/bin/phpX.Y`. Adding a private PHP prefix to discovery alone would leave execution broken. [Discovery](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/php_capabilities.go:137), [site units](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/create_site.go:1015), [pool directory](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/create_site.go:193), [application CLI](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/php_application.go:453), [Composer](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/php_application.go:1084), [capability contract](/Users/rickynkansah/Projects/nakpanel/internal/types/envelope.go:810)

Start with one trusted descriptor per PHP version containing provider, version, CLI/FPM paths, INI/extension locations and supported pool/configuration roots. Wrap today's distro paths unchanged for Noble and use equivalent native-8.5 paths for Resolute. Use that descriptor for probes, per-site isolated FPM units, CLI/cron/worker/Composer/WP-CLI commands and internal tools. Retain generated tenant-owned paths and confinement; a vendor handler must not collapse tenants into a shared unrestricted service. Root-owned installer profiles supply descriptors; HTTP/RPC clients must never supply executable paths.

Existing sites can retain their version fields while each version maps unambiguously to one provider. Persist a handler ID only if multiple providers for the same version become a real requirement, with a backwards-compatible mapping for old records and backups. A generic plugin framework, wholesale container conversion, or separate panel fork per Ubuntu release is unnecessary for the initial support milestone.

## Scope and compatibility constraints

The requested outcome is additional Ubuntu 26.04 server support without breaking existing Ubuntu 24.04 installations. Preserve current tenant PHP selections, subscription snapshots, plan revisions, numeric system identities, mail stores, database credentials, TLS material, container image digests and security boundaries.

Treat these as three independent support claims:

| Claim | Initial position | Promotion requirement |
| --- | --- | --- |
| Fresh Nakpanel installation and application updates on Ubuntu 26.04 | Experimental until qualified | Full product, security, reboot and same-release restore gates |
| Migration from Ubuntu 24.04 to a fresh Ubuntu 26.04 host | Separate later milestone | Forward database/data/configuration migration and cutover rehearsal |
| In-place Ubuntu 24.04 to 26.04 OS upgrade | Outside the initial support claim | Dedicated OS-upgrade, repository, database-cluster and recovery design |

Keep reverse 26.04-to-24.04 and cross-architecture full-server restores unsupported until explicitly qualified. Ubuntu itself disables third-party repositories during a release upgrade, making the current PHP PPA a material migration dependency. [Ubuntu upgrade guidance](https://ubuntu.com/server/docs/how-to/software/upgrade-your-release/)

## Published platform changes

These are distribution package families, not instructions to change an existing server's versions. Security-pocket revisions change over time and must be recorded during qualification.

| Component | Current Ubuntu 24.04 baseline | Ubuntu 26.04 evidence | Nakpanel implication |
| --- | --- | --- | --- |
| PHP | Native 8.3; installer adds 8.4 and 8.5 from Ondrej PPA | Native PHP-FPM defaults to 8.5 | Internal PHP and tenant PHP availability need separate configuration. [PHP default package](https://packages.ubuntu.com/resolute/php/php-fpm) |
| PostgreSQL | Distro PostgreSQL 16 | Distro PostgreSQL 18 | Test panel SQL, migrations, River and dump/restore with each major. [24.04 package](https://packages.ubuntu.com/noble/postgresql-16), [26.04 package](https://packages.ubuntu.com/resolute/postgresql) |
| MariaDB | Distro 10.11 | Distro 11.8 | Test tenant SQL, authentication, grants, collation and logical migration. [24.04 package](https://packages.ubuntu.com/noble/mariadb-server), [26.04 package](https://packages.ubuntu.com/resolute/mariadb-server) |
| nginx | Distro packages and generated Debian-style configuration | 1.28 family | Exercise every vhost variant with native configuration validation. [26.04 package](https://packages.ubuntu.com/resolute/nginx) |
| BIND | Distro packages and custom zone includes | 9.20 family | Validate zones, configuration, authoritative answers and confinement. [26.04 package](https://packages.ubuntu.com/resolute/arm64/bind9) |
| Podman | Existing distro package, explicit slirp networking | 5.7 family | Test exact rootless and rootful command/environment contracts. [26.04 package](https://packages.ubuntu.com/resolute/podman) |
| systemd | 255 family | 259 family | Validate hardened units, cgroups and reboot persistence. [24.04 package](https://packages.ubuntu.com/noble/systemd), [26.04 package](https://packages.ubuntu.com/resolute/systemd) |
| OpenSSL | Existing distro TLS stack | 3.5 family | Exercise trusted TLS, private-key loading, FTPS and mail clients. [26.04 package](https://packages.ubuntu.com/resolute/openssl) |

Ubuntu also changed the default providers of `sudo` and many core utilities. Test the actual `sudo -u`, `stat -c`, `sort -V`, permission-setting and timeout behavior used by installers. Some commands remain GNU implementations in 26.04. Keep the stock providers during qualification; changing the entire provider set can conflict with `build-essential` dependencies. [Ubuntu utility compatibility reference](https://ubuntu.com/server/docs/reference/other-tools/sudo-rs/)

The release notes describe broader AppArmor confinement and amd64v3 cloud images. Validate the actual cloud image's CPU requirements, kernel, filesystem and confinement; an arm64 Multipass result does not establish amd64 cloud support. These platform differences are qualification risks, not demonstrated Nakpanel runtime failures. [Ubuntu LTS changes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/)

## Confirmed blockers in Nakpanel

### Installer rejection occurs after server changes

The unified installer only warns for an Ubuntu release other than 24.04 and skips its OS check when `/etc/os-release` is absent. A component installer later strictly rejects non-24.04 releases. Fresh mode installs binaries, sets up PostgreSQL and applies schema migrations before it reaches the component chain. That chain also requests PHP 8.3 before it adds the PHP PPA.

Evidence:

- [Unified OS check](/Users/rickynkansah/Projects/nakpanel/deploy/install/install.sh:84)
- [Fresh installation ordering](/Users/rickynkansah/Projects/nakpanel/deploy/install/install.sh:456)
- [PHP 8.3 package requirement](/Users/rickynkansah/Projects/nakpanel/deploy/install/phase7-install.sh:20)
- [Late strict OS rejection](/Users/rickynkansah/Projects/nakpanel/deploy/install/phase30-install.sh:15)

Add one shared platform resolver before package installation, application-file replacement, schema migration or service changes. Standalone component installers must enforce the same contract. Unknown releases, missing OS metadata and an existing installation whose recorded platform differs from its host must fail clearly.

### The current PHP provider has no verified Resolute repository

The installer explicitly requires PHP 8.3, 8.4 and 8.5 with their extensions. Its tests deliberately enforce all three and reject a runtime-subset override. [Installer contract](/Users/rickynkansah/Projects/nakpanel/deploy/install/phase30-install.sh:22), [contract tests](/Users/rickynkansah/Projects/nakpanel/deploy/multipass/phase30_install_test.go:107)

Direct HTTP observations on the research date:

```text
.../ondrej/php/ubuntu/dists/noble/Release    HTTP 200; Suite=noble; Codename=noble
.../ondrej/php/ubuntu/dists/resolute/Release HTTP 404
.../ondrej/php/ubuntu/dists/devel/Release    HTTP 200; Suite=noble; Codename=noble
```

The successful metadata was dated 12 October 2026. The published [PPA distribution index](https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/) also lacks Resolute. The `devel` alias therefore does not provide a valid workaround. Never use Noble packages, rewrite suite names, or relax signature checks on Resolute.

Native 8.5 extensions including Imagick, Redis and APCu are listed in the [Ubuntu PHP package index](https://packages.ubuntu.com/resolute/php/). That makes an explicit 8.5-only profile worth qualifying, but it does not satisfy the existing multi-PHP contract.

This is a blocker in our current supply path, not an inherent Ubuntu limitation. Full parity requires either a maintained signed Resolute provider or Nakpanel-owned distribution-specific PHP packages and extension builds, like the packaging pattern demonstrated above. Maintaining our own packages adds CVE response, rebuilds, signing, provenance and per-architecture qualification; it is a separate product commitment.

### Internal webmail and database tools are hardwired to PHP 8.3

Both HTTP and HTTPS webmail templates use `/run/php/php8.3-fpm.sock`. The optional database-manager service executes `/usr/sbin/php-fpm8.3`, and its installer independently rejects 26.04. Phase 18 requires 8.3 extensions and restarts its FPM service. [Webmail renderers](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/phase6.go:846), [database-manager unit](/Users/rickynkansah/Projects/nakpanel/deploy/systemd/nakpanel-database-manager.service:14), [mail installer](/Users/rickynkansah/Projects/nakpanel/deploy/install/phase18-install.sh:78)

The PHP used for these internal applications must come from a validated platform setting. Keep existing 24.04 installations on internal PHP 8.3. Use versioned binaries and matching extension packages for a 26.04 internal PHP 8.5 candidate. Tenant sites must continue using their own explicit runtime versions.

### Published Roundcube source conflicts with PHP 8.5

The Resolute package source page lists `roundcube 1.6.11+dfsg-1`. Its original source declares `function array_first($array)` unconditionally in `program/lib/Roundcube/bootstrap.php:308`. Inspection of its Debian patch archive found no `array_first` patch. The current amd64 Resolute updates/security universe indices inspected during this research contained no Roundcube replacement. [Ubuntu source package](https://packages.ubuntu.com/source/resolute/roundcube)

PHP 8.5 supplies that function natively, so this source has a redeclaration incompatibility when run there. This is a source-level finding; a freshly resolved, installed candidate still needs a live application test. [PHP array_first reference](https://www.php.net/manual/en/function.array-first.php)

Upstream now offers Roundcube 1.6.19 LTS and 1.7.4 stable with signed releases. The 1.6.19 source guards `array_first` with `function_exists`, removing this particular collision. Qualify 1.6.19 LTS first for the new profile, with verified release signatures/checksum, dependencies, existing configuration layout and SQLite/MariaDB session stores. This does not establish complete PHP 8.5 compatibility. Prefer a maintained fixed distribution package when it becomes available; an upstream package otherwise needs a defined update path and isolated installation directory. Avoid editing installed vendor PHP with one-off substitutions. [Upstream downloads](https://roundcube.net/download/), [1.6.19 bootstrap source](https://github.com/roundcube/roundcubemail/blob/1.6.19/program/lib/Roundcube/bootstrap.php)

### Plans can advertise runtimes absent on 26.04

The seed migration sets built-in plans to default 8.4 and allow 8.4/8.5/8.3. `PreferredNewSitePHPVersion` selects 8.4 whenever it is allowlisted. Plan activation correctly rejects every unavailable allowed runtime, so changing only a default is insufficient. The API already intersects allowed and ready runtimes, while browser provisioning follows a different resolver. [Seed migration](/Users/rickynkansah/Projects/nakpanel/migrations/20260927000051_seeded_php_runtime_defaults.sql:6), [selection helper](/Users/rickynkansah/Projects/nakpanel/internal/control/quota/quota.go:385), [readiness validation](/Users/rickynkansah/Projects/nakpanel/internal/control/policy/plan_contract.go:124), [API selection](/Users/rickynkansah/Projects/nakpanel/internal/control/provisioningapi/accounts.go:412)

For the native profile, bootstrap only new built-in plans to the validated 8.5 inventory through a guarded, audited fresh-install operation after existing migrations. Do not edit historical migrations or rewrite custom plans and existing subscription snapshots. Share default-selection behavior across browser and API paths, retaining the 24.04 preference for ready 8.4. An explicitly requested or restored 8.3/8.4 runtime must remain explicit and be rejected clearly if unavailable.

### Test tooling cannot safely identify a second platform

`ensure_vm` reuses an existing VM name without checking its guest OS or architecture. The canonical wrapper deletes legacy phase VMs, its target and its DR target. Naming a new target does not prevent the legacy sweep. `destroy_vm` itself has no ownership check, and a freely supplied DR name can collide with another lab. [VM reuse](/Users/rickynkansah/Projects/nakpanel/deploy/multipass/common.sh:118), [destructive wrapper](/Users/rickynkansah/Projects/nakpanel/deploy/multipass/deployment-verify.sh:12), [delete helper](/Users/rickynkansah/Projects/nakpanel/deploy/multipass/common.sh:235)

Make test environments safe before live 26.04 work: unique run/release/architecture identities, ownership tokens, guest identity assertions, distinct source/DR names and cleanup limited to the current run. Protect existing lab and soak VMs. Do not run the present wrapper with only an image override.

## Runtime qualification beyond installation

Core tenant PHP already probes CLI/FPM readiness. Reuse those probes through the shared runtime descriptor rather than reconstructing paths at execution sites. Add an actual FastCGI test for INI paths, extensions, sessions, uploads and database access; CLI module output alone does not prove the web SAPI works.

Podman readiness currently proves executable/helper presence rather than an actual confined workload. Test Nakpanel's explicit slirp networking, custom wrapper, rootless identity/environment, cgroup resource enforcement, loopback ingress, denied egress, health activation, volumes, secrets, rollback and teardown. Preserve AppArmor, existing service hardening and tenant isolation; adapt a narrow rule only when a reproducible denial warrants it. Valkey uses a different, rootful Podman service path and needs its own tests. [Rootless runtime](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/application_runtime.go:92), [Valkey unit rendering](/Users/rickynkansah/Projects/nakpanel/internal/agent/ops/hosting_toolkit.go:1666)

nginx/BIND configuration validators are already useful compatibility gates. No confirmed source-level blocker requires rewriting all their templates. Prove DNS UDP/TCP answers, ACME, trusted TLS, PHP and proxy routes, then verify after reboot. Exercise FTPS passive transfers and SSH/SFTP chroots under stock confinement.

Disk quotas depend on the actual `/home` backing filesystem and kernel modules. Verify enforcement and persistence before any manual repair after reboot; the present Phase 29 script remounts/re-enables quotas, which can conceal a startup defect. [Quota installation](/Users/rickynkansah/Projects/nakpanel/deploy/install/phase8-install.sh:33), [reboot verification](/Users/rickynkansah/Projects/nakpanel/deploy/multipass/phase29-verify.sh:453)

Pinned Go, Stalwart, Composer, WP-CLI and phpMyAdmin artifacts need an explicit compatibility inventory. The current Composer 2.8.11 pin predates further PHP 8.5 fixes in 2.8.12; test a maintained pinned candidate without coupling every dependency upgrade to the OS change. [Composer changelog](https://github.com/composer/composer/blob/main/CHANGELOG.md)

Stalwart is pinned to a GNU Linux binary. Validate dynamic-library requirements and full SMTP/IMAP/storage behavior on each architecture. A successful `--version` invocation or panel health response is insufficient. Existing Valkey image digests must remain unchanged during application updates. Our successful static Go probes do not establish the portability of ordinary Makefile outputs or third-party executables; inspect each actual release artifact. [Build commands](/Users/rickynkansah/Projects/nakpanel/Makefile:42)

## Backup and rollback boundaries

Application rollback saves selected Nakpanel binaries, service units, `/etc/nakpanel` and a panel database dump. It does not reverse APT packages/repositories, OS changes, all nginx/BIND edits, quota/fstab modifications or independently installed mail/PHP tooling. Preserve and test this application rollback, but describe its actual scope. Use whole-machine snapshots for later OS/package failure drills. Fresh mode currently offers cleanup rather than a full transaction rollback. [Backup scope](/Users/rickynkansah/Projects/nakpanel/deploy/install/install.sh:518)

The archive manifest records application/schema versions but lacks OS/architecture, database server/client versions and runtime inventory. Restore checks schema compatibility and then stops services; later it drops/recreates databases. Add optional provenance and a destination-compatibility check before service stops or file/database replacement. New readers must decode old archives; missing provenance must not be interpreted as permission for a cross-release restore. [Manifest](/Users/rickynkansah/Projects/nakpanel/internal/backup/archive.go:37), [restore preflight](/Users/rickynkansah/Projects/nakpanel/internal/backup/restore.go:94)

PostgreSQL supports forward logical migration but does not guarantee loading a newer dump into an older major. Select a compatible dump/restore toolchain and prove a real import. MariaDB SQL transfer also needs exact client/server compatibility: its sandbox directive is supported by updated 10.11 clients, so it is not automatically a current-Noble failure. [PostgreSQL compatibility notes](https://www.postgresql.org/docs/18/app-pgdump.html#APP-PGDUMP-NOTES), [MariaDB client versions](https://mariadb.com/docs/server/clients-and-utilities/mariadb-client/mariadb-command-line-client)

Full archives also carry generated PHP paths, nginx configuration, units, tenant artifacts and a paused Stalwart store. Do not overwrite target-native platform settings with source-host settings during migration. Check required runtime availability before restore and regenerate managed configuration only after an explicitly qualified migration. Preserve user content, identity ownership and secrets.

Phase 29's upgrade drills are Nakpanel application upgrades. Its DR path uses the same image and donor-native binaries, so it presently does not establish OS-release or CPU-architecture migration. [Application upgrade drill](/Users/rickynkansah/Projects/nakpanel/deploy/multipass/phase29-verify.sh:201), [DR provisioning](/Users/rickynkansah/Projects/nakpanel/deploy/multipass/phase29-verify.sh:495)

## Proposed architecture and alternatives

Use one shared installer platform resolver, with a small explicit mapping rather than scattered version comparisons. Record the successfully installed profile and internal runtime in root-owned installation state. The agent receives constrained runtime descriptors; it does not infer tenant PHP from the OS. A platform contract consists of OS release, architecture/CPU baseline, Nakpanel release, dependency origins/versions, enabled features and required verification evidence.

| Profile | Tenant runtime contract | Internal tools | Status |
| --- | --- | --- | --- |
| Ubuntu 24.04 Noble | Retain 8.3/8.4/8.5; retain ready 8.4 preference | Retain existing 8.3 behavior | Existing baseline and default |
| Ubuntu 26.04 Resolute native | Advertise only validated 8.5 | Qualified 8.5 plus fixed compatible webmail/tools | Proposed experimental profile |
| Ubuntu 26.04 Resolute with full PHP parity | 8.3/8.4/8.5 only after all are supplied and tested | Independently selected validated runtime | Separate provider/package project; not available through the present PPA |

Three approaches were considered:

1. **Native 26.04 profile first:** smallest dependency surface and earliest useful qualification. Runtime availability differs from 24.04 and must be explicit. Recommended for development, with full service gates before public support.
2. **Require exact PHP parity before any 26.04 support:** keeps the same runtime menu but depends on a real signed Resolute repository with all extensions on both architectures. Choose this if 8.3/8.4 hosting is a launch requirement.
3. **Supply Nakpanel PHP packages:** build native packages in isolated environments for each release/architecture, use a private prefix such as `/opt/nakpanel/php/8.4`, register them through the same descriptor, and maintain security updates/signatures/SBOMs. This follows Plesk's package separation while retaining our own provisioning model. Defer until parity justifies the ongoing maintenance, unless parity is a launch requirement. Containerized PHP is another larger design with separate file, network and isolation contracts; it is unnecessary for the initial native profile.

Do not change existing PHP alternatives, immutable plan revisions or tenant runtime choices to make a new host appear ready. A same-version installer invocation must still detect an OS/profile mismatch instead of returning a misleading successful no-op.

## Required verification and rollout

Use four native qualification cells: Ubuntu 24.04 and 26.04, each on amd64 and arm64. Keep the 24.04 image and existing lab defaults. Linux containers or cross-compilation alone cannot qualify systemd, AppArmor, quotas and rootless networking.

| Gate | Required evidence in each supported cell |
| --- | --- |
| Preflight and test ownership | Unsupported/mismatched hosts and unowned/protected VMs reject before mutation; same-OS reruns remain supported |
| Clean install | Canonical fresh installer on a genuinely new host; package origins/versions recorded; native config and application checks pass |
| Application update | Real previous Nakpanel release with populated tenants; no-op, downgrade refusal and injected rollback failures |
| Product behavior | PHP/WordPress/managed releases/workers, database SSO, mail send/read/webmail, DNS/TLS, backups, Git, scheduled tasks, file access, statistics, containers and Valkey |
| Security and reboot | Tenant denial tests, filesystem/agent boundaries and resource enforcement before/after reboot; capture failures before repairs |
| Same-release recovery | Fresh 24.04-to-24.04 and 26.04-to-26.04 restoration; tenant/mail contents and desired stopped states verified |

Add a separate later forward migration cell for 24.04-to-fresh-26.04, initially on the same architecture. Require source data retention, a compatible runtime inventory, real PostgreSQL/MariaDB import, mail-store compatibility, regenerated managed configuration, trusted TLS, a second reboot and an explicit cutover/rollback boundary.

Current CI uses `ubuntu-latest`, requests Go 1.22 despite a Go 1.23 module minimum, and runs security/Phase 29 rather than the entire modern product chain. Add explicit guest release/architecture jobs and preserve baseline required checks. Use unique run names and serialized access to native runners where needed. [Current workflow](/Users/rickynkansah/Projects/nakpanel/.github/workflows/ci.yml:14)

The [proposed implementation plan](/Users/rickynkansah/Projects/nakpanel/docs/superpowers/plans/2026-10-18-ubuntu-26-04-support.md) orders work as: safe harness, strict profiles/preflight, portable release artifacts, PHP descriptors, internal tooling, fresh plan defaults, restore provenance and full dual-release qualification. Optional multi-PHP packages and forward migration have separate gates. Promote 26.04 only after complete native evidence passes on each advertised architecture. Keep in-place OS upgrade outside the initial support claim.

## Research evidence and limits

Local source audits covered installers, runtime provisioning, plan selection, CI, verification and archive/restore contracts. Official Ubuntu/upstream/Plesk/Go documentation, vendor package indexes, PPA Release responses, Roundcube source tarballs and the current amd64 Resolute updates/security universe indices were inspected. Six unchanged-source static Go cross-builds passed as described above. No installer, service, existing VM or deployed system was changed. Package availability observations must be refreshed when implementation starts; they do not substitute for signed APT resolution and native application tests.

### Architecture follow-up — 19 October 2026

Canonical confirms that Ubuntu26.04's `amd64v3` package variant is opt-in, preserving the ordinary AMD64 installation path. It requires additional CPU features such as AVX2, FMA and BMI2. Keep the explicit conservative Go binary baseline and the pinned ordinary AMD64 qualification images; enabling a different image/package variant needs its own hardware validation. The installer does not enable `APT::Architecture-Variants`. [Ubuntu26.04 architecture variants](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#architecture-variants-and-amd64v3), [supported architectures](https://ubuntu.com/project/docs/how-ubuntu-is-made/concepts/supported-architectures/)
