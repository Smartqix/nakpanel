# Disposable GitHub-hosted AMD64 qualification

The workflow `.github/workflows/ubuntu-hosted-qualification.yml` supplies an
AMD64 qualification path without registered self-hosted runners. It runs on
manual dispatch, or on pushes **only** to `codex/ubuntu-26-support`, so the
isolated review branch can execute it before the workflow reaches the default
branch. It does not run on pushes to main, arbitrary branches or pull requests.
Push events use the same explicit verified image defaults as manual dispatch.
All jobs require a public repository; this workflow does not opt into private
repository runner charges.

No passing live result is implied by the workflow's existence. Parent review
and an actual workflow run are required before claiming either AMD64 cell.
This complements the local native ARM64 cells and does not replace them.

## Required CI production-schema tests

The existing `unit + generated-code + go test` check uses an isolated PostgreSQL
16 instance on its Ubuntu24.04 runner. Its data and Unix socket directories are
private to that job, TCP listening is disabled and the observed data directory
and effective listening setting must match before tests start. Cleanup stops
only that job's instance.

Mail/forward fixtures and PHP-only plan tests use different databases in that
instance. Production subscription advisory locks are database-wide, so separate
schemas with the same seeded subscription IDs are insufficient for concurrent
Go packages. Every pooled plan-test connection also selects its own schema at
startup. `NAKPANEL_REQUIRE_PLAN_PHP_POSTGRES=1` makes a missing plan-test DSN fail
instead of skipping actual schema55/56 preservation and concurrency tests.
Candidate 20 executed this private PostgreSQL 16 startup and owned cleanup in the
hosted unit job, and its quota package passed. The complete unit job failed
separate database-manager fixture assertions. The retained log contains the
data-directory/Unix/no-TCP assertion and successful subsequent control flow;
its SQL result was captured silently, so direct observed field values are not
claimed. This does not establish a passing full CI or native qualification result.

## Disposable runner bootstrap

The first Snap installation can also download dependencies; Snap authenticates
those downloads through its store. Canonical documents the
[installation transaction](https://snapcraft.io/docs/tutorials/get-started/) and
[network availability requirements](https://snapcraft.io/docs/how-to-guides/manage-snaps/fix-common-issues/).
Candidate 20 had several dependency download failures before creating a guest.
Those original failures remain retained as infrastructure preparation failures.

The shared runner helper permits at most three Multipass Snap installation
attempts, with 10-second and 20-second backoffs. Each attempt uses
the same authenticated store command with a 360-second timeout and a five-second
kill grace. Separate original stdout, stderr and exit-code files are retained
privately for every attempt, including failures before a later success.

Only ordinary exit code 1 is retried. Timeouts and other exit codes stop
preparation immediately: the helper does not start another installation or
attempt to repair an unknown backend state. Successful installation must still
pass the existing daemon, certificate, socket/ACL, KVM and capacity checks.
These retries apply only to disposable runner preparation, before guest
ownership and product qualification. They do not repeat failed product gates or
change any original report.

## Feasibility and resource evidence

GitHub documents standard public-repository `ubuntu-24.04` x64 runners as
4 vCPUs, 16 GB RAM and 14 GB storage, with free unlimited standard hosted
compute for public repositories. See the [GitHub-hosted runner
reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
The image contents are recorded in the official [Ubuntu2404 runner
manifest](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).

GitHub explicitly announced Linux KVM hardware acceleration, including standard
runners, in its [hardware accelerated virtualization
announcement](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/).
Canonical states that [Multipass uses KVM on
Linux](https://github.com/canonical/multipass). The inference is that the same
exposed KVM facility can support these Multipass guests; it is not a guarantee
for every future runner allocation. The workflow verifies `/dev/kvm` API12 and
successful `KVM_CREATE_VM` before launching any guest. Missing acceleration
fails with evidence; software emulation cannot count as native qualification.

The published 14 GB storage floor is insufficient for this suite. An official
runner-images maintainer explains that additional free storage is not promised
and describes reclaiming unused preinstalled SDKs in this [disk-space
issue](https://github.com/actions/runner/issues/954). Accordingly, only on its
own disposable `github-hosted` VM, this workflow removes unused Android/.NET/
Swift/Haskell/Java/CodeQL/PowerShell/Conda trees and unused Docker images. It
preserves the selected Go toolchain and Node.js. It measures actual space after
staging artifacts/images and requires **48 GiB free**, **14 GiB total memory**,
**11 GiB available memory**, four host vCPUs and usable KVM. If the allocation
cannot provide these, it fails before guest launch and uploads the capacity
report. Reclamation is not reported as guaranteed extra storage.

Explicit qualification-only resource settings allocate source/historical
upgrade guests 2 vCPUs, 5 GiB RAM and 32 GiB virtual disks. DR gets 2 vCPUs,
3 GiB RAM and a 16 GiB virtual disk. The completed historical guest is destroyed
through validated ownership before the DR leg begins. Thus at most two guests
coexist: ten GiB during the historical upgrade and eight GiB during DR, leaving
RAM for the host. Virtual disks are sparse; the measured free-space gate and
subsequent real installation/backup/restore operations remain authoritative.
Ordinary harness resource defaults and all product gates remain unchanged.

`hosted-runner-preflight.py` writes the measured host/image/resources and
failure reasons with `qualification_passed:false`. A successful host capacity
probe is not a product qualification result.

## Genuine current/prior artifacts

One native AMD64 build job creates the current application bundle and the real
historical source baseline
`ef8b5a7ebc0462cb90a1ae5b8fa98e4a3af46466`. Only packaging machinery is copied
into that checkout. Its `cmd`, `internal`, migrations and historical installers
remain the pinned historical application sources and are actually compiled.
The historical application is not simulated by changing the current VERSION.

The release builder is explicitly restricted to AMD64 using
`NAKPANEL_RELEASE_ARCHITECTURES=amd64`; its ordinary default still builds both
architectures. An ephemeral test key signs both bundles. A tracked README
marker makes each build explicitly dirty/development without changing the
application's comparable VERSION contract. Every manifest must state
`development:true`, and the historical manifest must contain the exact pinned
source commit. Actual historical and candidate commits must differ.

The artifact upload contains the signed bundle archives, **public key only**,
source/version metadata and image-selection evidence. The private key stays
outside the upload tree and is removed in an always-run cleanup step. Both
Ubuntu cell jobs download the same current AMD64 bundle artifact; neither
rebuilds it. Their final summary requires both complete reports and identical
signed current release manifests. These test-key results are always
nonpromotion, even if all native product gates pass. Artifacts are retained
for three days.

## Signed and pinned Ubuntu cloud images

Defaults were checked against Canonical's release indexes on 2026-10-18:

| Guest | Official dated release | AMD64 SHA256 |
|---|---|---|
| 24.04 | [Noble release-20261017](https://cloud-images.ubuntu.com/releases/noble/release-20261017/) | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` |
| 26.04 | [Resolute release-20260927](https://cloud-images.ubuntu.com/releases/resolute/release-20260927/) | `8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2` |

Each dispatch can explicitly select another official dated serial and an
independently checked SHA256. The build job verifies Canonical's signed
`SHA256SUMS.gpg` using the Ubuntu-packaged cloud-image keyring and requires the
selected filename's digest to equal that pin. Each cell verifies the signature
again and hashes the actual downloaded local image before use. Canonical
publishes this [cloud-image verification
procedure](https://ubuntu.com/docs/public-images/public-images-reference/artifacts/).
There is no PPA-suite substitution, devel image alias or unsigned image bypass.
Actual guest Ubuntu version, architecture and host/guest ownership markers
remain mandatory. Resolute's separate historical24 guest uses the Noble pin.

## Execution and evidence

After code review, the parent can push the isolated review branch, or dispatch
**Hosted Ubuntu AMD64 qualification** once it is available on the default
branch. No self-hosted runner label, production signing key or new cloud host
is required for the attempt. This document does not authorize a child agent to
push, publish or dispatch it.

Both release jobs call `ubuntu-platform-verify.sh`, including its fresh clean
installer, genuine populated prior24 upgrade, native26 same-profile update,
rootless OCI/rootful Valkey boundaries and cgroups, full security suite,
synthetic rollback, reboot and same-OS DR, native PHP, service plans, Toolkit,
webmail, uninstall, GoAccess and domain removal. Database-manager FastCGI and browser coverage is required for push runs and
by default for manual dispatches. An explicit manual
`verify_database_manager=false` leaves that optional feature unrequested;
such a result does not establish its coverage. The
required Mail workspace browser uses pinned Playwright1.64.1 and installed
Chrome even when that optional database feature is not requested. Dispatch
`php_provider=sury` selects the optional `ubuntu-26.04-sury` profile only for
the 26.04 cell, including PHP 8.3, 8.4 and 8.5 gates. The 24.04 cell and its
historical upgrade guest keep their original profile. Push runs and default
dispatches use native PHP 8.5 on 26.04; the four-cell self-hosted workflow is
unchanged. The cell report records the provider and PHP parity. Required
features are not skipped to fit the hosted runner.

Each job always attempts owned-only guest cleanup and uploads host preflight,
image/bundle metadata, cell report, inventory and gate logs. Cleanup never uses
a global Multipass purge. The summary fails for missing/failed cells, differing
current manifests or any result incorrectly marked promotable. A capacity,
package, registry, VM, feature or timeout failure remains a failed run, with
its evidence available for diagnosis. Long-running soak remains separate.

Internal-tools logs contain fixed stage markers. On failure, the bounded
nonhidden `internal-tools-diagnostic.json` records the actual child exit and
cleanup state, and a strictly validated protocol status/error/send count when
available. Missing or invalid observations stay unknown. The diagnostic
contains no credentials, session values or message bodies and never grants
qualification. Private hidden raw evidence remains excluded from broad uploads.

The Mail workspace gate covers real browser creation/editing/password rotation,
alias delivery, SMTP TLS/STARTTLS and IMAP retrieval, unrelated-customer denial,
and QA cleanup. It trusts the installed Stalwart certificate explicitly inside
the guest and keeps hostname/certificate verification enabled. Random QA
credentials remain outside uploaded artifacts. Configured public-HTTPS webmail
popup handoff is separate; actual Roundcube FastCGI/login remains mandatory.
## Surý same-version maintenance coverage

This new coverage is pending actual hosted acceptance. Its source tests do not
establish a completed AMD64 maintenance rehearsal.

An explicit Surý26 dispatch defaults `verify_sury_maintenance` to true and
requires `verify_database_manager=true`. After all17 canonical gates finish in
an isolated, reaped process group, the additional step runs a fresh real
Roundcube send/read, takes an owned quiesced cold snapshot, restarts and verifies
the selected runtime, and retains its exact installed PHP8.3/8.4/8.5 dependency
closure from natively verified Surý Resolute metadata. Both architecture indexes
are authenticated; the actual AMD64 guest packages are downloaded and retained
privately on that runner. The existing maintenance controller then performs a
real same-version reinstall, failed FPM configuration recovery for each minor,
two reboots and three additional fresh Roundcube send/read flows. Database-manager
checks after maintenance prove actual FastCGI health; the full restricted-browser
workflow belongs to the initial canonical baseline. This does not prove a
security version advance or APT version rollback. Explicitly disabling the
maintenance input leaves that coverage unrequested. Private specs, package
archives and credentials stay outside uploaded evidence; only the allowlisted
receipts and results enter the existing always-upload directory. Owned cleanup
remains responsible for this run's guests and their snapshots.
