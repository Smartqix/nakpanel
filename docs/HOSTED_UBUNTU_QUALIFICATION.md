# Hosted Ubuntu 26.04 AMD64 qualification

The hosted workflow targets one server OS: Ubuntu 26.04/resolute on AMD64,
using the signed Surý PHP 8.3/8.4/8.5 profile and internal PHP 8.5. Hosted
Phase 3 operational/maintenance acceptance passed on `63c00f6`; the focused
Phase 4 scheduled-backup/restore slice passed on `0654aa3`, as recorded below.
The `1140165` verifier diagnostics change has focused local evidence and
does not change the served runtime. PR #13 required CI, including hosted
security/reliability, passed in run `39696504919`. The 21 October checkpoint
authorized consolidation into main and deletion of merged branches, with required
main CI and no deployment. See the
[consolidation record](verification/2026-10-21-main-consolidation.md).
After PR #14 merged, main checks passed on `3879f77`, followed by the explicitly
authorized nakpanel.com development deployment and focused live mail checks;
see the [23 October deployment record](verification/2026-10-23-subdomain-mail-deployment.md).
This dedicated qualification workflow remains manual-only; branch deletion and
documentation closeout must not launch unchanged optional qualification.
Ubuntu 26.04 remains experimental pending remaining release qualification.
See [platform qualification](PLATFORM_QUALIFICATION.md) and the
[transition plan](superpowers/plans/2026-10-18-ubuntu-26-04-support.md).

## Runner, artifacts and image

The reusable `prepare-hosted-runner.sh` acts only on a disposable GitHub-hosted
runner. Its measured KVM, memory and disk preflight runs before guest launch.
The hosted runner label `ubuntu-24.04` is a build/VM-host choice, not a supported
Nakpanel server OS. Native ARM64 still requires its own qualified runner; this
AMD64 workflow cannot establish that support.

The canonical full qualification builds the current signed AMD64
panel/agent/panelctl bundle with an ephemeral test key. Authenticate its exact
manifest, executable inventory and architecture before staging. Development
bundles remain nonpromotable; no historical checkout or Noble guest is required.
The focused backup mode separately authenticates its pinned accepted Phase 3
artifact; selecting its current-build option installs fresh current-run signed
bytes. See the focused-mode constraints below.

Both the main CI security job and the dedicated hosted workflow select:

| OS image | Release serial | SHA256 |
| --- | --- | --- |
| Ubuntu 26.04 AMD64 | `20260927` | `8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2` |

These are frozen selections, not an instruction to trust an unverified download.
Check the exact image against signed Ubuntu SHA256 sums and verify downloaded
bytes. Any replacement image needs a separately verified pin. The existing
artifact/digest/signature checks and live guest identity assertions remain
mandatory. Transfer archives are parsed safely and staged privately.

## Execution and evidence

Fresh source and DR guests have unique run tokens, exact ownership records and
distinct names. Never adopt an existing VM, sweep legacy VM names or clean up a
protected lab/soak. Always retain bounded diagnostic evidence and then perform
ownership-checked cleanup, including on failure.

The canonical workflow has 16 current-version gates, explicitly excluding
`real-upgrade`. Its report must say `CURRENT_VERSION_ONLY`, contain the complete
PHP runtime contract and record every actual pass/failure/skip. It still proves
fresh install, product/security boundaries, current application recovery,
containers/Valkey, quotas, reboot and same-OS disaster recovery. The required
main CI security check retains its identity and fail-closed dependency on the
signed build. A failed/cancelled build cannot silently skip required security.

The final hosted summary requires the complete 26.04 AMD64 report and its signed
current manifest, with no unexpected/missing cell or false production-promotion
claim. Every advertised architecture needs separate evidence. Local unit tests,
static compilation and workflow lint do not establish hosted acceptance.

## PHP maintenance recovery

Maintenance uses the already qualified current-version Surý source and requires
actual database-manager/browser coverage. Its prerequisites are exactly the 16
current-version gates, bound to the selected source, run, application and hashes.
Explicitly excluding historical upgrade work does not bypass a current gate.

The actual drill must prove signed same-version PHP package delivery, the owned
FPM configuration fault, the expected APT/dpkg failure and half-configured state,
recovery, two distinct reboots and three real Roundcube send/read assertions.
Required package/version/origin, isolation, cleanup and drain checks remain
strict. The summary checks the actual maintenance result and its source binding;
prerequisite success or an output file's presence is insufficient.

A manual maintenance opt-out must be recorded as `NOT_REQUESTED` and cannot
claim maintenance acceptance. Same-version delivery does not prove a genuine
security-version advance, APT downgrade rollback or Nakpanel application rollback.

## Phase 3 diagnosis and verification

Run [39632906571](https://github.com/Smartqix/nakpanel/actions/runs/39632906571)
on `a82d6ec` passed all 16 current-version gates, then failed real PHP maintenance
configuration recovery. Its new safe error frames identified the package step.
All owned guests were cleaned up; no maintenance reboot was verified.

The optional `diagnose_php_maintenance` dispatch isolates package recovery on a
fresh owned, credential-free Ubuntu 26.04 AMD64 KVM guest. It reuses the actual
maintenance backend, signed pinned image and trusted Surý source for PHP
8.3/8.4/8.5. It cannot run with `diagnose_fwupd`; product jobs and the product
summary are skipped. Its PASS explicitly sets `product_qualified=false` and
`reboots_verified=false`. Inspect the separate owned-cleanup exit receipt as
well as its package log. This diagnostic avoids repeating the full application
baseline solely to collect an APT error; it never replaces product qualification.

Diagnostic [39647396390](https://github.com/Smartqix/nakpanel/actions/runs/39647396390)
proved APT rejects `--reinstall` of the half-configured FPM package with
`Internal Error, No file name`, despite all 56 cached archives being present.
The next diagnostic
[39649611313](https://github.com/Smartqix/nakpanel/actions/runs/39649611313)
confirmed configuration-only APT reached postinst, but its FPM restart hit the
start limit consumed by the deliberate fault. Owned cleanup passed for this run.

Commit `63c00f6` finishes configuration of only the exact pending FPM package,
after restoring the owned configuration, verifying the original full package
inventory and signed installed postinst, and accepting only a Conf-only APT
simulation. It preserves the affected unit's state before clearing only that
unit's start counter; the actual transaction forbids downloads and removals.
Postboot validation still observes unassisted state and performs no service
repair. Diagnostic
[39651263936](https://github.com/Smartqix/nakpanel/actions/runs/39651263936)
passed actual failed-configuration recovery for all three PHP minors and owned
cleanup on that commit.

Full product run
[39652821843](https://github.com/Smartqix/nakpanel/actions/runs/39652821843)
passed on runtime/qualifier commit
`63c00f6006df3bba1ca9ef474e0f350ff7835165`, with database-manager and PHP
maintenance required. All 16 canonical gates passed in 77m40s. Maintenance
preparation, actual same-version recovery and both reboots passed in 10m11s.
The downloaded receipts confirm two distinct new boot IDs, unassisted service
health, all three PHP minors, three fresh actual Roundcube send/read executions,
unchanged package/configuration/desired state and database-manager FastCGI
health. Owned cleanup and the workflow summary passed. Phase 3 is complete for
this AMD64 development profile. Focused Phase 4 verification is described below.
Genuine security-version
advancement, ARM64 qualification and elapsed soak remain separate requirements.

### Hosted firmware scope

The optional `diagnose_fwupd` dispatch runs a bounded standalone reproduction
on the pinned image, retains the vendor unit/journal and destroys its owned
guest. It does not build or qualify Nakpanel.

Product qualification explicitly enables `NAKPANEL_HOSTED_GUEST_FIRMWARE_POLICY=1`
only on disposable GitHub Actions KVM guests. Physical firmware belongs to the
hypervisor; fwupd metadata availability is excluded with a guest ExecCondition
and `EXCLUDED_HOST_FIRMWARE` receipts in `report.json.environment_exclusions`.
This follows the observed LVFS HTTP 503 failure in run 39600020263. It is not a
firmware update or LVFS availability pass. Other failed systemd units still fail
recovery, with their actual VM journal retained. Production installers do not
apply this test-environment policy.

## Focused scheduled backup and restore verification

Select `scheduled_backups_only=true` for this Phase 4 slice. On the repaired
current branch also select `scheduled_backups_build_current=true`; the canonical
builder produces new signed bytes. Baseline-only reuse rejects runtime changes.
Product qualification, PHP maintenance and diagnostic jobs remain skipped.
The job reads the exact accepted Phase 3 artifact from run `39652821843`; its
archive, public key, manifest and runtime commit are pinned. It rejects runtime
source changes and authenticates the signed image before launching fresh owned
Ubuntu 26.04 AMD64 guests. Cross-run artifact access uses only `actions:read`
and `contents:read`, following the [upstream action contract](https://github.com/actions/download-artifact/tree/v4).

The source uses actual product fixtures and PHP 8.3/8.4/8.5 web/file canaries.
The normal cron sweep must create an active, verified encrypted backup with a
completed River job and scheduler-attributed audit event. No manual backup or
status rewrite can satisfy the check. The exact archive is restored onto a
separate fresh signed installation. Control/MariaDB and tenant file/PHP canaries
must survive restore and a real reboot, with no service repairs. The restored
server must produce another naturally scheduled verified archive after boot.
Only bounded structured receipts enter uploaded evidence; archive keys and
arbitrary command output stay private. Always-owned cleanup has its own receipt.
This is short operational evidence, not an elapsed soak or a new full release
qualification. Run `39669768594` proved the actual scheduler backup and imported
the exact archive, then failed restored PHP HTTP execution before reboot. Both
owned guests were cleaned up. That failed attempt did not establish acceptance.
The diagnostic iteration recorded HTTP status, selected FPM unit/socket state,
nginx error
categories and reconciliation state without publishing HTTP bodies or raw logs.
The diagnostics neither repair services nor convert a failed check to success.


When a scoped runtime defect requires repair, select
`scheduled_backups_build_current=true` together with `scheduled_backups_only`.
The existing signed-bundles job builds the current development candidate;
unrelated qualification jobs remain skipped. The focused job authenticates that
same run's candidate, binds its signed manifest to the exact checkout and records
new archive/manifest/public-key hashes. Only the explicitly scoped classic-site
runtime repair and regression test are allowed beyond harness/docs changes.
Old Phase 3 evidence remains attributed to runtime `63c00f6`, rather than being
relabeled as full qualification of the repaired candidate.


### Measured acceptance — 21 October 2026

[Run 39676085171](https://github.com/Smartqix/nakpanel/actions/runs/39676085171)
passed this focused slice on fresh signed runtime `0654aa3`. Source scheduled
backup ID 1, its exact fresh-host restore, PostgreSQL/MariaDB and tenant file
canaries, all three PHP CLI/HTTP runtimes and tenant ownership before/after a
real restored reboot, new postboot scheduled backup ID 3 and owned cleanup
(two records, exit 0) passed. The active backup job took 25m46s. The downloaded
candidate signature/source and terminal acceptance receipts were independently
checked; no archive key appears in public JSON. The confirmed failure and scoped
classic PHP service-state repair are recorded in the
[result and evidence](superpowers/plans/2026-10-21-phase4-scheduled-backups.md).
Full qualification and legacy tests were skipped; other architecture/destination,
security-version advancement and endurance claims remain separate. Nothing was
merged or deployed.
