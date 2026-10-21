# Hosted Ubuntu 26.04 AMD64 qualification

The hosted workflow targets one server OS: Ubuntu 26.04/resolute on AMD64,
using the signed Surý PHP 8.3/8.4/8.5 profile and internal PHP 8.5. Workflow
alignment in Phase 2 is local only; no hosted dispatch/push is authorized by
this document. Ubuntu 26.04 remains experimental pending operational acceptance.
See [platform qualification](PLATFORM_QUALIFICATION.md) and the
[transition plan](superpowers/plans/2026-10-18-ubuntu-26-04-support.md).

## Runner, artifacts and image

The reusable `prepare-hosted-runner.sh` acts only on a disposable GitHub-hosted
runner. Its measured KVM, memory and disk preflight runs before guest launch.
The hosted runner label `ubuntu-24.04` is a build/VM-host choice, not a supported
Nakpanel server OS. Native ARM64 still requires its own qualified runner; this
AMD64 workflow cannot establish that support.

Build only the current signed AMD64 panel/agent/panelctl bundle with an ephemeral
test key. Authenticate its exact manifest, executable inventory and architecture
before staging. Development bundles remain nonpromotable. No historical checkout,
prior binary or Noble image is built/downloaded for current qualification.

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

## Remaining operational blocker

Run [39582799272](https://github.com/Smartqix/nakpanel/actions/runs/39582799272)
failed in the current 26.04 disaster-recovery prerequisite on
`fwupd-refresh.service`; the actual PHP maintenance drill was skipped. The unit's
underlying failure cause was not retained. Cleanup passed. This remains Phase 3
work; it is not fixed by retiring Ubuntu 24.04 or by local workflow changes.
The former cross-OS migration run remains a historical failure outside the new
release scope. No retry, scheduled-backup run or later phase is launched here.

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
