# Verification and evidence

Ubuntu 26.04 is the only server target. Read [platform qualification](PLATFORM_QUALIFICATION.md)
for the full PHP contract and remaining release qualification; AMD64 evidence
and static ARM64 builds do not establish native ARM64 server acceptance.
Hosted tests require explicit authorization. This guide does not authorize a
new run, a merge, external mail or a deployment.

## Current source-bound examples

| Scope | Recorded source | Evidence |
| --- | --- | --- |
| Ubuntu 26.04 AMD64 operational/PHP maintenance recovery | `63c00f6` | [Run 39652821843](https://github.com/Smartqix/nakpanel/actions/runs/39652821843) |
| Scheduled local backup and exact-archive restore | `0654aa3` | [Run 39676085171](https://github.com/Smartqix/nakpanel/actions/runs/39676085171) |
| Focused Operations Center and both UX fixes | `40a3faf` | [Report](verification/2026-10-23-operations-hosted.md) |
| Operations Center required PR CI, security and recovery | `99d3912` | [Run 40003012002](https://github.com/Smartqix/nakpanel/actions/runs/40003012002), [merged PR #15](https://github.com/Smartqix/nakpanel/pull/15) |

These development results retain their original source and scope; they are not
production-promotion certificates or substitutes for remaining qualification.
The historical reports retain unsuccessful attempts and their limitations.
The focused Operations suite was not repeated for the later required PR CI.

## Canonical server verification

After explicit authorization, run the single-VM deployment verifier:

```bash
deploy/multipass/deployment-verify.sh
```

This creates a fresh, uniquely named owned Ubuntu 26.04 Multipass VM,
installs the service stack, runs migrations, builds the
panel, agent, and CLI, installs systemd units, and retains the Phase 28 and
adversarial security gates before Phase 29 reliability/disaster recovery.
Phase 30 then installs the current worktree and proves
the detailed PHP runtime inventory, a real Classic WordPress 7.1 site, native
Managed PHP release/worker behavior, cross-subscription isolation, and reboot
recovery. Phase 31 proves plan lifecycle and assignment rules, fail-closed
capability validation, immutable revisions, synchronization impact previews,
and non-destructive subscription compliance. Phase 32 remains directly
runnable as the Toolkit feature gate: it
provisions an entitled Classic PHP site through the domain WordPress Toolkit,
checks inventory and core integrity, requires a completed backup before
updates, verifies maintenance recovery, enforces the per-subscription site
limit, and checks that secrets never enter River arguments. Phase 33 is the uninstall gate:
it proves backup-gated uninstall, managed-database provenance,
domain preservation, tombstone reinstall, external-database preservation, and
pre-drop failure recovery. Phase 34 is the statistics/privacy gate: it generates real nginx
traffic, checks GoAccess reports through the authenticated panel, verifies URL
privacy filtering, and proves customer report isolation. The canonical runner
then finishes with `domain-removal-verify.sh`, covering removal, retained data
and scoped recovery.

Every reuse, sync and deletion requires matching host and root-owned guest
records for the current run, actual Ubuntu release and architecture. Existing
lab/soak and unrelated VMs are protected; ordinary verification does not sweep
historical phase VMs. A name prefix alone never authorizes deletion.

To override the lab VM name or Ubuntu image:

```bash
NAKPANEL_MULTIPASS_IMAGE=26.04 deploy/multipass/deployment-verify.sh
```

After a successful verification, open:

```text
https://<vm-ip>:7443/login
```

The bootstrap certificate is self-signed, so the browser warning is expected.

The canonical verifier supplies an explicit private administrator bootstrap file
for its disposable lab. Its admin identity and password are defined in
`deploy/multipass/current-install-verify.sh`; they are synthetic test credentials,
not installation defaults. The seeded client and reseller logins are disabled.
Use the scoped customer fixtures created by the relevant verifier instead of
trying to authenticate as a public seeded customer.

## Earlier transition snapshot

The following text was the README's transition status before consolidation.
Its “unmerged” and deployment statements describe that earlier snapshot, not
current branch or server state. PR #13 and PR #15 have since merged; consult the
linked reports for their exact source bindings.

> Phase 2 aligned the installer, VM defaults and CI with this contract. Phase 3
> [passed hosted Ubuntu 26.04 AMD64 qualification](https://github.com/Smartqix/nakpanel/actions/runs/39652821843)
> on `63c00f6`: all 16 current-version gates, PHP 8.3/8.4/8.5 maintenance failure
> recovery, both unassisted reboots, three fresh Roundcube send/read flows and
> owned cleanup. This is development-signed same-version evidence; remaining
> architecture, security-version advancement and elapsed-soak acceptance are
> pending. Phase 4's scoped scheduled-backup/restore checks
> [passed on hosted Ubuntu 26.04 AMD64](https://github.com/Smartqix/nakpanel/actions/runs/39676085171)
> with freshly signed runtime `0654aa3`: exact scheduled-archive restore, database
> and file canaries, PHP 8.3/8.4/8.5 before/after reboot, resumed scheduling and
> owned cleanup. A classic PHP service-state reconciliation defect was fixed.
> Full product gates and legacy tests were not repeated. Changes remain unmerged;
> nothing was deployed. Ubuntu 24.04 and cross-OS migration are outside
> the release requirements. See the
> [transition plan](superpowers/plans/2026-10-18-ubuntu-26-04-support.md).

## Further reading

- [Hosted Ubuntu qualification](HOSTED_UBUNTU_QUALIFICATION.md)
- [PHP security maintenance](PHP_SECURITY_MAINTENANCE.md)
- [Long-run soak](SOAK.md)
- [Operations Center](operations-center.md)
