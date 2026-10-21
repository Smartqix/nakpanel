Nakpanel now targets Ubuntu 26.04 LTS (Resolute) as its sole server OS and
rejects unsupported server releases before mutation. Hosting PHP 8.3/8.4/8.5
remains required, with validated internal PHP 8.5 and the signed Resolute Surý
provider. Ubuntu 24.04 support, cross-OS migration and historical compatibility
matrices are retired development requirements.

## Changes

- Align installer/platform guards, runtime descriptors, defaults, dependency
  policy and workflows with the Ubuntu 26.04-only contract while preserving
  explicit tenant PHP intent and isolation.
- Keep current-version signed installation, application recovery and encrypted
  backup/restore checks. Constrain PHP failed-configuration recovery to the
  authenticated installed package and recover only the affected FPM start state.
- Make classic PHP reconciliation inspect service state so matching restored
  configuration cannot conceal a stopped tenant FPM unit. Active and suspended
  intent are covered for all three PHP minors.
- Add focused scheduled-backup/restore verification, bounded diagnostics and
  owned guest cleanup. Preserve original source attribution for reused evidence.
- Reconcile the platform, recovery, soak, removal and tool documentation; record
  the PHP maintenance policy owner as Nakpanel project maintainers through GitHub.

## Verification evidence

| Scope | Tested source | Recorded result |
| --- | --- | --- |
| Full hosted Ubuntu 26.04 AMD64 Phase 3 | `63c00f6006df3bba1ca9ef474e0f350ff7835165` | [Run 39652821843](https://github.com/Smartqix/nakpanel/actions/runs/39652821843): all 16 current-version gates, actual PHP same-version delivery/configuration-failure recovery, both unassisted reboots, fresh Roundcube flows, database-manager coverage and owned cleanup passed |
| Focused hosted scheduled local backup/restore | `0654aa39eee180935f8dbed3cc3b1458e156ba1d` | [Run 39676085171](https://github.com/Smartqix/nakpanel/actions/runs/39676085171): scheduled encrypted archive, exact fresh-host restore, PostgreSQL/MariaDB and file canaries, all three PHP CLI/HTTP runtimes before/after reboot, resumed scheduling and owned cleanup passed |
| Focused local recheck | Implementation/harness through `1140165` | Nine affected runtime Go checks and four harness/workflow Go checks passed; all 12 Python verifier behavior cases passed after the initialization-diagnostics fix; actionlint and diff checks passed |

The recheck independently authenticated the retained candidate signature/source
and hosted receipts. The initial-command diagnostics regression was observed
failing before the fix and passing afterward. Read-only reviews found no
important remaining Phase 4 defect. The documentation-only follow-up changed no
runtime, installer or workflow. This PR runs the required CI described below. Earlier failed runs retain
their failure status; the focused Phase 4 pass is not a new full-product pass on
`0654aa3` or `1140165`.

## Remaining before merge and release limits

- Final-branch CI is pending: generated code, full unit tests, release policies
  and the required security gate must be checked on the final PR branch.
  Required CI is authorized: unit/generated-code checks, the signed release
  build and the hosted Multipass security gate. Optional native qualification,
  private PHP builds and separate hosted qualification dispatches remain off.
- Hosted acceptance is AMD64 development-signed evidence. ARM64 qualification,
  other backup destinations, genuine PHP security-version advancement and the
  30–60 day elapsed soak remain separate release claims.
- The measured LVFS outage has an explicit exclusion only on owned disposable
  hosted KVM guests. Physical firmware servicing and upstream availability are
  not validated by that exclusion.
- Ubuntu 26.04 remains experimental. This PR does not authorize a merge,
  deployment or production promotion.

Current scope and history: [transition plan](https://github.com/Smartqix/nakpanel/blob/ricky/ubuntu26-recovery-phase3/docs/superpowers/plans/2026-10-18-ubuntu-26-04-support.md).
Detailed backup/recheck evidence: [Phase 4 report](https://github.com/Smartqix/nakpanel/blob/ricky/ubuntu26-recovery-phase3/docs/superpowers/plans/2026-10-21-phase4-scheduled-backups.md).
