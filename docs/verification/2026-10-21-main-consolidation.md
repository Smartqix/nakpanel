# Repository consolidation — 21 October 2026

The user authorized merging every branch and open PR into main, then deleting
merged branches so main is the sole branch. Deployment is not authorized.

The inventory contained 10 local branches, 94 remote branches and two open
PRs (#11 and #13). The prepared Ubuntu-only implementation includes most feature
branches, including instant navigation and the subscription redesign. Local
main additionally contained seven unpublished Backup Manager commits through
`72f1140`; these are integrated, rather than discarded. The alternate fresh
installer commit has the same patch ID as the included `6998f65`.

Old one-run diagnostic, historical migration and legacy-archive branches are
superseded. Their commits are merged as history while retaining the current
Ubuntu 26.04-only tree. Current PHP maintenance already includes their complete
APT simulation budget, trusted runuser path, signed postinst diagnostics and
current-version scope. Do not restore retired workflows or legacy requirements.
Every original head must be an ancestor of the consolidated main before branch
deletion. A verified complete Git bundle and copies of the 16 uncommitted
primary-checkout documents were retained privately outside the repository.

The integration keeps both recovery-document additions and regenerates the
workspace template. Read-only review found a Backup Manager deletion issue:
WordPress references could reject row deletion only after the archive was
removed. Preview and confirmation now reject any referenced safety backup.
The worker checks references again after obtaining its row lock, before the
agent can delete an archive. Active and completed WordPress reference cases
were observed failing before the fix and passing afterward; referenced archives
and operation history remain protected.

The required unit job now supplies the existing isolated removal-test database,
so backup-manager, removal and related database tests execute. Its PostgreSQL
cluster has sufficient lock slots for concurrent fixture migrations and supplies
a URL DSN required by the concurrent migration test. The dedicated optional
hosted workflow is manual-only, preventing retired branch deletion from starting
another qualification run.

Prior PR #13 CI passed in [run 39696504919](https://github.com/Smartqix/nakpanel/actions/runs/39696504919)
on proposed merge `72a2cd7e07416258b033c5bf58aa920e35bfead7`, with source head
`0f54398`. It proves that source, not the subsequent Backup Manager integration.
The combined result receives full local Go/database tests, vet, JavaScript
checks, generated-code and workflow validation, followed by required main CI.
Use the latest [main CI](https://github.com/Smartqix/nakpanel/actions/workflows/ci.yml?query=branch%3Amain)
and the final consolidation report for its terminal result; this checkpoint
does not predeclare that CI passed. No optional qualification is dispatched.

Ubuntu 26.04 and hosting PHP 8.3/8.4/8.5 remain the contract. Existing AMD64
operational, maintenance and scheduled-backup evidence retains its tested source.
ARM64 guest acceptance, other destinations, genuine PHP security-version
advancement and elapsed endurance remain separate release claims.
