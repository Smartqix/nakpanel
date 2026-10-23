# Operations center — final local acceptance

Implementation source: `d2eedb95802bfa608a9a49128192ba93c8d54b48` on
`ricky/operations-center-design`; base `26ff13f6796788c6106d8cd8a09b7016ff7d18b4`.
Documentation-only acceptance changes follow that implementation commit.

Local implementation phases 1–5 and the authorized local portion of phase 6
have passed. Hosted acceptance, external email, PR, merge and deployment have
not run. This report does not establish hosted Ubuntu 26.04 acceptance.

## Review and regression fixes

One fresh-context reviewer inspected the whole branch through `ef5efe1` against
the plan, specification and implementation rulings. No Critical findings were
reported. All nine Important findings were confirmed, reproduced and fixed in
one pass. No second review or security scan was claimed.

| Finding | Regression evidence and resulting behavior |
| --- | --- |
| Terminal outcomes disappeared outside the quick eight rows | `all relevant terminal results beyond eight rows are presented once`, `TestFeedIncludesTerminalPresentationMetadata` and browser acceptance: all twelve succeeded/cancelled/failed results remain visible in the global result surface; routine successful reconciliation stays quiet. |
| Fragment navigation skipped or replayed events | `navigation preserves consumed cursor within authenticated scope, including cached fragments`: retain the consumed cursor; ignore newer/stale HTML seeds within that scope. Browser acceptance also checks old result cards clear on a customer-scope change. |
| Independent tasks and backup destinations merged | `TestRecorderSeparatesTasksAndBackupDestinationsWithinOneScope`: two tasks on one site and two server backup destinations have four incidents, with recurrences grouped only within their stable subject. Database/application/import subjects also have explicit incident identities. |
| Provisioning SSL failure appeared cancelled | `TestRecorderRecognizesPersistedCertificateFailureOnCancellation`: a fresh persisted AfterProvisioning TLS failure creates a failed attempt and TLS issue; genuine cancellation and an older persisted failure do not become new incidents. |
| Manual backup retry never verified | `TestBackupRecoveryVerifiesManualAndDisabledSchedules`: independently inspect the current archive without requiring an automatic schedule; an archive preceding the manual failure and failed checksum inspection cannot establish recovery. Scheduled deadlines remain enforced. |
| Customer support workspace omitted descendants | `TestCustomerSupportScopeIncludesCurrentDescendantsEverywhere`: pages, counts, inbox and feed include current site/subscription descendants, and stop including them immediately after transfer. |
| SMTP DATA acceptance was retried after QUIT disconnect | `TestSMTPAcceptedDataSurvivesQuitDisconnect`: the positive final DATA reply records Accepted by SMTP; QUIT cleanup is bounded and best effort. This is not an inbox-arrival or exactly-once SMTP guarantee. |
| Acknowledged filter failed | `TestAcknowledgedFilterKeepsOnlyUnresolvedAcknowledgedIssues`: accept the advertised filter and return only unresolved acknowledged issues; Open excludes acknowledged issues. |
| Slow initial preference loading overwrote edits/defaults | `preferences remain unavailable until loaded and stale loads cannot overwrite newer settings`: controls and Save remain disabled until successful loading; stale responses are ignored and policy reload preserves personal edits. Browser acceptance delays both GET requests. |

The certificate reproduction was rerun with the domain override temporarily
removed: it failed because no TLS issue existed, then passed after restoration.
Other recorded RED cases included the missing filter, merged incidents, missing
customer descendants, manual schedule rejection, QUIT acceptance failure,
consumed-cursor resets, missing terminal presentation and stale-scope result
cards. All final targeted checks pass.

## Final local checks

- `go test ./... -timeout 8m` with GNU Bash 5 and the dedicated operations DSN:
  **43 tested packages passed**; [complete package output](evidence/2026-10-23-operations/final-suite.log).
- JavaScript test suite: **253 passed, 0 failed**.
- `go test -race ./internal/control/operations ./internal/control/provision`:
  **both passed**; [output](evidence/2026-10-23-operations/final-race.log).
- `go vet ./...`: passed with no output.
- Pinned SQLC 1.30.0 generation: no store changes. Pinned templ 0.3.960
  regeneration: identical hashes on repeat. `git diff --check`: clean.
- Fresh headless Chrome with fictional loopback data: twelve terminal results,
  cursor continuity, replay dedupe, scope clearing, slow preference loading and
  desktop/mobile checks passed, **zero script errors and no horizontal overflow**;
  [browser result](evidence/2026-10-23-operations/final-browser.log).
- Real local PostgreSQL/River fixtures cover current-role/ownership changes,
  independent receipts, outbox rollback/replay, typed recovery and stale verifier
  fences. A local SMTP capture uses the production sender and fictional owned
  recipients. No external SMTP recipient was contacted.

The shared Herd PostgreSQL instance stalled in filesystem sync and was not
restarted or reconfigured. Validation used a separate disposable PostgreSQL 18
cluster on loopback port 55432 and private schemas. Crash durability was disabled
only on that disposable fixture: transaction tests do not prove power-loss
recovery. No production database setting changed. Earlier failed runs remain
failures in their original phase reports; this final run supersedes local
acceptance status, without claiming hosted evidence.

## UI evidence

All screenshots use fictional resources. [Editable Figma flow](https://www.figma.com/design/xKb9jZ6VvLAWEwwsKRZeG5)
remains the design reference; exact pixel equivalence was not claimed.

- [Desktop Activity](assets/2026-10-23-operations/desktop-issues.png)
- [Backup recovery confirmation](assets/2026-10-23-operations/desktop-recovery.png)
- [Desktop terminal results](assets/2026-10-23-operations/desktop-results.png)
- [Mobile terminal results](assets/2026-10-23-operations/mobile-results.png)
- [Mobile inbox](assets/2026-10-23-operations/mobile-inbox.png)
- [Desktop preferences](assets/2026-10-23-operations/desktop-preferences.png)
- [Mobile preferences](assets/2026-10-23-operations/mobile-preferences.png)

## Remaining work and limits

Two minor UX findings are deferred: issue details lack a direct resource/settings
link for unsupported automatic actions, and opening an inbox issue does not
mark its notification read automatically. Existing resource navigation and the
explicit personal Mark read action work. Neither changes issue recovery state.

Focused hosted Ubuntu 26.04 acceptance and external delivery/public DNS checks
need separate authorization. Required CI, including the hosted security gate,
belongs to a subsequently requested PR. PR, merge and deployment are not included
in this local implementation. Ubuntu 24.04, legacy compatibility, historical
backfills and old backup-format matrices remain retired. Hosting PHP 8.3/8.4/8.5
and internal PHP 8.5 requirements are unchanged.

The complete [implementation decisions and deferred findings](2026-10-23-operations-decisions.md)
record the rulings and costs accepted during this work.
