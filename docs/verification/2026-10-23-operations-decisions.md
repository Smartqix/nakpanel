# Operations center — implementation decisions

This records every ruling made during local implementation, in order. The active
plan and repository development policy remain authoritative.

1. Ruling: The owner's latest “implement now” authorizes the local implementation phases. Report each phase before continuing; hosted tests, external mail, PR, merge and deployment remain unapproved. Cost if wrong: more local implementation than a phase-only request; no external release effects.

2. Ruling: The plan uses Phase headings rather than Task headings. Treat each phase as one task, retaining its full brief and checkpoint; use this ledger directly rather than changing public phase names for a script parser. Cost if wrong: bookkeeping differs, deliverables and test gates do not.

3. Task 2: Ruling: River invokes a database projection dispatcher. Feed publication and outbox acknowledgement commit together; no child job per event is necessary. Crash recovery replays the same projection transaction. Cost if wrong: a future external consumer must add atomic queue insertion before acknowledgement.

4. Task 2: Ruling: Replace the task HTTP source and remove its unused dashboard reader now. Root HTML badge/tray wiring belongs with phase 4 template work; no compatibility adapter was added. Cost if wrong: the intermediate phase-2 checkout is not ready for UI release; phase 4 must remove the remaining raw-job presentation.

5. Task 3: Ruling: Capture pinned River source transitions with a PostgreSQL trigger, rather than independent after-the-fact worker callbacks. This makes source state, attempts, incidents and outbox atomic and preserves automatic retries. No historical job backfill. Install the recorder after River migrations before starting workers. Cost if wrong: future River schema changes need the integration test to catch them.

6. Task 3: Ruling: First-release automatic mutation is a typed backup retry from current intent. Other operation kinds use their existing resource settings; generic destructive job retry will be removed. Independent verifiers cover backup checksum, local TLS, site runtime and local mail/webmail readiness. Cost if wrong: additional one-click actions need separately implemented preflights; none are silently exposed.

7. Task 3: Ruling: Persist backup completion time separately from queue creation time. Historical rows are not backfilled and cannot establish freshness; current successful backups set it. Cost if wrong: existing development archives without completion evidence require a fresh backup for protection acceptance.

8. Task 3: Ruling: Move transient attention/root projection removal into phase 4's template/read-model change, keeping one coherent UI edit. Phase 3's backend is not UI acceptance. Cost if wrong: this intermediate commit must not be released on its own.

9. Task 3: Ruling: Retire the old generic discarded-job retry implementation and its obsolete Multipass script. It rewrote terminal jobs and could replay restores, violating typed recovery. The new recovery chain is covered by local PostgreSQL/River and HTTP tests; hosted acceptance is still unclaimed. Cost if wrong: a new hosted operations scenario must be authorized before release.

10. Task 3: Ruling: The local full-suite Roundcube child-failure harness error is tracked through final acceptance while proceeding with independently passing operations/UI work. No hosted acceptance is inferred and no gate is removed. Cost if wrong: local release acceptance remains blocked until that failure is understood and verified.

11. Task 4: Ruling: Preference controls are implemented here, with persisted policy and end-to-end validation in phase 5, where that service is defined. The intermediate UI is not a release candidate. Cost if wrong: preferences cannot be accepted until phase 5 passes.

12. Task 5: Ruling: SMTP defaults off at both server and personal levels; critical/security in-app notices are mandatory. Only current authorized account addresses receive mail. Server backup address selection is retained for registered authorized administrators; the standalone unscoped security alert override is removed with its CLI/schema callers. Cost if wrong: operators must configure policy and each user must opt in before email flows.

13. Task 5: Ruling: Replace address-only email records with scoped batches directly, without historical receipt migration. Keep detailed history; the earlier proposed 30/90-day deletion windows remain inactive. Cost if wrong: development email history needs recreation and stored history grows until an explicit retention policy is chosen.

14. Task 5: Ruling: Hold current audience identity rows during the bounded SMTP call. TestEmailOwnershipCannotChangeDuringFinalAuthorizationAndSMTP RED→GREEN proves a concurrent transfer cannot cross the last authorization check. Cost if wrong: an ownership or preference edit can briefly wait for the SMTP timeout.

15. Task 5: Ruling: Correlate domain worker failure notices through a River context middleware, retaining independent security/health notices. The operation projector links the existing current notice rather than adding a duplicate. TestOperationsCorrelatesDomainFailureNoticeWithoutDuplicateInboxEntry RED→GREEN. Cost if wrong: new worker failure kinds must explicitly join the correlation allowlist.

16. Task 5: Ruling: Increase only the mocked hosted-preparation fixture's local startup budget from 0.2s/0.05s to 1s/0.25s. Production/hosted deadlines are unchanged. The observed snap-retry-once false timeout is now passing. Cost if wrong: a failing local fixture can take slightly longer to report.

17. Final: Ruling: Hosted Ubuntu 26.04, external SMTP, DNS, inbox arrival and deployment remain outside local acceptance — no such actions were authorized in this task — cost if wrong: these environments can reveal additional failures before release.

18. Final: Ruling: Archive receipts prove checksum/size, not restore or application recovery rehearsals — the UI and operator guide state that boundary — cost if wrong: a valid archive may still fail a future restore rehearsal.

19. Final: Ruling: Keep the first-release recovery/verifier allowlist and tracked job-family list — additional actions and removal/system mutations need separate source contracts rather than generic replay — cost if wrong: operators must use existing resource tools for those cases.

20. Final: Ruling: No historical migrations, backfills or Ubuntu 24.04 validation — current development policy supersedes those obligations — cost if wrong: historical development data needs recreation.

21. Final: Ruling: Retain history and one UTC daily digest schedule; no pixel-equivalence claim — the correctness review did not judge retention alternatives, digest schedules or exact Figma matching — cost if wrong: storage grows and those product refinements remain future work.

22. Final: Ruling: Keep the feature branch local after local acceptance — pushing, PR, merge and deployment are explicitly gated by the active plan — cost if wrong: work is not available on the remote until separately requested.

## Minor findings deferred at initial acceptance

- Final: minor (deferred): Unsupported automatic-recovery details have explanatory text but no direct resource/settings link; use the existing Websites/Subscriptions navigation.

- Final: minor (deferred): Opening an inbox issue does not automatically mark its notification read; the explicit personal Mark read action remains available. Neither action acknowledges or resolves an issue.

## Follow-up resolution

The owner subsequently authorized both deferred UX fixes. They are now resolved
at `51eeb1d`: current scoped settings destinations and personal read-on-open after
successful detail loading. See the [focused follow-up report](2026-10-23-operations-ux-followup.md).
The deferral entries above retain the initial review history.
