# Managed Services controls — local verification

Date: 28 October 2026. Branch: `ricky/services-task-feedback`. Base: `dd4e0045ea0c7c0178cab2a8ed60bc77d3bd5021`.

## Result and scope

Service actions now use the correct browser form endpoint and encoding, create a named durable Task atomically, display queued/executing/verifying/terminal state, and retain recent manual successes for ten minutes. Service rows link to the same Task and recover active operations after navigation. The dropdown closes on selection, outside click and Escape, with reachable focus after cancellation. Errors appear outside the collapsed authorization form; password confirmation opens when required and does not replay a service action.

This is local implementation evidence. No hosted tests, live service actions, push, PR, merge or deployment were performed. Ubuntu 26.04 remains the only supported server OS; hosting PHP 8.3/8.4/8.5 and internal PHP 8.5 requirements remain intact. Browser fixtures do not establish hosted Ubuntu acceptance.

## Correctness and regression coverage

- Real HTTP handlers accept bounded URLencoded and multipart forms, preserve CSRF/admin/recent-password checks, and reject uploads and duplicate fields. JSON callers remain supported.
- A server operation, River job, Operations task and task linkage commit together. A per-service unique index prevents conflicting queued actions. Failures on different services have different issue identities.
- The worker records verification and independently inspects the requested service before succeeding. Stop requires an available service in the inactive state; other actions require active state. No automatic mutation retry is introduced.
- The administrator-only, noncacheable snapshot returns active and recent service actions with safe errors and task IDs; raw agent errors and request payloads are excluded.
- Quick Tasks keeps active/failed tasks and recent successful manual service actions. Scheduled/unrelated/old successful work stays excluded, and server tasks remain hidden from tenants.
- Client tests cover fast completion, out-of-order snapshots, detached views, duplicate submissions, 5xx/network uncertainty, and checking current state before retry. Background inventory responses cannot replace forms behind an open confirmation.
- Current schema apply/rollback and application-update migration coverage ran against a dedicated loopback PostgreSQL 18 cluster. The new migration replaces the recorder function for existing current installations; it adds no historical backfill.

## Browser checks

The opt-in `TestServicesBrowserPreview` fixture serves real templates and embedded assets on loopback with fictional services. It does not connect to an agent or database or execute systemctl. Checks used the in-app browser.

| Flow | Observed result |
| --- | --- |
| Desktop menu selection, Cancel, outside click, Escape, arrow keys | Menu closes; Cancel/Escape restore the service Actions opener. |
| Restart accepted once | Named Task and service-row task link appear immediately; Actions is busy. |
| Execution verification | Row displays Verifying; Task displays Running. |
| Home → Back during execution | Same durable task link and busy state recover. |
| Successful/fast completion | Result remains in quick Tasks with Succeeded; active count returns to zero. |
| HTTP 400 | Visible error outside authorization disclosure; no accepted action. |
| HTTP 428 → password confirmation | Disclosure opens, password focuses and clears after success, no action is automatically queued. |
| Mobile Stop → completed | Row shows Stopped and Stop completed; only Start is offered. |
| 390px and 320px layouts | No document horizontal overflow; Actions and menu choices measure at least 44px high. |
| One service completes during another service's confirmation | Captured source stays connected; confirming queues exactly one additional action. |

Evidence: [desktop progress](evidence/2026-10-28-service-controls/desktop-progress.png), [desktop completion](evidence/2026-10-28-service-controls/desktop-completed.png), [mobile stopped service](evidence/2026-10-28-service-controls/mobile-stopped.png), [visible service error](evidence/2026-10-28-service-controls/desktop-error.png).

## Commands

```sh
make generate
NAKPANEL_OPERATIONS_TEST_DSN='<dedicated loopback PostgreSQL test database>' go test ./... -count=1
go vet ./...
go build ./cmd/...
node --test internal/control/web/*test.cjs internal/control/web/static/*.test.cjs
git diff --check
```

All 44 tested Go packages passed, with the dedicated local Operations database enabled. Generation, `go vet ./...`, `go build ./cmd/...` and `git diff --check` passed. The JavaScript suite passes 282/282 tests. The opt-in browser fixture is skipped in ordinary test runs and was started separately for the browser checks above. Database-backed Operations tests were explicitly enabled; other independently gated hosted/integration suites were not implied to have run.

## Final review and decisions

A fresh read-only review found two important client cases: 5xx responses released uncertain intent, and automatic inventory refresh could detach an open confirmation's source. Both were reproduced with failing tests and corrected; focused tests passed afterward. The complete local suites were rerun after the fixes. No minor findings were deferred.

Decisions: implement in the existing isolated worktree and queue rather than introduce another task engine; use fictional loopback services and real-handler/database tests within the authorized local scope; keep the branch local for reporting. Hosted acceptance remains a separate, explicitly authorized step. Historical compatibility/backfill matrices are retired by AGENTS.md; generated template slot renumbering is mechanical output from templ.


## Two-pass recheck — 28 October 2026

The owner requested two additional review/fix passes after `d612f52`. Both were performed locally on the feature branch.

**Pass 1: backend and durable task lifecycle.** Reproduced terminal River jobs leaving their service operation pending/running and permanently holding its per-service lock. The current recorder now closes an unfinished service operation in the queue transition transaction. Cancellation before execution is cancelled; discarded/interrupted or otherwise unverified execution fails with safe guidance to inspect current state. It never replays a command. A proven success or failure persisted by the worker takes precedence even if queue acknowledgement is subsequently lost. Seven real PostgreSQL scenarios cover cancellation, discard, missing outcome and preserved terminal results, with Task/snapshot agreement and later action admission.

**Pass 2: browser lifecycle and focus.** Reproduced an old service/reauthentication response consulting the next page after navigation. Response handling now belongs to the originating page lifetime. Accepted background work still refreshes Tasks, and replacing an inventory row on the same page retains the accepted operation/task identity. Reproduced Task detail closing to the notification bell after quick-task rows are replaced; the dialog now remembers its originating Tasks/Notifications surface. Unit checks preserve notification focus behavior. In the real loopback browser, Restart nginx completed, appeared in quick Tasks, opened its correct successful attempt and closed with `document.activeElement.dataset.npOpToggle === "tasks"` after background row refreshes.

Every defect was reproduced by a failing regression before its fix. Pass 1's five focused Go packages passed with local PostgreSQL enabled. Pass 2's complete JavaScript suite passed **287/287**. Final verification passed all **41 tested packages** in `go test ./internal/... ./cmd/... ./migrations -count=1`, with the dedicated Operations database enabled, followed by an additional web package check after the last JavaScript change. Generation, vet, build and diff checks passed. Unchanged deployment harness checks were not repeated.

Recheck evidence: [Task focus browser result](evidence/2026-10-28-service-controls/recheck-tasks-focus.png), [backend failing regression](evidence/2026-10-28-service-controls/recheck-pass1-red.log), [backend verification](evidence/2026-10-28-service-controls/recheck-pass1-green.log), [JavaScript verification](evidence/2026-10-28-service-controls/recheck-pass2-green.log), [Go verification](evidence/2026-10-28-service-controls/recheck-go.log).

Ubuntu 26.04 and hosting PHP 8.3/8.4/8.5 requirements remain unchanged. No hosted tests, live service operations, push, PR, merge or deployment were performed. These checks establish local correctness; hosted acceptance remains unperformed. The temporary browser fixture and dedicated PostgreSQL cluster were stopped after verification.
