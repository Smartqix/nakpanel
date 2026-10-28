# Compact Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a readable, compact bell preview and matching full inbox without changing notification/issue semantics or disrupting hosting workflows.

**Architecture:** Keep the existing operations store, personal receipts, scoped APIs and single poller. Add a small safe notification-detail read boundary and focused notification view components; leave issue/task mutation and recovery machinery unchanged.

**Tech Stack:** Go, PostgreSQL, templ, embedded CSS/vanilla JavaScript, current Node test runner and existing loopback Operations fixture.

**Spec:** [Approved direction and proposed detailed design](../specs/2026-10-28-compact-notifications-design.md). Read it before execution. Mockups and plan await owner review; implementation is not authorized yet.

## Global Constraints

- Existing Go/templ, embedded CSS, vanilla JS and stdlib HTTP only.
- No external fonts, CDN scripts, framework rewrite or new browser dependency.
- No database migration, legacy adapter, dual path or historical matrix.
- Read/archive change personal receipts only; they cannot resolve or acknowledge issues.
- Preview width 400px, maximum height 560px; mobile viewport inset 12px and maximum height 620px, always further constrained by available viewport height.
- Row title/summary 14px/20px; metadata 12px/18px; heading 16px/24px. Mobile actions at least 44px. Content-driven panel height.
- Five preview entries; independent preview/inbox filters; the existing full inbox route and keyset pagination.
- Ubuntu 26.04 LTS (Resolute) is the only supported server OS. Reject unsupported server OS versions before mutation.
- Preserve hosting PHP 8.3/8.4/8.5, isolated FPM/CLI readiness and validated internal PHP 8.5, using existing signed Resolute Sury providers/descriptors.
- Report each phase before moving on. Local checks do not establish hosted acceptance. Hosted tests, deployment, merge and push require separate authorization.

## Review Focus

1. Long emails, DNS labels, IPv6 text and 2000-character messages must not squeeze text beside controls; pinned in Tasks 2 and 5.
2. A focused row/menu or an unsaved hosting form must survive a poll, navigation and scope switch without stale updates leaking; pinned in Tasks 3 and 5.
3. Rapid clicks, failed receipts and a newer notification arriving during mark-all-read must not fabricate success or zero unread; pinned in Tasks 3 and 4.
4. Standalone security notices and removed/transferred resources must obey fresh authorization and safe-summary redaction, including search; pinned in Tasks 1 and 4.
5. Mobile wrapped headers, short viewports, zoom and empty-last-row transitions must retain reachable controls and predictable focus; pinned in Tasks 2, 4 and 5.

## File Map

| File | Responsibility |
| --- | --- |
| `internal/control/operations/queries.go` | Safe notification projection, target label, scoped ID lookup and safe search |
| `internal/control/http/operations.go`, `server.go` | Typed GET detail boundary, validation, no-store and error handling |
| `internal/control/web/notification_views.templ` (new) | Preview/inbox row variants and standalone detail shell |
| `internal/control/web/notification_views.go` (new) | Compact server labels, kind/icon/context mapping |
| `internal/control/web/operations.templ`, `operations_helpers.go` | Compose focused notification views, keep Tasks/Issues contracts |
| `internal/control/web/static/notifications.js` (new) | Safe DOM rendering, keyed reconciliation, timestamp/position helpers |
| `internal/control/web/static/operations.js` | Existing poller integration, selected detail and receipt orchestration |
| `internal/control/web/static/operations.css` | Scoped preview/inbox/mobile styles; compact quick Tasks rows |
| `internal/control/web/assets.go`, `workspace.templ` | Embed/load new JS before `operations.js`; no CDN |
| Existing/new Operations Go/Node/fixture tests | Data, role, rendering, interaction and local acceptance |
| `docs/operations-center.md` | Document current notification behavior and evidence limits |

Generated `*_templ.go` files must be regenerated, never hand-edited. Mockup code
under `docs/assets/compact-notifications-2026-10-28` is design evidence, not
production code to copy wholesale.

---

### Task 1: Safe Standalone Notification Reads and Search

**Files:** Modify `internal/control/operations/queries.go`, `internal/control/http/operations.go`, `internal/control/http/server.go`, `internal/control/http/operations_test.go`; create `internal/control/operations/notification_details_test.go`.

**Interfaces:**
- Add `Target string` with JSON name `target` to `operations.Notification`.
- Add `(*Store).Notification(context.Context, auth.SessionUser, int64, Resource) (Notification, error)` and the same method to `OperationsService` using `operations.Resource`.
- Register `GET /api/workspace/operations/notifications/{id}` with `Server.handleOperationNotification`.
- Reuse `NotificationVisibilitySQL`, `notificationFrom`, `resourceFilter` and the existing safe-summary allowlist. ID lookup returns no raw body, metadata, secrets or receipt side effects.

- [ ] **Step 1: Write failing store and handler tests.** `TestNotificationDetailIsScopedAndReadOnly` proves same DTO content/target as the list, current client/reseller/admin visibility, support resource restriction, archived-but-authorized detail access, unchanged receipt/issue state and cross-tenant 404. `TestNotificationSearchUsesPublishedProjection` searches title/allowed summary/target while an unknown-kind raw body containing `hidden-secret-sentinel` never matches. `TestNotificationDetailHTTPBindsViewer` covers anonymous 401, invalid/nonpositive ID and malformed resource 400, denied 404, JSON/no-store and GET with no mutation. Update fake services explicitly.
- [ ] **Step 2: Run the new tests and observe failure.** Use `go test ./internal/control/http -run TestNotificationDetailHTTP -count=1` and `NAKPANEL_OPERATIONS_TEST_DSN="$NAKPANEL_OPERATIONS_TEST_DSN" go test ./internal/control/operations -run 'TestNotification(Detail|Search)' -count=1`. Supply a dedicated loopback `nakpanel_operations_*` database; a skipped PostgreSQL test is not a pass.
- [ ] **Step 3: Implement the shared safe projection and scoped read.** Validate `Resource` before querying. Apply current visibility and the selected resource predicate to ID reads; keep authorized archived reads available. Expand search only through the same published, bounded safe summary and target expressions. Do not search raw `n.body` outside that projection.
- [ ] **Step 4: Run the focused tests and existing Operations store/HTTP suites.** Require real PostgreSQL cases to execute and pass. Confirm no migration or receipt-write query was added to GET.
- [ ] **Step 5: Commit only Task 1 files.** Suggested message: `feat(notifications): add scoped safe notification details`.

### Task 2: Compact Server-Rendered Views and Responsive Styles

**Files:** Create `internal/control/web/notification_views.templ`, `notification_views.go`, `notification_views_test.go`; modify `operations.templ`, `operations_helpers.go`, `static/operations.css`. Regenerate templ output.

**Interfaces:**
- `notificationPreview(view WorkspaceView, page operations.Page)` composes the bell header, independent All/Unread selector, list and footer.
- `notificationRow(n operations.Notification, compact bool, now time.Time)` produces semantic row markup with stable `data-np-notification-id`, an opening button, `<time datetime>`, named overflow trigger and unread accessible text.
- `notificationTimeLabel(created, now time.Time) string` and `notificationContext(n operations.Notification) string` provide compact safe SSR labels.
- New component classes use `np-notification-*`; full-page issue/task rows keep their existing contract. Quick Tasks get a scoped compact variant, not notification actions.

- [ ] **Step 1: Write failing rendering tests.** Pin 0/1/5-item preview structure, full-inbox route/scope, unknown-kind fallback, escaped HTML, 2000-character safe summary and a 253-character target. Assert no large per-row Mark read/Archive buttons and no full datetime column. SSR must expose full permitted message text in markup and exact UTC times in `<time>` metadata.
- [ ] **Step 2: Run `go test ./internal/control/web -run 'TestNotification(View|Time|Context|Preview)' -count=1` and observe failure.**
- [ ] **Step 3: Implement the templ components/styles.** Follow the spec's exact typography, density, sizes, mobile targets and one-panel layout. Use the existing icon/font assets. Include local error/status regions even when the host page is not Activity. Keep the full inbox in Activity; preserve support/subscription links. Clamp summaries only in enhanced presentation; do not omit full safe text from SSR.
- [ ] **Step 4: Regenerate with `task templ:generate`, then run the focused tests and `go test ./internal/control/web ./internal/control/http -count=1`.** Update tests that depended on obsolete notification row structure rather than retaining old markup.
- [ ] **Step 5: Commit Task 2, including generated views.** Suggested message: `feat(ui): add compact notification preview and inbox rows`.

### Task 3: Stable Client Rendering and One Poller

**Files:** Create `internal/control/web/static/notifications.js`, `notifications.test.cjs`; modify `static/operations.js`, `operations.test.cjs`, `assets.go`, `workspace.templ`. Add focused client/lifecycle harness coverage in the existing `operations-client.test.cjs`.

**Interfaces:**
- Export `notificationTime(value, now, locale)` returning `{label, datetime, title}`. Use the same compact age thresholds as SSR; use local exact time with timezone in detail/title.
- Export `notificationPopoverPosition(triggerRect, viewport)` returning `{left, top, width, maxHeight}` from the actual bell rectangle, inset 12px, gap 8px, width cap 400px and current desktop/mobile height cap.
- Export `createNotificationView(root, options)` with options `{identity, density, now, locale, preserveInteraction, onOpen, onReceipt}`. Return a controller with `render(items, context)`, `setPending(idOrAll, pending)`, `setError(message)`, `destroy()`; keep event handlers and DOM nodes stable by notification ID. `context` contains the current identity and authoritative count, not callbacks or a new timer.
- Browser global `window.NakpanelNotifications` and CommonJS exports follow existing testable helper conventions. Load it before `operations.js`.

- [ ] **Step 1: Write failing pure/helper and lifecycle tests.** Pin invalid/future timestamps, just-now/minute/hour/date boundaries, 99+ visual count with exact accessible count, 320px/390px viewport positions and wrapped topbar geometry. For reconciliation, preserve the active row node, menu trigger, scroll anchor and pending state across polling; reject updates with an old actor/resource identity.
- [ ] **Step 2: Run `node --test internal/control/web/static/notifications.test.cjs internal/control/web/static/operations-client.test.cjs` and observe failure.**
- [ ] **Step 3: Integrate focused views into the existing poller.** Fetch preview with its own `view=inbox&limit=5` and independent status, carrying only current resource scope, not inbox search/pagination. Keep full inbox query state separate. Do not create another timer or interval. Patch content in place, deferring poll-driven reorder/removal while interacting. Recompute panel placement on viewport/anchor changes without resizing fonts.
- [ ] **Step 4: Run all static Node tests and asset/templ tests.** Assert one poller after repeated fragment mounts, hidden-tab abort/backoff, scope-switch cancellation and no change to unrelated form dirty state. Exact commands: `node --test internal/control/web/static/*.test.cjs` and `go test ./internal/control/web ./internal/control/http -count=1`.
- [ ] **Step 5: Commit Task 3.** Suggested message: `fix(notifications): preserve focus and scope across live updates`.

### Task 4: Message Opening, Receipt Actions and Accessible Failure Recovery

**Files:** Modify `static/operations.js`, `static/notifications.js`, `operations.templ`, `notification_views.templ`, relevant Go render tests and Node client tests; extend `internal/control/web/operations_ux_acceptance.cjs` and `operations_browser_test.go`.

**Interfaces:**
- Existing issue/task `openDetail` remains the linked-notification destination.
- Add `openNotification(id, trigger)` for standalone events. Fetch Task 1's authorized DTO with current resource scope, then render safe text through the shared modal controller.
- One receipt orchestration function handles read/archive/read-all with action keys bound to actor/resource identity. It owns pending, success, refresh and local error state.
- No changes to acknowledgement, verification, recovery or SMTP interfaces.

- [ ] **Step 1: Add failing interaction cases.** Successful standalone and linked loads emit exactly one read POST for the chosen ID; closing before completion, superseded loads and GET 404 emit none. Test failed receipt state, duplicate clicks, mark-all-read racing a newly arriving unread item, archive of the focused last item, Escape menu-before-preview ordering, outside click into a dirty input, session-expired feedback and focus return after navigation removes the original trigger.
- [ ] **Step 2: Run the corresponding Node tests; use the opt-in loopback fixture for browser-only assertions.** Do not run browser tests against nakpanel.com. Record the expected red case before implementation.
- [ ] **Step 3: Implement actions without optimistic data loss.** Await success before changing receipts or removing rows. Refresh counts authoritatively; do not assume mark-all-read forces zero. Keep local errors visible with retry. Use shared dialog focus management; the preview remains non-modal. Close the other quick panel before opening one. On archive, focus next/previous row or heading. When a trigger disappears, fall back to the bell or scoped inbox heading.
- [ ] **Step 4: Run Go/Node focused suites and local interaction checks.** Prove no issue/task/resource mutation was sent for read/archive. Confirm failures are visible from domain and service-plan hosts, not just Activity.
- [ ] **Step 5: Commit Task 4 and regenerated templ output.** Suggested message: `fix(notifications): make message actions reliable and accessible`.

### Task 5: Two-Pass Local Acceptance and Handoff

**Files:** Extend existing loopback Operations fixtures/acceptance checks; update `docs/operations-center.md`; add a dated local evidence report under `docs/verification/`. Do not modify installer/provider or hosting runtime code.

**Interfaces:** Use Tasks 1-4's real production views with fictional fixture data; do not substitute the design mockup for implementation acceptance. Existing `TestOperationsBrowserPreview` is the base fixture and must remain loopback-only, agent-free and mail-free.

- [ ] **Step 1: Expand fixtures before the final implementation pass.** Include 0/1/5/50 notifications, a standalone sign-in, linked issue/task, unknown kind, long email/domain/IPv6, safe redaction sentinel, delayed/failed requests, expired session, archived last row, independent search/preview filters and wrapped mobile header. Use deterministic times and varied current roles/scopes.
- [ ] **Step 2: Reproduce every current regression against the actual implementation fixture.** Pin single-alert panel height below 300px for the standard fixture, correct content width, reachable menus, visible error feedback and preserved focus. Preserve failing evidence until it is fixed.
- [ ] **Step 3: Complete local implementation acceptance.** Run `go test ./... -count=1`, `go vet ./...`, `task build`, `node --test internal/control/web/static/*.test.cjs`, and `git diff --check`. Run PostgreSQL Operations tests with `NAKPANEL_OPERATIONS_TEST_DSN` pointing only to a dedicated loopback database named `nakpanel_operations_*`; record executed cases rather than skips. Validate changed shell scripts individually if any exist.
- [ ] **Step 4: Perform two independent browser passes using the loopback fixture.** Pass A: desktop 1440x1000, preview/full inbox, all actions, keyboard, errors and dirty-plan preservation. Pass B: reset fixture state, mobile 390x844, then 320px and 200% zoom, repeating actions and delayed/failed responses. Assert zero horizontal document overflow, no intersecting controls, 14px body text, 44px mobile action targets, no menu/footer clipping, no duplicate receipt POST and no unrelated mutation. Capture and inspect screenshots of rendered application states, not only the design artifact. Use the approved computer/browser tool for manual screenshots and actions.
- [ ] **Step 5: Update behavior/evidence documentation and commit it.** Report each task's outcome and list remaining limitations. Stop for review/integration choice. Hosted acceptance and production deployment require fresh explicit authorization; verify supported Ubuntu 26.04 before any authorized server mutation. Re-run affected checks if concurrent service-plan work changes the shared shell.

## Self-Review / Scope Decisions

- All spec sections map to Tasks 1-5; safe-summary search and standalone opening are not deferred.
- The five Review Focus conditions are assigned above and must appear in test evidence.
- No new schema, notification producer, retention job, recovery operation or dependency is planned.
- SSR rows remain readable before enhancement; JavaScript owns interactive receipt actions as in the current Operations UI. No historical compatibility or full no-JavaScript mutation project is implied.
- Archived ID reads remain authorized, while archived rows stay absent from inbox/count queries.
- New detail reads accept current resource scope; existing personal receipt authorization remains unchanged.
- The prototype's in-memory interactions are illustrative and do not replace testing the integrated views.

## Execution Choice Pending

Review the detailed design, four primary frames, state examples and this plan
before implementation. Native execution is recommended: five tightly coupled
tasks share one poller and rendering lifecycle, and the existing test fixtures
cover the boundaries. Subagent-driven execution is also available if the owner
prefers independent per-task reviews. No application implementation or hosted
work should begin from this plan without that next authorization.
