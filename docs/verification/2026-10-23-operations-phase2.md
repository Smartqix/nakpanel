# Operations center — phase 2

Local implementation follows phase 1 commit `6624c32`. No hosted tests, external
mail, PR or release actions were performed.

- Added scoped paginated Issues, Tasks, History and Inbox queries, detail routes,
  personal read/archive actions and issue acknowledgement. Counts ignore page
  size and use the same live ownership boundary as rows and actions.
- Snapshot queries use a repeatable-read transaction. The browser feed uses a
  publication cursor assigned during dispatch, rather than source sequence IDs;
  a source transaction that commits late is still delivered on the next poll.
- A River worker publishes committed outbox rows and acknowledges them in one
  PostgreSQL transaction. Rollback/restart replays the projection; repeated
  execution cannot publish a second copy. No external side effect occurs in it.
- The Tasks API now reads authorized operations for all three roles. Its quick
  view prioritizes active work and failures; routine successes cannot bury an
  older active task. Full pagination remains separate. Removed the obsolete
  dashboard task endpoint reader.
- HTTP responses exclude raw worker arguments and errors. New mutation routes
  use the existing session, origin, body-limit and CSRF guards.
- Added the dispatcher to the node-level site-removal job classification and
  regenerated SQLC models with the pinned tool.

## Local evidence

`NAKPANEL_OPERATIONS_TEST_DSN` names the dedicated loopback database used in
phase 1. Tests create disposable schemas; the River test applies its real
migrations in one of those schemas.

- `go test ./...`: passed with GNU Bash 5 on PATH and the operations test DSN.
- `go test -race ./internal/control/operations -count=1`: passed.
- Focused operations, HTTP, dashboard, web and panel tests: passed.
- `git diff --check`: passed.

Tests cover late source commits, dispatch rollback/replay, cursor pagination,
counts beyond eight rows, ownership transfer, cross-tenant detail/feed denial,
scope filters, independent unread counts, quick-view priority, authenticated
viewer binding, invalid request bounds, CSRF and diagnostic redaction.

A real River insertion test first reproduced default uniqueness suppressing all
dispatcher ticks after a completed tick. Explicit active-state uniqueness fixes
that and preserves overlapping-tick dedupe. The full suite also caught the new
worker missing its removal classification; that integration is now included.

Initial root-page badges and tray HTML still use the existing dashboard
presentation until phase 4. Worker event producers, verification and recovery
are phase 3. This is backend acceptance only, not completed UI/hosted acceptance.
