# Operations center — phase 1

Local implementation on `ricky/operations-center-design`, based on `b6e7002`.
No hosted tests, external mail, PR or release actions were performed.

## Changes

- Added typed resources, operation/attempt states, incident identity,
  acknowledgement, verification fencing tokens and recovery capability types.
- Added current-design PostgreSQL operations, attempts, issues and event/outbox
  tables. Event dedupe and incident updates share the producer transaction.
- Replaced shared notification read state with per-user receipts. Existing quota
  reads use the viewer's receipt and the same current-ownership predicate.
- Permission checks reject stale roles and unrelated tenants. Personal security
  messages stay private from other administrators. Acknowledgement leaves an
  issue open; a new attempt cannot rewrite an earlier failure.
- Regenerated SQLC models using the pinned v1.30.0 tool.

## Local evidence

Dedicated loopback PostgreSQL database `nakpanel_operations_20261023`; every test
creates and removes its own schema. Tests reject remote databases and fallbacks.

- `go test ./internal/control/operations ./internal/control/quota ./internal/types ./migrations -count=1`: passed with `NAKPANEL_OPERATIONS_TEST_DSN` set.
- `go test -race ./internal/control/operations -count=1`: passed with the same DSN.
- `go test ./...`: passed with the operations DSN and GNU Bash 5 on PATH.
- `git diff --check`: passed.

Coverage includes concurrent incident dedupe, duplicate source events,
transaction rollback, per-user receipts, current ownership/role denial, retained
attempt failures and applying the new migration to the complete current schema
and rolling it back. The first full baseline used macOS Bash 3 and failed the
qualification harness admission tests. Installing GNU Bash 5 and placing it on
the test PATH resolved that environment failure without changing those tests.

The UI, event dispatcher, worker producers, independent verifiers and delivery
policy remain for subsequent phases. Schema and focused tests do not establish
hosted or end-to-end acceptance.
