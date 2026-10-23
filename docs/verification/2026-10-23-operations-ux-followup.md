# Operations center — UX follow-up

Implementation: `51eeb1d6d75a9a7036df7e3c25ee7790d05c92fd` on
`ricky/operations-center-design`, following local acceptance at `de3bfb3`.
The owner authorized these two fixes and focused local tests only.

Both previously deferred UX findings are resolved.

## Direct settings links

Issue details return fixed application settings destinations after the current
viewer has passed the existing issue authorization predicate. Site links target
the relevant backup, TLS, hosting, mail, DNS, task, database or application page;
subscription, customer, server and personal delivery issues use their applicable
settings pages. Server settings remain administrator-only; unavailable customer
settings direct the client to their provider.

Current resource existence is read with the issue. Administrators can retain
historical incident visibility after removal without receiving a stale settings
link. Customer support links preserve the customer path for sites/subscriptions.
Following a link uses the existing GET route, which rechecks current access.
External or malformed destinations are rejected, and denied/removed details
show an explicit unavailable state.

## Read on open

Opening a notification's issue or task records only the viewer's personal read
receipt after the primary details have loaded and rendered. This applies to the
initial server-rendered inbox, polled rows and quick inbox. It refreshes counts
through the existing scoped read model. Opening an ordinary issue from Activity
is independent of notification receipts.

Closing before details load, or receiving a denied response, does not record a
read. Failed receipt writes keep the details open and explain that Mark read can
be retried. No opening handler sends acknowledge, verify or recovery actions.
The database regression verifies unchanged issue acknowledgement, resolution,
generation and latest event, independent read state for another viewer, and
receipt denial after ownership transfer.

## Focused local validation

- `go test ./internal/control/operations ./internal/control/http ./internal/control/web ./internal/control/provision -count=1 -timeout 120s`: **all four packages passed**, using private schemas in a disposable loopback PostgreSQL 18 cluster.
  [Package output](evidence/2026-10-23-operations-ux/final-focused-go.log).
- `node --test internal/control/web/static/operations.test.cjs internal/control/web/static/navigation-lifecycle.test.cjs`: **13 passed, 0 failed**.
- Focused headless Chrome loopback fixture: **8 scenarios passed**, with no script errors:
  initial inbox read-on-open, polled quick inbox read-on-open, task notifications,
  close-before-load, customer support settings links, denied details, removed
  settings and failed receipt feedback.
  [Browser output](evidence/2026-10-23-operations-ux/final-browser.log).
- `go vet` on operations/HTTP/web passed. Pinned templ 0.3.960 regeneration was
  idempotent. `git diff --check` passed.
- The missing settings destination/availability, missing read-on-open POST,
  denied-resource message and malformed destination were reproduced before their
  corresponding fixes; the final checks are green.

The browser fixture uses fictional resources; database authorization/state tests
use real local PostgreSQL. No hosted VM, external mail, push, PR, merge or
deployment ran. The earlier complete-suite evidence remains attributed to its
original revision; unchanged broad checks were not repeated for this follow-up.
Hosted acceptance and required PR CI remain separate authorization gates.
