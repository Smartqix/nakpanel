# Subdomain mail — Phase 2 local verification

Date: 2026-10-22. Phase base: `87044f1` (completed Phase 1).
Branch: `ricky/subdomain-mail-phase1`, reused in the attached implementation worktree.
Main remains at `d992462`; no hosted tests, server changes, push, PR, merge or
deployment were performed. The user authorized Phase 2 only.

## Demonstrated failures and fixes

- Reconciliation could silently suppress a record at a CNAME and still publish
  the other mail records. It now checks all required names before mutation and
  reports the conflict. Active MX/NS/service endpoint collisions are rejected;
  an otherwise unused `mail` label is allowed.
- A child delegated by NS records received ineffective parent-zone defaults.
  The worker now preserves the delegation and records and gives requirements
  for the delegated provider. A separate local child zone checks that its apex
  NS set matches the configured parent delegation; missing/different delegation
  gets an explicit action notice without changing parent records.
- Custom MX/SPF/authentication records and conflicting records owned by another
  site could suppress local defaults without readiness feedback. They remain
  preserved and now produce an action notice; no extra local MX/SPF is mixed in.
- External DNS previously received generic guidance. The notice now includes
  child record names and values, including the actual generated public DKIM
  record returned by the agent. Private keys stay on the server.
- A failed or malformed agent acknowledgement could leave an existing domain
  marked `in_sync`. Failures now update only the captured domain intents and
  remain visible as failures. Missing requested DKIM output also fails.
- Reconciliation changed the caller's desired-record slice in place. Scoping
  now works on a copy; unchanged reconciliation preserves rows, revisions and
  queued-job counts.
- DNS record and mode edits did not invalidate old mail readiness. They now
  mark affected domains pending and enqueue one existing mail recheck per user
  transaction, including parent/separate zone transitions. The mail worker's
  internal DNS reconciliation does not enqueue another mail job.

The Mail workspace separates mail setup pending/failed, DNS pending/failed,
DNS action required, external DNS requirements and DNS applied locally. It
reads zone status and desired/applied revisions live, including parent delegation
application for a separate child zone. It does not label a queued DNS change as
applied. Multi-line public record guidance remains readable and escaped.

## Preservation evidence

Current-schema disposable PostgreSQL fixtures contain a parent, child and
sibling. Row fingerprints prove that parent/sibling canaries are unchanged by
child reconciliation and worker runs. Custom routing survives enabled
reconciliation, key refresh and repeated DNS cleanup. CNAME conflicts perform
no DNS mutations. Parent-zone children use `child`, `mail.child`,
`nak1._domainkey.child` and `_dmarc.child`; separate zones use apex-relative names.

No schema, dependency, OS or PHP runtime contract changed. Ubuntu 26.04 only,
hosting PHP 8.3/8.4/8.5 and the existing signed provider remain unchanged.
No compatibility adapters, backfills or historical matrices were added.

## Focused local checks

macOS ARM64; pinned Go 1.26.9; owned disposable PostgreSQL 17.11, Unix socket
only, database `nakpanel_removal_test`. Existing VMs and other PostgreSQL
instances were untouched. The worker's agent response is a fixture; this is
not live BIND, Stalwart or external DNS evidence.

| Evidence | Result |
| --- | --- |
| Existing DNS baseline before changes | 5 top-level tests passed, no skips |
| Main final provision/web/HTTP slice | 20 top-level tests passed, no skips |
| Final DNS-mode/template/record-edit slice | 6 top-level tests passed, no skips |
| Distinct tests across both final slices | **24 top-level tests passed** |
| `go vet` on provision/web/HTTP, then affected DNS-template/provision packages | Passed |
| Pinned templ 0.3.960 regeneration comparison | Passed; generated output identical |
| `gofmt` and `git diff --check` | Passed |

The second final slice repeats two tests because the shared transactional recheck
helper changed to support DNS mode transitions. Unchanged hosted, PHP, recovery
or historical checks were not repeated. JavaScript did not change.

The exact Go commands, complete outputs and exit metadata are retained in this
plan's ignored `.superpowers/sdd/2026-10-22-subdomain-mail/` directory under
`phase2-final.*`, `phase2-mode-green.*`, `phase2-vet-final.*`,
`phase2-mode-vet.*` and `phase2-generated-check.*`.

Failure evidence remains in the same directory. The first four direct CNAME
fixtures incorrectly assigned MX-only priority to CNAME and failed SQL validation.
After correcting those fixtures, only those cases were replayed against the
original Phase 1 mail worker, with the current file restored in a `finally`
block. They then demonstrated the actual missing-conflict and DNS-mutation bugs.
The remaining original regressions, protected-owner warning and DNS-mode
recheck failures were separately observed before their fixes.

## Review and phase boundary

Independent review is pending before the final phase report. The phase stops
before Phase 3 quota/lifecycle work. No live agent, authoritative DNS query,
public delegation/propagation, SMTP, IMAP, Roundcube or external delivery was
verified. Those claims require later explicitly authorized acceptance.

Local fixture evidence cannot establish hosted Ubuntu acceptance. The existing
current-format backup/restore and runtime requirements remain required; their
implementation did not change in this phase.
