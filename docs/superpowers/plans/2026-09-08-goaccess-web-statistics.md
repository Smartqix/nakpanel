# Phase 34: Domain Web Statistics

## Approved Scope

Implement the Plesk-inspired GoAccess recommendations approved on September 8,
2026. Domain Statistics remains the entry point; provider sidebars gain no
separate analytics module. Existing quota accounting stays authoritative.

## Delivery

- [x] Add typed statistics contracts, durable settings/report state, and plan
  inheritance through subscription entitlement snapshots. Disabled and GoAccess
  are the engine choices; site overrides require explicit permission.
- [x] Add bounded agent report generation from server-derived domain logs.
  Scrub request and referrer query parameters, apply configured IP anonymization,
  support rotated logs, and retain the last complete report on failure.
- [x] Schedule daily River collection and rate-limit manual refresh. Store
  identifiers in jobs and expose generation period, freshness, pending state,
  and sanitized errors.
- [x] Add native domain summaries and an authenticated, sandboxed detailed
  report. Enforce ownership, provider scope, support-view context, CSRF, and
  audit events. Reports live outside tenant website directories.
- [x] Add administrator Web Statistics settings for engine health, retention,
  generation schedule, and privacy. Privacy changes invalidate incompatible
  reports until regenerated.
- [x] Install GoAccess through the Ubuntu deployment workflow and add the
  Phase 34 verifier after Phase 33.
- [x] Review code and test authorization, privacy, resource bounds, rotation,
  failed refresh retention, inherited permissions, and UI states. Run relevant
  Go tests, vet, build, shell checks, and live Ubuntu verification.

## Defaults And Boundaries

Daily generation and manual refresh are the initial modes. Live WebSocket
reporting is unnecessary. Reports are always accessed through the panel login;
there is no public statistics directory or reused FTP password. Generated
GoAccess scripts run in a sandbox without the panel origin's privileges.
Retention describes available report data and is bounded by retained nginx logs;
the UI must not imply recovery of logs that have already been deleted.

## References

- [Plesk website statistics](https://docs.plesk.com/en-US/obsidian/administrator-guide/statistics-and-monitoring/viewing-web-statistics-for-websites.80044/)
- [GoAccess manual](https://goaccess.io/man)

## Execution Record

- Existing Phase 31-33 worktree retained so this feature extends the deployed
  WordPress Toolkit. No merge or push is part of this request.
- Implementation delegated as one integrated task; parent performs independent
  operational research, documentation, review, and final verification.
- Passed `go test ./... -count=1`, `go vet ./...`, `task build`, focused race
  tests, deployment shell syntax checks, and `git diff --check`.
- The first live migration encountered an existing account-teardown guard.
  Backfill now excludes terminating/terminated accounts without disabling that
  guard; a real PostgreSQL regression test verifies preservation.
- Live generation exposed GoAccess 1.8.1's explicit stdin argument requirement.
  The corrected bounded command passed both a regression test and Ubuntu use.
- `NAKPANEL_SKIP_PRIOR_PHASES=1 deploy/multipass/phase34-verify.sh` passed on
  `nakpanel-lab` (`192.168.252.68`), creating site 57 through product routes.
  The existing lab was upgraded; the destructive fresh full chain was not run.
- Desktop 1440px and mobile 390px browser checks passed for the domain report
  and server settings. The detailed report rendered 22 charts with no JavaScript
  errors, no document overflow, and no access to the parent panel document.
