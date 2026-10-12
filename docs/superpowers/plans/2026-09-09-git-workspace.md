# Domain Git Workspace

Approved scope: one remote repository per domain, with guided connection,
separate fetch/deploy, manual/automatic/disabled modes, commit history,
confirmed overwrite/rollback/disconnect, scoped progress and safe failures.
Preserve existing hosted repositories without advertising new hosted push
access. Preserve the selected UX branch and existing uncommitted changes.

## Execution Ledger

- Runtime: explicit agent actions, pinned SHA, bounded inspection, key and path
  safety, non-destructive disconnect, code rollback. Complete.
- Control: migration 46, serialized revision-fenced operations, persisted
  fetched/deployed state, modes, branch-aware authenticated webhook delivery.
  Complete.
- UI: domain workspace, guided connection, readable forms, histories, dialogs,
  scoped polling and mobile layout. Complete.
- HTTP/integration: server-derived site ownership, CSRF/support scope, JSON and
  ordinary form fallback, regression tests. Complete.
- Verification: independent review, full Go/JS/build checks, disposable-domain
  Ubuntu verification and desktop/mobile browser checks. Complete within the
  verification boundaries below.

## Verification Evidence

- Full Go suite, go vet, Task build, JS tests, shell syntax, and diff checks
  passed. Final UI changes also passed focused web/HTTP and seven Git JS tests.
- Independent review findings were fixed and rereviewed, including failed-write
  restoration, replay safety, stale revisions, and bounded Git subprocesses.
- Ubuntu site 59 verified prepare/fetch/preview, immutable deployment through
  nginx, branch changes, code rollback, disabled mode, automatic deployment,
  wrong-branch rejection, duplicate delivery handling, and non-destructive disconnect.
- Final panel and agent installed on nakpanel-lab; both services are active.
- Desktop settings and 390px mobile navigation were inspected. Mobile document
  width remained 390px; tab switching preserved the URL hash.
- Existing site 58 was not used to publish test code. The disposable domain
  git-workspace-20260909.test is retained with its repository disconnected.
- Private SSH authentication has automated coverage but was not exercised with
  a real private provider repository. The fresh whole-phase VM reset chain was
  not run; verification reused the requested lab and preserved its data.

## Rulings

### Follow-up Recheck

- Fixed Test connection dispatching fetch with automatic publication enabled.
  A distinct test operation now fetches metadata without entering deployment.
- Automatic Pull updates now asks for publication confirmation. Disconnected
  controls are disabled; session expiry and non-JSON errors are actionable.
- Added regression tests and reran the full Go suite, vet, Task build, ten Git
  JS tests, shell syntax and diff checks successfully.
- Repeated Ubuntu verification on site 59 proved connection testing with a
  newer fetched commit leaves published SHA and file content unchanged in
  automatic mode. Webhook deployment, rollback, replay, disabled mode and
  disconnect checks passed afterward. Browser confirmed disconnected controls.
- Updated panel deployed to the existing lab; real site content untouched.

- No merge, push, reset, or replacement with the separate feature worktree.
- Existing hosted repositories remain compatible; new connection UI is remote
  only until authenticated push is verified.
- Manual is the new-repository default; existing automatic values migrate as
  automatic. Disabled means no publication, not deletion.
- Git rollback restores tracked code only, never database state or uploads.
- Public webhook access is not opened automatically on the private lab VM.
- Test deployment uses a disposable domain, never kofik.com content.
