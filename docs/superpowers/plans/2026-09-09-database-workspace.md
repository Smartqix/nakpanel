# Database Workspace and Scoped phpMyAdmin Implementation Plan

**Goal:** Make domain database creation, progress, connection details, password changes, and phpMyAdmin access usable without weakening tenant isolation.

**Architecture:** Retain Go/templ, PostgreSQL intent, River jobs, the encrypted service-secret store, MariaDB and the protected agent. Add an isolated phpMyAdmin runtime behind the authenticated panel proxy. Use database-level grants as the security boundary, not database-list filtering.

**Tech Stack:** Go, templ, vanilla JavaScript, MariaDB, PHP-FPM, phpMyAdmin signon authentication, systemd, Ubuntu 24.04.

## Evidence and Scope

- Database 30 (`test23_db`) exists in MariaDB and is active under site 58 and subscription 39. No creation failure was reproduced for that database.
- Domain database pages originally had no completion polling. A bounded HTML refresh was added; extend it with a small scoped status endpoint and explicit timeout/retry states.
- `/db` currently creates a token and displays it. There is no working Adminer or phpMyAdmin session integration.
- Creation stores an encrypted generated database credential; preserve existing credentials and grant ownership. Never rotate existing passwords merely to implement browser access.
- Keep the selected UX deployment and all unrelated uncommitted work. Do not reset the VM, replace it with the other feature worktree, or delete existing databases.

## User Experience

1. Domain > Databases > Create database: name, default-generated user name, and generated or user-entered password with reveal/copy. Show generated credentials only during this flow, never on a later page reload.
2. Successful submission closes the dialog and inserts a Creating row. Disable repeat submission and retain form values on validation failure.
3. Refresh only status/list summaries. Stop at Active or Failed. At five minutes show Still processing and Refresh status; do not imply failure or enqueue duplicates.
4. Active rows have Open phpMyAdmin, Connection details, and Reset password. Pending/failed rows cannot open phpMyAdmin; failed rows display a safe error and an idempotent Retry action.
5. Connection details show the actual database, username, local host/port and copyable PHP/PDO configuration with a password placeholder. Do not display a guessed password or reveal stored secrets on GET.
6. Password reset warns that applications must be updated. Keep the old credential authoritative until the new credential is applied and verified.
7. No new global Mail-like sidebar module. Keep this workspace under the domain, with server health under Tools & Settings.

## Task 1: Scoped Database Workflow

Files: `internal/control/http/database_workspace.go` and its tests; existing `server.go` route registration; `internal/control/web/workspace.templ`; new `database_workspace.templ`; `static/app.js`; provisioning manager/repository tests.

Proposed routes:

```text
GET  /sites/{id}/databases/status
GET  /databases/{id}/connection
POST /databases                         (preserve existing route)
POST /databases/{id}/retry
POST /databases/{id}/password
```

- Write failing handler tests for selected site/subscription validation, cross-tenant 404, CSRF, disabled/suspended subscriptions, quota rejection, duplicate submit, pending/failed/active responses and support prefixes.
- Validate ownership on every request, derive subscription from the selected site, and reject mismatched browser IDs. Retain explicit subscription-only creation for existing non-domain forms.
- Return 202 JSON with database ID, status URL and safe notice for enhanced submissions; retain 303 fallback for normal forms.
- Status JSON contains only authorized database IDs, display names, state and sanitized errors. No credentials, token hashes, raw River errors or SQL text.
- Bind a create idempotency key to actor/session and normalized payload; repeated submissions return the same intent, conflicting reuse returns 409. Back it with a database constraint, not only a disabled button.
- Retry only failed existing intent, revalidate entitlement/ownership, and fence duplicate active River jobs. Do not generate another database or password.
- Add browser tests for validation recovery, auto-refresh without dialog/focus loss, network failure, timeout, no-JS redirects, duplicate clicks and two-tab submission.

## Task 2: Credential Lifecycle

Files: provisioning credential service alongside `internal/control/provision/repository.go`; shared server administration password operation; HTTP password handler and tests; next unused migration.

- Add a typed request accepting password only on the protected POST. Enforce length/size limits and redact it from all errors. Browser-generated passwords use Web Crypto.
- Reuse the encrypted secret store; River arguments contain database ID, operation ID and secret revision reference only.
- Persist a pending password version. Agent applies ALTER USER idempotently, verifies authentication with the restricted account, and records an operation result. Commit the canonical credential revision after verification.
- If a job or PostgreSQL commit is interrupted, reconcile the same desired secret revision; never generate a replacement on retry. Revoke manager grants during rotation and keep the UI in Updating until convergence.
- Test MariaDB failure, lost agent response, restart after apply, duplicate operation, encrypted-secret persistence and old/new credential convergence.
- Never expose password values in audit metadata, River JSON, logs, status responses, page reloads or connection examples. Audit actor, database ID and result only.

## Task 3: Isolated phpMyAdmin and Session Bridge

Files: `deploy/install/database-manager-install.sh`; dedicated systemd/PHP-FPM configuration; `internal/control/http/database_manager.go`; `internal/control/provision/database_manager.go`; isolated fixed PHP signon adapter; tests; next unused migration.

Proposed routes:

```text
POST /databases/{id}/manager
GET|POST /database-manager/{grantID}/... (fixed upstream proxy)
POST /database-manager/{grantID}/logout
GET /db                                (compatibility redirect, no token display)
```

- First prove a local end-to-end signon spike with an unprivileged test database. Pin a supported stable phpMyAdmin artifact and verify its upstream checksum/signature before installation. Do not ship upstream examples as production authentication code.
- Run phpMyAdmin in its own non-root FPM service with root-owned application code, private writable sessions/temp files and a fixed loopback-only HTTP upstream. It receives no panel database credentials, agent socket, encryption keyring or tenant filesystem mounts.
- Launch is a CSRF-protected POST. Authorize database ownership, active customer/subscription, live database state and MariaDB grants. Return a fresh manager grant bound to the panel session, actor, database and credential revision; store only its token hash.
- Grant bootstrap expires in 60 seconds and is consumed atomically once. Manager idle timeout is 15 minutes with an absolute 60-minute maximum; logout, suspension, permission loss or credential rotation invalidates it.
- On every proxy request, revalidate the panel session and manager grant. Strip incoming internal headers, panel cookies and Authorization before forwarding; accept only the fixed upstream, methods and manager-relative paths. Deny arbitrary targets and traversal.
- Deliver database credentials server-to-server through a narrowly authorized local bridge using a short-lived opaque bootstrap capability. The FPM identity may redeem only that capability, not query arbitrary secrets. Do not pass credentials through redirects, URLs, browser forms, labels or logs.
- Configure phpMyAdmin signon with the selected restricted MariaDB principal. MariaDB grants must exclude global privileges and other customer schemas. A database filter is cosmetic, not authorization. Keep unavoidable system metadata access consistent with MariaDB's permission model.
- Namespace manager sessions per grant so simultaneous databases/tabs cannot switch credentials accidentally. Strip/rewrite Set-Cookie to a manager-only path with Secure, HttpOnly and SameSite; never forward panel cookies to PHP. Apply no-store and no-referrer headers and disable access logging of grant-bearing paths.
- Require panel session revalidation even after phpMyAdmin has its own session; phpMyAdmin logout terminates the grant. Retain phpMyAdmin's CSRF protections and validate origins for state-changing proxied requests.
- Disable setup, arbitrary-server login, remote server selection and unnecessary external integrations. Bound import size, request duration and concurrency separately from ordinary panel form limits.
- Stop displaying legacy Adminer tokens. `/db` redirects to the authorized database inventory with a short selection notice.
- Test replay, expiry, logout, revoked panel session, suspension, header spoofing, path traversal, cross-tenant SQL, two-tab isolation, unready runtime and safe proxy errors before deployment.

## Task 4: UI Completion and Observability

- Use compact existing domain rows and dialogs. Buttons are Open phpMyAdmin, Connection details, Reset password and Retry only when applicable.
- Open manager in a new tab with a visible return-to-domain route; preserve support context while recording the real administrator identity.
- Runtime unavailable state explains the failure to admins and offers Tools & Settings diagnostics; customers receive a contact-provider message. Never offer a dead link.
- Add manager runtime health/version to server diagnostics. Audit manager launch/logout, credential rotation and retry; clarify that raw SQL statements executed inside phpMyAdmin are not captured by panel audit events.
- Render mobile summaries at 390px, at least 44px touch targets, accessible dialog focus and copy confirmation. Do not reset the entire page while an action is open.

## Task 5: Verification and Non-Destructive Deployment

- Run failing tests first for each task, implement only that boundary, then rerun focused Go and JS tests before proceeding.
- Run `go test ./... -count=1`, `go vet ./...`, `task build`, `git diff --check` and shell syntax checks.
- Add a non-destructive database-workspace verifier using unique test resource names on `nakpanel-lab`. Do not run the fresh VM reset command during this repair.
- Create a test database through the actual domain dialog and observe Active without manual refresh. Verify authenticated SQL access, table create/read/update/delete, small import/export and correct database selection.
- Prove a second customer's database cannot be opened through forged IDs or SQL. Prove a reseller is limited to its provider scope and support view retains admin attribution.
- Test password rotation and application connection before/after, logout, session expiry, suspension, service restart and two concurrent database tabs.
- Clean up only verifier-owned resources after explicit ownership checks. Preserve `test23_db` and all existing user data.
- Deploy with panel/runtime backups and rollback instructions. Verify the existing site and database remain operational. Never mark the feature complete based only on a 200 response or a token page.

## Definition of Done

The domain workflow can create a usable database, show completion automatically, provide truthful connection information, rotate credentials safely and open phpMyAdmin without another login. Every operation is tenant-scoped, secrets remain protected, failure recovery is tested, and existing databases and the chosen UX are preserved.

## Sources

- https://docs.phpmyadmin.net/en/latest/setup.html (signon authentication)
- https://docs.phpmyadmin.net/en/latest/config.html (SignonSession, cookie/session and server configuration)

## Deferred

Remote MariaDB access, arbitrary SQL in Nakpanel itself, database deletion, multiple extra database users and roles, a global root database console and scheduled database backups are not required for this repair.

## Implementation Verification (2026-09-09)

- Deployed the selected UX branch's panel, agent, CLI and isolated phpMyAdmin
  runtime to the existing lab without resetting it. Applied migrations 44/45.
- Browser verification passed creation, automatic Active transition, duplicate
  submission replay, connection details, password rotation and old-grant denial.
- Real phpMyAdmin SQL, import/export and logout passed. MariaDB denied access to
  `mysql.user` and the other database. Reviewed the 390px domain layout.
- Removed only the four verifier-owned databases (31-34). Database 30,
  `test23_db`, remains active; its data and password were not replaced. Its legacy
  underscore grant was narrowed to the literal database name.
- Added durable agent database ownership markers and escaped GRANT patterns
  after security review. Restore marker preservation/adoption has unit coverage,
  but a full-server restore was not performed on the live lab.
- Session expiry, suspension, provider/support scope and proxy boundaries have
  automated coverage. A full multi-role live lifecycle/expiry matrix remains a
  separate acceptance exercise; do not interpret this lab run as that coverage.
- Runtime diagnostics currently use the authenticated launch preflight and
  systemd service status, not a new Tools & Settings inventory screen. Panel
  audits record manager launch/logout and credential changes, not raw SQL.
