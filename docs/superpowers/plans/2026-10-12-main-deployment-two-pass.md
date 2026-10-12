# Main Deployment and Two-Pass Acceptance

**Request:** Deploy the latest main to nakpanel.com, deeply check the implemented workflows twice, and repair issues.

**Target:** Ubuntu 24.04, nakpanel.com / 2.29.45.217. Preserve hosted hostname services, PostgreSQL intent, trusted certificates, mail identities and SSH. No reset, OS upgrade, or new full-server backup.

## Progress
- [x] Confirm clean GitHub/local main at f4c2c10 and inspect live release f4c1be0.
- [x] Build native Ubuntu binaries and deploy immutable release f4c2c10 with rollback; verify trusted HTTPS and agent ping.
- [x] Run Go/JavaScript tests, vet and build locally; run Linux tests and a second Linux suite against a freshly migrated disposable PostgreSQL database.
- [x] Verify administrator pages, responsive navigation, SMTP/IMAP/FTPS and agent UID rejection.
- [x] Diagnose WordPress failure from stale pre-reset database ownership markers. Remove only verified orphaned development markers/principals; preserve ownership validation. Retry the failed database and WordPress installation successfully.
- [x] Reproduce new cache form failure with regression tests before correcting credential initialization and entitlement-derived defaults.
- [x] Review, commit and deploy cache onboarding and FTPS convergence fixes (505a4b6); native Ubuntu tests/vet/build and trusted HTTPS health checks pass.
- [x] Finish first live hosting acceptance pass (audit1791834007), rerun failed checks after repairs, and tear down its isolated hosting fixtures.
- [x] Repeat acceptance with independent resources (audit1791837166): 120 named checks, 103 administrator pages, and no outstanding failures after retries.
- [x] Verify desktop/mobile navigation and protocols; remove temporary hosted resources, customers and subscriptions, revoke fixture sessions and disable the retained restore-audit login identities.

## Acceptance Scope
Authentication/CSRF/RBAC, customer and subscription onboarding, plan preview, PHP and WordPress creation, database idempotency and scoped phpMyAdmin, mailbox/alias management, PHP inheritance/reset, files, backups/restores, tasks/logs, DNS/subdomains, Git keys/fetch, Composer managed releases/workers and failed-candidate rollback, OCI health/routing/rollback/removal, Valkey isolation, inherited suspension/reactivation, MFA/recovery, support view, statistics, FTPS/SFTP, and desktop/mobile navigation.

Destructive actions are confined to newly created acceptance subscriptions. Do not run the historical Multipass reset chain against this public installation. OS upgrades and restoring production/server-level archives are not acceptance mutations.

## Findings
- The previous development reset removed PostgreSQL/MariaDB schemas but retained `/var/lib/nakpanel-agent/database-ownership` records and some orphan principals. Recycled database IDs were correctly rejected by the agent. Never weaken this check; before clearing a stale marker, verify its schema is absent and its name/principal is not current intent. Roundcube and current tenant databases/principals remain untouched.
- First-use cache configuration used fixed limits above smaller plan grants and exposed optional credential rotation instead of required initialization. New forms now derive finite defaults from the effective snapshot and request initial credential generation; existing configuration saves do not rotate credentials by default.
- Fresh review found that allocation gates must retain existing cache inventory and include account-wide CPU/process ceilings. Regression tests failed before correction and now cover these cases, unlimited grants and zero limits.
- A stale node-wide FTPS snapshot acknowledged every FTP row, including a newly created account not yet applied. Convergence now acknowledges only captured account IDs with exactly matching desired fields and intent timestamps. Node-wide read/apply/acknowledgement is serialized with a PostgreSQL transaction advisory lock, shared by billing teardown before its intent deletes. Failed runtime or rollback operations remain visible. Real PostgreSQL tests cover late-committed edits, overlapping acknowledgements, lock release on commit/rollback, and failure after prior readiness; worker and teardown regressions cover captured rows and lock ordering.
- Initial harness retries were needed after repairing the WordPress fixture: the failed bootstrap had not filled its runtime identity fields. These are harness setup failures, not additional product failures.
- Actual SFTP authentication exposed a root-only key-store read failure: OpenSSH attempts ordinary AuthorizedKeysFile reads as the account user. The agent now emits a fixed root-run AuthorizedKeysCommand for the validated account path; key files remain 0600 and directories 0700, with forced internal SFTP, chroot, no TTY and no forwarding. The regression test failed before correction; native sshd validation and a live key-authenticated SFTP transfer/start-directory/confinement test pass after release e179cb5.
- Staging queue creation rolled back because PostgreSQL could not infer variadic JSON audit parameter types. Explicit bigint/text/boolean casts fix the production statement; a real PostgreSQL regression reproduced SQLSTATE 42P18 before correction and passed afterward.
- Files-only staging then copied successfully but could not persist its result because a nil database-snapshot slice became SQL NULL in a NOT NULL array column. The completion statement now stores an empty array. The exact production SQL failed the PostgreSQL regression before repair and passed afterward, including on Ubuntu. Existing fixture jobs were retried; copy and confirmed promotion succeeded in both subscriptions.

## Final Evidence
- Runtime fixes verified on Ubuntu in release cbf76b2, following the initial latest-main deployment. Native Go tests, vet/build and all seven focused PostgreSQL FTPS/staging regressions pass.
- Local full Go suite passes against a freshly migrated disposable database; focused quota/web race tests, all 32 JavaScript tests, Task build, shell syntax and diff whitespace checks pass.
- Live acceptance includes plan/customer onboarding, WordPress install/operations/backed-up uninstall, PHP version/reset, scoped databases and phpMyAdmin, mail/aliases, file edits, backup/restore, DNS/subdomains, tasks/logs, Git keys/fetch, managed Composer releases/workers, OCI rollback/removal, Valkey, MFA/support view, inherited suspension/reactivation, staging, and site/database/backup quota rejection without intent or enqueue.
- Trusted hostname HTTPS, SMTP STARTTLS, IMAPS delivery, encrypted passive FTPS, plaintext FTP rejection and unauthenticated relay rejection pass twice. Actual SFTP key authentication, root-only key permissions, domain start directory and chroot confinement pass in both resource sets.
- Desktop and 390px mobile subscription navigation have no document overflow; active tabs stay visible, the drawer closes with Escape and no console errors were recorded.
- Final hosted inventory is one active nakpanel.com website, one hostname customer/subscription, two system mailboxes, zero tenant databases/backups, and no failed systemd services or outstanding retry/discard jobs.
- Immutable retired verification plan revisions and disabled login identities referenced by restore history are retained deliberately. No immutability trigger or audit constraint was bypassed. Temporary fixture customers/subscriptions and all hosted files/services were removed through account teardown.
- The updated Phase 21 verifier includes a real SFTP handshake/confinement check. Its static/syntax tests and equivalent live Ubuntu checks pass; the full historical Multipass reset chain was not run against this public server.
- Destructive server-level restore, OS upgrades, multi-server/reseller live onboarding and external inbox receipt were not acceptance mutations. Provider PTR still requires an external hosting-provider change.

## Constraints
External inbox receipt is not established by local SMTP acceptance. Provider PTR remains an external prerequisite. No arbitrary private-root trust, password disclosure, shell weakening, or bypass of plan ceilings is permitted.
