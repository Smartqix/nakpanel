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
- [ ] Review, commit and deploy the cache form fix.
- [ ] Finish first complete live hosting acceptance pass and cleanup its isolated fixtures.
- [ ] Repeat acceptance with independent new customer/subscription resources.
- [ ] Verify final browser/server state and remove temporary test data and credentials.

## Acceptance Scope
Authentication/CSRF/RBAC, customer and subscription onboarding, plan preview, PHP and WordPress creation, database idempotency and scoped phpMyAdmin, mailbox/alias management, PHP inheritance/reset, files, backups/restores, tasks/logs, DNS/subdomains, Git keys/fetch, Composer managed releases/workers and failed-candidate rollback, OCI health/routing/rollback/removal, Valkey isolation, inherited suspension/reactivation, MFA/recovery, support view, statistics, FTPS/SFTP, and desktop/mobile navigation.

Destructive actions are confined to newly created acceptance subscriptions. Do not run the historical Multipass reset chain against this public installation. OS upgrades and restoring production/server-level archives are not acceptance mutations.

## Findings
- The previous development reset removed PostgreSQL/MariaDB schemas but retained `/var/lib/nakpanel-agent/database-ownership` records and some orphan principals. Recycled database IDs were correctly rejected by the agent. Never weaken this check; before clearing a stale marker, verify its schema is absent and its name/principal is not current intent. Roundcube and current tenant databases/principals remain untouched.
- First-use cache configuration used fixed limits above smaller plan grants and exposed optional credential rotation instead of required initialization. New forms now derive finite defaults from the effective snapshot and request initial credential generation; existing configuration saves do not rotate credentials by default.
- Fresh review found that allocation gates must retain existing cache inventory and include account-wide CPU/process ceilings. Regression tests failed before correction and now cover these cases, unlimited grants and zero limits.
- A stale node-wide FTPS snapshot acknowledged every FTP row, including a newly created account not yet applied. Convergence now acknowledges only captured account IDs whose intent has not changed since the snapshot; both success and failure updates are fenced. A worker regression reproduced the broad update before the fix.
- Initial harness retries were needed after repairing the WordPress fixture: the failed bootstrap had not filled its runtime identity fields. These are harness setup failures, not additional product failures.

## Constraints
External inbox receipt is not established by local SMTP acceptance. Provider PTR remains an external prerequisite. No arbitrary private-root trust, password disclosure, shell weakening, or bypass of plan ceilings is permitted.
