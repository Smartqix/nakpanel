# UI Integration and Fresh Development Installation

> **For agentic workers:** Use superpowers:executing-plans to implement and verify each task.

**Goal:** Integrate the subscription workspace changes and replace the development Nakpanel installation on the existing Ubuntu host.

**Architecture:** Keep the routed Go/templ workspace and central server authorization. Verify the new UI before reinstalling through the unified Ubuntu installer. Preserve only infrastructure needed for SSH, authoritative hostname DNS, and trusted service certificates.

**Tech Stack:** Go, templ, embedded Tailwind/JavaScript, PostgreSQL, River, Linux systemd, nginx, Stalwart and ProFTPD.

**Spec:** User request in this chat: review and fix UI integration; fresh Nakpanel installation while keeping Ubuntu; do not take a new backup.

## Global Constraints
- Do not take a new backup or remove unrelated historic recovery archives.
- Reset only Nakpanel-managed tenant data and runtime artifacts.
- Keep Ubuntu, SSH/firewall access, hostname DNS and trusted panel/mail/FTPS certificates.
- Never weaken CSRF, RBAC, provider/customer isolation or server entitlement enforcement.
- Keep passwords out of logs, job arguments and repository files.

## Review Focus
- Revoked permissions must not hide retained resource inventory or safe deletion actions.
- Client actions must not point to provider-only write routes.
- Displayed usage must agree with enforced subscription usage, including domain-scoped FTP accounts.
- Incomplete collection must not appear as authoritative zero usage.
- Installer/bootstrap defaults must not leave known test credentials enabled on the public server.

### Task 1: Verify and Repair Subscription UI
**Files:** `internal/control/web/subscription_detail.go`, `workspace.templ`, generated templates, workspace queries and focused tests.
- [x] Capture populated desktop/mobile subscription views and permission-disabled states.
- [x] Write failing tests for confirmed integration issues.
- [x] Apply narrowly scoped fixes and regenerate templates/CSS.
- [x] Run full Go tests, vet, build, diff and shell syntax checks.

### Task 2: Fresh Installation Without a New Backup
**Interfaces:** Existing unified `deploy/install/install.sh --fresh --force --yes` installer; operator-only reset orchestration.
- [x] Inventory managed resources, units and paths; record only non-secret validation metadata.
- [x] Stage verified binaries and migrations before stopping services.
- [x] Remove tenant runtimes/data and recreate PostgreSQL intent without changing Ubuntu or SSH.
- [x] Run the fresh installer, provision the real administrator and disable migration-seeded test logins.
- [x] Preserve and reconcile trusted hostname/service TLS and notification infrastructure.

### Task 3: Verify the Fresh System
- [x] Test authentication, plan/customer/subscription onboarding, domains, PHP, database manager, DNS, TLS, backups (read-only), mail and FTPS.
- [x] Verify new subscription tabs and desktop/mobile navigation against real data.
- [x] Remove only temporary verification resources and confirm final service health.
- [x] Commit the reviewed fixes and report the usable URL, reset scope and remaining external prerequisites.

## Execution Notes
- Confirmed and fixed retained inventory hiding, client-only forbidden retry, support navigation/redirects, incomplete measurement handling, aggregate disk/traffic usage, FTP/mail counts, backup totals and overuse copy. Regression tests failed before fixes and passed afterward; full tests, vet, build, diff and shell checks pass.
- Ruling: preserve the existing UI branch `ricky/subscription-detail-redesign`. Inspection confirmed the redesign is on that branch, while main remains on the earlier production release. Deployment uses a verified immutable release, not a mutable working checkout; no unrelated branch is changed or removed by this reset.
- Ruling: no new backup of the current installation. Existing unrelated historic archives remain untouched. Fresh backup/restore screens are verified read-only rather than creating a new archive during the reset.
- User confirmed: rebuild an empty hostname subscription and system mail identities. No prior site content or messages are retained.
- Fresh migrations passed on an isolated empty local database, which was then removed. Live reset removed the three prior domains, tenant database, mail messages, customer/subscription intent and existing plans without a backup. Historic unrelated recovery archives, Ubuntu, SSH and trusted certificates were preserved.
- Unified fresh installer completed; bootstrap password file was privately made readable by the service identity for the administrator-ensure step. Known migration test users and their seeded customers/subscriptions were removed before panel startup.
- Live verification passed for trusted panel/site HTTPS, administrator login, CSRF, active plan and customer/subscription onboarding, per-domain PHP 8.4/8.5 convergence, DNS and both hostname nameservers, all subscription tabs, domain settings pages, temporary database creation and scoped phpMyAdmin, mailboxes/aliases/webmail, authenticated own-server SMTP with delivery to the fresh local administrator mailbox, trusted IMAPS, encrypted passive FTPS and plaintext FTP rejection.
- The disposable database and its encrypted credential were removed after verification. Final intent is one empty hostname site, one customer/subscription, two system mailboxes, default plans plus the hostname infrastructure plan, zero tenant databases and zero backups. nginx, BIND and OpenSSH configuration checks pass; no failed systemd services or pending/retryable River jobs remain.
- External inbox delivery and the complete historical Multipass verification chain were not rerun as part of this fresh-host UI reset. Previous external delivery was confirmed by the user; the external PTR still needs to be set to `mail.nakpanel.com` in the hosting provider console.
- Final UI validation exposed and fixed mobile active-tab clipping, stretched activity icons, misleading interactive-shell copy, and the incorrect migration warning on newly provisioned accounts. Go and JavaScript regression tests passed after failing first. Live mobile checks confirm the active tab is onscreen, activity icons are 24px, and new accounts show migration as not required.
- Final code release is `29.0.0+f4c1be0`. After a service restart, trusted HTTPS, agent ping, SMTP/local delivery, IMAPS and TLS-only passive FTPS passed again. No failed services, disabled-seed-login exposure, backups, temporary databases or retryable/discarded jobs remain. Generated HTTP verification sessions and private temporary cookie/response files were removed.
- Screenshots: `/tmp/nakpanel-ui-reset-20261012/desktop-subscription.jpg` and `/tmp/nakpanel-ui-reset-20261012/mobile-subscription.jpg`. Temporary viewport overrides were reset. The reviewed code is committed on the existing UI branch; merging or publishing the branch remains a separate user choice.
