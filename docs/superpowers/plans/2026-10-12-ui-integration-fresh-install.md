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
- [ ] Inventory managed resources, units and paths; record only non-secret validation metadata.
- [ ] Stage verified binaries and migrations before stopping services.
- [ ] Remove tenant runtimes/data and recreate PostgreSQL intent without changing Ubuntu or SSH.
- [ ] Run the fresh installer, provision the real administrator and disable migration-seeded test logins.
- [ ] Preserve and reconcile trusted hostname/service TLS and notification infrastructure.

### Task 3: Verify the Fresh System
- [ ] Test authentication, plan/customer/subscription onboarding, domains, PHP, database manager, DNS, TLS, backups, mail and FTPS.
- [ ] Verify new subscription tabs and desktop/mobile navigation against real data.
- [ ] Remove only temporary verification resources and confirm final service health.
- [ ] Commit/push the reviewed fixes and report the usable URL, reset scope and remaining external prerequisites.

## Execution Notes
- Confirmed and fixed retained inventory hiding, client-only forbidden retry, support navigation/redirects, incomplete measurement handling, aggregate disk/traffic usage, FTP/mail counts, backup totals and overuse copy. Regression tests failed before fixes and passed afterward; full tests, vet, build, diff and shell checks pass.
- Ruling: keep the current main checkout, following the user's earlier request to merge work into main and remove other branches.
- Ruling: no new backup of the current installation. Existing unrelated historic archives remain untouched. Fresh backup/restore screens are verified read-only rather than creating a new archive during the reset.
- Ruling: preserve DNS/TLS infrastructure independently of tenant content; rebuild an empty hostname subscription and system mail identities by default to preserve the user's previously requested own-server notification email. No prior site content or messages are retained.
