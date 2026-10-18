# Mail Workspace Figma Implementation

Approved source: [Mail workspace](https://www.figma.com/design/hMmle03TChlSqaWiubt7IQ?node-id=26-4432), with connection, form, settings and mobile frames on the same page.

## Contract

Implement the approved domain-centered Mail UI in Go/templ, existing embedded assets and vanilla JS. Preserve provider/customer ownership, support context, CSRF, audit events, write-only passwords and existing mail operations. Do not add passwordless webmail SSO, POP3 listeners, autodiscover or downloaded credential profiles. No migration is needed.

Webmail links use only validated configured HTTPS hostnames from owned `webmail_hosts` rows. Suspended, disabled, missing or failed services must not present a working-access link. Connection help uses only the mail hostname and observed secure local IMAP/SMTP services, never relay credentials. Verify certificate identity with the system trust store, with bounded loopback probes and no remote-address input. POP3 remains explicitly unavailable.

## Tasks

- [x] 1. Record baseline tests and fetch the detailed Figma views. Reuse the current domain shell, Inter font, icons, dialogs and menus.
- [x] 2. Add failing tests for the mailbox workspace, safe webmail URLs, connection data, ownership, secret exclusion and unavailable states. Implement a minimal public mail-client profile with authenticated scope and verified local TLS protocols.
- [x] 3. Implement compact domain Mail status, email/alias views, filtering, mailbox actions and settings. Keep normal links/forms functional without JS. Make forms single-column and preserve current values and backend field names.
- [x] 4. Add mailbox-specific manual connection and setup-guide dialogs, secure copy feedback, keyboard/mobile behavior and non-JS fallback. Preserve the selected mailbox and support prefix. Do not copy passwords.
- [x] 5. Run Go/JS tests, vet, build, diff and shell checks. Compare desktop/mobile implementation against Figma and obtain one fresh whole-branch review; fix material findings with regression tests.
- [x] 6. Deploy the exact tested panel build atomically on nakpanel.com with binary rollback and health verification. Preserve existing website content, databases, backups and original mailboxes.
- [x] 7. Perform two isolated live verification rounds: admin/customer/support scope, mail UI, mailbox and alias create/edit/password/quota/status flows, webmail sign-in, secure IMAP/SMTP, copies, settings and mobile/keyboard behavior. Use only newly created QA resources for mutation/cleanup and record any untested operations explicitly.

## Verification

`go test ./... -count=1`, `node --test internal/control/web/*test.cjs`, `go vet ./...`, `task build`, `git diff --check`, and relevant shell syntax checks. Browser evidence at 1440x1000 and 390x844; include short-view dialog bounds, clipboard contents without secrets, no document overflow and proper focus restoration.

## Integration

Work on `ricky/mail-figma`, based on main `4850c33`. The user authorized deployment, not a new merge or GitHub push in this request. Leave the tested branch available for finalization.

## Pre-deployment Evidence

Full Go tests, vet, Task build, 119 JavaScript tests and diff checks passed. Browser fixture checks passed at 1440x1000, 390x844 and 1024x620, including clipboard contents, selected mailbox, IMAP/POP state, incoming/outgoing mobile views, search, dialog focus and non-JS fallback.

Independent review findings were fixed: HTML content negotiation, nullable legacy mail-domain site links, shared mobile filtering and real form fallback routes. Form verification also caught and fixed unchecked mailbox/DKIM/mail-service controls being treated as enabled, while preserving legacy API defaults. No migration or agent operation was added.

## Deployment Verification

Completed on 2026-10-18. Deployed code: `9bcc18c`, version `29.0.0+9bcc18c`. Linux panel SHA-256: `42dfb1fe11fd94773a6c9f17b63dfa3ace75ed8eb609cf23947303628004a5a6`. The agent, schema, original mailbox credentials and hosted data were unchanged. Binary rollback is retained under `/var/lib/nakpanel/deployments/mail-9bcc18c/`.

Two complete final-build mail rounds passed using separate synthetic mailboxes (IDs 5 and 6) and aliases (IDs 3 and 4). Each round created an address through the UI, changed quota, reset its password, proved the old password was rejected, created/edited an alias, saved domain settings, authenticated over IMAP 993, SMTP 465 and SMTP 587 STARTTLS, delivered/retrieved a synthetic alias message, and signed in to Roundcube through Open webmail. Each round then disabled/re-enabled and removed its QA address and alias with the confirmation UI.

Desktop, mobile, short-viewport and no-JS checks passed twice on the final build. These covered search, selected-mailbox connection details, secure copies, POP3 unavailable state, setup guidance, creation/edit/settings dialogs, focus/Escape restoration, visible mailbox cards, bounded menus and connection-form fallbacks. Screenshot evidence is in `/tmp/nakpanel-mail-live/` on the development machine.

Earlier live ownership rounds created two isolated client customers, verified cross-customer resource `404` responses and server-mail controls `403`, and verified the admin support workspace. Those customers (IDs 6 and 7) remain suspended with no hosting subscriptions. Automated tests also cover reseller scope and legacy nullable site links.

Final cleanup confirmed only the original `admin` and `notifications` mailboxes, no aliases, and both original hosted sites active. River arguments, audit metadata and panel/agent/mail service logs were scanned for generated plaintext QA credentials and contained none. All six core services and `nginx -t` passed, and trusted HTTPS health returned the deployed version.

Scope boundaries: POP3 was not enabled; webmail is a separate authenticated Roundcube login, not SSO. Import navigation was checked, but no existing customer message archive was imported or modified. SMTP tests used internal synthetic recipients, not an external recipient inbox. Existing data was not reset.
