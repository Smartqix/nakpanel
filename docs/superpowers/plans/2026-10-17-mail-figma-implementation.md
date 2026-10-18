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
- [ ] 6. Deploy the exact tested panel build atomically on nakpanel.com with binary rollback and health verification. Preserve existing website content, databases, backups and original mailboxes.
- [ ] 7. Perform two isolated live verification rounds: admin/customer/support scope, mail UI, mailbox and alias create/edit/password/quota/status flows, webmail sign-in, secure IMAP/SMTP, copies, settings and mobile/keyboard behavior. Use only newly created QA resources for mutation/cleanup and record any untested operations explicitly.

## Verification

`go test ./... -count=1`, `node --test internal/control/web/*test.cjs`, `go vet ./...`, `task build`, `git diff --check`, and relevant shell syntax checks. Browser evidence at 1440x1000 and 390x844; include short-view dialog bounds, clipboard contents without secrets, no document overflow and proper focus restoration.

## Integration

Work on `ricky/mail-figma`, based on main `4850c33`. The user authorized deployment, not a new merge or GitHub push in this request. Leave the tested branch available for finalization.

## Pre-deployment Evidence

Full Go tests, vet, Task build, 119 JavaScript tests and diff checks passed. Browser fixture checks passed at 1440x1000, 390x844 and 1024x620, including clipboard contents, selected mailbox, IMAP/POP state, incoming/outgoing mobile views, search, dialog focus and non-JS fallback.

Independent review findings were fixed: HTML content negotiation, nullable legacy mail-domain site links, shared mobile filtering and real form fallback routes. Form verification also caught and fixed unchecked mailbox/DKIM/mail-service controls being treated as enabled, while preserving legacy API defaults. No migration or agent operation was added.
