# nakpanel.com webmail repair — 23 October 2026

The Mail workspace now shows **Webmail Ready** and **Open webmail** for
`kofi@nakpanel.com`. The public endpoint is <https://webmail.nakpanel.com/>.

## Cause

The Business plan's webmail preset was false. Subscription 3 had no override,
no `webmail_hosts` row and no webmail DNS record. Roundcube 1.6.19 and its SQLite
database were installed, but `/etc/roundcube/config.inc.php` did not exist. The
existing website certificate covered `nakpanel.com`, not `webmail.nakpanel.com`.
The UI collapsed these distinct setup prerequisites into “Unavailable”.

[Plesk documents separate installation, server enablement and domain selection
for webmail](https://support.plesk.com/hc/en-us/articles/12377287661719-How-to-install-and-manage-webmail-in-Plesk).
An active mailbox alone does not establish webmail availability.

## Live configuration changes

- Used the authenticated panel to set subscription 3's policy override to
  `{"mail":{"webmail":true}}`. Other subscriptions and the Business plan itself
  were not changed.
- Added only `webmail.nakpanel.com A 2.29.45.217` through the domain DNS form.
- Installed Certbot and its nginx authenticator from Ubuntu Resolute packages.
  No existing package was upgraded or removed.
- Issued the `nakpanel-webmail` Let's Encrypt certificate, expiring
  21 January 2027, and configured the agent's exact webmail TLS hostname and
  certificate/key paths. Set `NAKPANEL_MAIL_TLS_HOSTNAME=nakpanel.com` so
  Roundcube verifies its loopback IMAP/SMTP certificate identity.
- Restarted the agent and configured webmail through the panel. Its job
  completed with an active host and no error. Roundcube uses internal PHP 8.5.
- Configured nginx authentication for certificate renewal, enabled Certbot's
  timer and installed a deployment hook that tests and reloads nginx.
  `certbot reconfigure` completed its simulated renewal successfully.

No application binaries, database schema, hosting PHP versions or website
configuration were deployed or changed. The runtime remains commit `3879f77`.

## Verification

- Trusted Chrome HTTPS navigation reached the real Roundcube login page.
- A new, uniquely named temporary mailbox authenticated through Roundcube and
  reached its Inbox. It then logged out. No test mail was sent and no existing
  user's inbox was opened.
- Removed that mailbox through the panel and its owned Roundcube test profile.
- Compared the remaining mailbox records, including their password hashes,
  against a private pre-change digest: identical. Kofi's password was never
  read, reset or used.
- Existing DNS records, both website configurations and baseline website files
  matched the pre-change evidence. The only additional DNS record was the
  intended webmail A record.
- HTTP redirects with 301; trusted HTTPS returns 200. nginx configuration is
  valid. Panel, agent, nginx, Stalwart and PHP 8.3/8.4/8.5 services are active.
- After cleanup, the Mail workspace reports Ready and presents the HTTPS link.

Private baseline, rollback configuration and verification receipts are retained
under `/root/nakpanel-deployment/webmail-20261023/`. They contain operator data
and are not committed. Credentials are excluded from this report.

## Local source changes

The separate `ricky/webmail-readiness` branch explains disabled policy,
unconfigured, queued and failed setup states. It exposes **Enable webmail**
before first configuration, retains **Reconfigure webmail** afterward, and shows
the setup failure explanation. Generated templates and operator instructions
were updated together. Provisioning behavior and hosted recovery fixtures were
kept outside this UI change; the live HTTPS repair uses existing supported
configuration.

Focused local Mail/Webmail tests passed (14 test/subtest results, zero failures;
one opt-in browser preview skipped). `go vet` passed. No hosted qualification
suite, push, PR, merge or application deployment was launched for this change.
The unrelated subscription activity-preview commit remains on its own branch.
