# Activity, notifications and recovery

Activity provides Issues, Tasks, History and a personal Notifications inbox.
Every request uses current ownership and role; support and subscription views
keep their resource scope. Reading is personal. Acknowledgement records that
someone is looking; it never resolves an issue. Original failed attempts remain
in history after a retry or verified recovery.

The first automatic recovery action is backup retry. Its preflight checks current
ownership, permissions, quota, conflicting work, agent reachability, Ubuntu 26.04
and a minimum free-space reserve. It does not promise the backup will fit or that
the destination is writable. The worker reloads current intent before execution.
Other problems link to their resource settings. Restores have no generic retry.

Scheduled observation checks certificates within 14 days of expiry and overdue
backup protection, with UTC schedule evaluation and 30 minutes of grace. A
current independent probe must verify recovery. Queue completion, metadata,
reading or acknowledgement cannot do so. Verifier receipts state their limits:
archive checksum/size is not a restore rehearsal; local TLS is not public DNS;
local mail/webmail readiness is not verified external delivery. All hosting
PHP 8.3/8.4/8.5 requirements remain in place on Ubuntu 26.04.

## Email policy and preferences

Notification email is off by default at both server and personal levels. In
Activity → Notification preferences, an administrator enables the server policy;
each user chooses Off, Immediate or Daily digest. Critical and security notices
always remain available in app. Preferences never backfill old email.

The operator configures `NAKPANEL_SMTP_HOST`, `NAKPANEL_SMTP_FROM` and the existing
SMTP port/TLS/credential settings privately. SMTP passwords are never returned
by the preferences API. Server backup destination notification addresses select
registered, authorized administrators who have opted into email; an arbitrary
unscoped address does not receive an alert. Security notices follow the current
account audience; the old standalone security `--alert-email` override is removed.

Daily digests close at 00:00 UTC and are sent on the following delivery tick.
Events are deduplicated per user. Immediately before transmission, delivery
rechecks current role, ownership, address, preferences and server policy. Identity
rows remain locked during the bounded SMTP call so a concurrent transfer cannot
race this final authorization. Digests summarize up to 50 updates and explicitly
count additional authorized updates available in Activity.

**Accepted by SMTP** means the configured server accepted the message. Recipient
inbox arrival is not established. A transient or uncertain send can be retried;
SMTP does not provide exactly-once delivery. Each batch has at most eight tries,
with increasing delays. Stored failures contain safe codes, not raw transport
errors or credentials. Delivery failure creates one private in-app incident;
that incident and its recovery never generate further email. Later SMTP
acceptance verifies only the delivery incident, never the underlying hosting issue.

## Development schema and release validation

This is the current development design. The schema replaces address-only email
delivery records with scoped user batches; it does not migrate historical email
receipts. Development databases and fixtures may be recreated. Detailed history
is retained; the earlier 30/90-day retention proposal is not an active deletion
policy. No automatic pruning is enabled by this change.

Run operations PostgreSQL tests only against a dedicated loopback database whose
name starts with `nakpanel_operations_`, using `NAKPANEL_OPERATIONS_TEST_DSN`.
Fixtures create private schemas. No hosted server is launched by these tests.
`NAKPANEL_OPERATIONS_UI_PREVIEW=1 go test ./internal/control/web -run
'^TestOperationsBrowserPreview$' -v` starts a loopback-only fictional UI fixture
for visual checks; it never contacts an agent or sends external mail.

Hosted Ubuntu 26.04 acceptance, external mail, a PR, merge and deployment require
separate authorization. Local results do not establish hosted acceptance.
