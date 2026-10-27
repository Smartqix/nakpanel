# Plesk requirements inventory — Phase 2

Status: synthetic inventory and rehearsal planning only. The owner requested
dummy data first after no confirmed customer inventory was found. No live
Plesk server has been contacted and no real customer has been assessed.

## Scope and evidence

Baseline: main commit `24ea971`, with passing
[post-merge CI](https://github.com/Smartqix/nakpanel/actions/runs/40422549043).
That CI proves its recorded scope, not Plesk migration or production readiness.

- Target Ubuntu 26.04 LTS/resolute only, signed Resolute Surý provider.
- Keep hosting PHP 8.3/8.4/8.5 and validated internal PHP 8.5.
- No Ubuntu 24.04 target, older PHP fallback, compatibility shim, historical
  Nakpanel archive support or in-place Plesk conversion is proposed.
- This phase generates synthetic requirements and runs focused local checks.
  Hosted rehearsals, source exports, live migration, DNS changes, mail delivery,
  deployment, commits, pushes and PRs are not authorized by this document.
- Real inventory, application compatibility and all migration results remain
  unknown. Candidate means suitable for a rehearsal, never approved to migrate.

## Fictional inventory

The [JSON fixture](../../migration/fixtures/plesk-customers.synthetic.json)
contains eight independent fictional subscriptions and customer references.
All domains use the reserved .test suffix. Data volumes are metadata only;
there are no large generated archives, real mailboxes, credentials or backups.

| Case | Fictional requirement | Proposed classification | Rehearsals |
| --- | --- | --- | --- |
| S01 | PHP 8.3, WordPress, MariaDB, external mail | Candidate for rehearsal | R1, R4, R5 |
| S02 | PHP 8.4, Composer, cron, SFTP, external mail | Candidate for rehearsal | R1, R2, R4, R5 |
| S03 | PHP 8.5, child mail, internal alias, custom DNS | Candidate for rehearsal; mail catch-up remains a gate | R1, R3, R4, R5 |
| S04 | PHP 8.2, ionCube, Apache access rules | Blocked by runtime requirement; application changes needed | R2 |
| S05 | Native Node.js and managed tenant PostgreSQL | Blocked by missing hosting capabilities | R2 |
| S06 | External forwarding, catch-all, autoresponders, Sieve, contacts and unchanged mail passwords | Blocked by mail feature/import gaps | R3, R4, R5 |
| S07 | MySQL 8 behavior, routines/events/definers, Apache rewrites, transactional writes | Needs SQL/configuration changes and measured rehearsal | R2, R4, R5 |
| S08 | Import beyond message, folder, message-size and archive limits | Blocked; no silent truncation or limit bypass | R3 |

Summary: three rehearsal candidates, one needs changes, four blocked;
zero real subscriptions assessed and zero subscriptions approved to migrate.
These are manual, source-grounded planning decisions. No automatic compatibility
classifier or full Plesk importer is implemented by this work.

## Real inventory intake, when separately selected

Use one parent record per Plesk subscription, with child records for every
domain, subdomain, alias, database, mailbox, access identity and scheduled task.
Preserve customer/reseller ownership and relationships across shared resources.
Do not infer missing values as false, unlimited, empty or compatible.

| Required group | Fields and evidence needed |
| --- | --- |
| Provenance | Operator-selected server/export, Plesk version, source OS/architecture, collection time, completeness, reviewer and private evidence reference |
| Ownership and service | Customer/reseller/subscription references, primary/add-on/child/alias relationships, plan/add-on overrides, suspension and expiry, quotas and actual usage |
| Business constraints | Critical workflows, maintenance window/timezone, permitted downtime and data loss, recovery deadline, reviewer and acceptance owner |
| PHP/apps | Per-domain app/version, source PHP and handler, supported target minor, required extensions/loaders, ini/FPM overrides, Composer lock and writable paths |
| Web behavior | Apache/nginx settings, .htaccess rewrites and access rules, redirects, aliases, headers, protected/hidden files, symlinks and case-sensitive paths |
| Databases | Actual engine/version/location, size, charset/collation/SQL mode, users/grants, routines/views/triggers/events/definers and shared/external dependencies |
| Mail | Local/external routing, domain/child relationships, accounts/aliases/forwarders, quotas, message/folder counts and largest message, filters/autoresponders, contacts/calendars and password-reset constraints |
| Access and jobs | SSH/SFTP/FTP/FTPS identities and confinement, key ownership, cron command/user/cwd/timezone, workers, Git source/branch/hooks and credential references |
| DNS/TLS | Authoritative provider, complete records/TTLs, NS/glue/DS/DNSSEC, MX/SPF/DKIM/DMARC, verification TXT, IPv4/IPv6, certificates/SANs/expiry and renewal ownership |
| Recovery/capacity | Verified source backup, offsite destination/key custody, dataset size/inodes, traffic/concurrency, resource headroom and retention obligations |
| Dependencies | External databases/mail/DNS, payment/email APIs, extensions, billing/provisioning integrations and application license restrictions |

Keep raw exports and the mapping from anonymous references to actual customers
in private operator storage outside Git, with restricted permissions. The
repository may contain synthetic examples and anonymized findings only.
Do not collect password values, hashes, private keys or mail bodies for inventory.
References to credentials describe custody and access, not their contents.

Plesk's documented list/info commands can support metadata collection on an
explicitly selected Linux source. Review output privately before sharing it:

```sh
plesk bin subscription --list
plesk bin subscription --info example.test
plesk bin php_handler --list -json true
plesk bin php_handler --extension-list -id REVIEWED_HANDLER_ID
plesk bin mail --list
plesk bin mail --info mailbox@example.test
```

These examples have not been run. Do not use create/update/remove, handler
replacement, repair, password retrieval, source suspension, DNS changes or
full database dumps as inventory shortcuts. Subscription totals must reconcile
against the source; CLI summaries alone do not cover every field above.

## Compatibility gaps in the current implementation

| ID | Finding and evidence | Required disposition |
| --- | --- | --- |
| G01 | Nakpanel uses nginx; Plesk can depend on Apache and .htaccess. [Plesk behavior](https://docs.plesk.com/en-US/obsidian/administrator-guide/website-management/websites-and-domains/hosting-settings/web-server-settings/apache-and-nginx-settings.72320/) | Translate necessary rules explicitly; verify URLs and negative access checks before eligibility |
| G02 | Only PHP 8.3/8.4/8.5 are hosted; required extensions are readiness checked in [php_capabilities.go](../../../internal/agent/ops/php_capabilities.go) | Upgrade incompatible applications separately; prove each extra loader/extension instead of assuming support |
| G03 | [Agent wiring](../../../cmd/agent/main.go) registers only MariaDB for tenant database provisioning; engine constants/admin registry entries do not prove tenant PostgreSQL/MySQL hosting | Prove scoped MySQL-to-MariaDB conversion or retain an explicitly agreed external service; managed tenant PostgreSQL/MS SQL remain outside current hosting |
| G04 | [Mail aliases](../../../internal/control/quota/mail_accounts.go) resolve only to mailboxes in the same subscription; [mail follow-ups](../../MAIL.md#explicit-follow-ups-not-in-v1) list external forwarding, catch-all, Sieve and autoresponders | Block affected local-mail moves until the requirement is implemented or an alternative is explicitly accepted |
| G05 | [Mail import](../../MAIL_IMPORT.md) verifies messages and receipts, but completion ends source watching; new import records do not share deduplication receipts | Prove final catch-up and late-delivery handling; do not start another import blindly |
| G06 | Import bounds: 100,000 messages, 1,000 folders, 64 MiB/message; Maildir 128 MiB compressed/1 GiB expanded. Contacts/calendars, Sieve and password-hash migration are outside the importer scope | Preserve unsupported data at source; agree explicit transfer/reset handling; no silent exclusions or assumed safe batching |
| G07 | [Feature boundaries](../../FEATURES.md) exclude native Node.js/Python, advanced WordPress cloning/multisite/auto-update policies and full advanced reseller parity | Treat each required feature as a blocker or a separately agreed application change; OCI is not automatic Plesk application conversion |
| G08 | [Git workspace](../../GIT.md) manages one remote per domain; new hosted push access is not offered, and code rollback excludes databases/uploads | Rehearse the selected publishing mode; replace keys/hooks deliberately; provide data recovery separately |
| G09 | DNS preview/apply and local mail readiness do not establish registrar delegation or external delivery; [DNS templates](../../DNS_TEMPLATES.md) preserve custom records | Inventory all records/delegations and validate the selected authoritative route, DNSSEC and TLS endpoints independently |
| G10 | Existing backup/recovery tools cover Nakpanel's current format; no complete Plesk subscription importer or proven reverse customer-data transfer was found | Recreate reviewed intent through normal scoped operations; preserve source recovery assets and prove write-aware rollback |

G03 distinguishes tenant provisioning from Nakpanel's own PostgreSQL control
database and its database-server administration registry. G04 distinguishes an
internal alias from external forwarding. Source MySQL may be convertible;
calling it MariaDB without testing is not conversion.

Mail TLS notes in the older v1 documentation are not blanket evidence of the
current configuration: the current mail renderer sets smarthost
`tls.allow-invalid-certs = false`. Verify actual endpoint trust in rehearsal
instead of repeating older self-signed/unverified-TLS claims.

## Decision rules and handoff

Use candidate_for_rehearsal, needs_changes, blocked or unknown. A missing required
field keeps a real subscription unknown. Every exception needs its owner,
evidence and intended customer outcome; no silent PHP upgrade or dropped feature.

The [rehearsal plan](../plans/2026-10-26-plesk-migration-rehearsals.md)
defines acceptance and abort conditions. Future real inventory replaces
synthetic assumptions, not the production platform contract.

## Primary research

- [Plesk subscriptions CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/subscription-subscriptions.37768/)
- [Plesk PHP handler inventory](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/php_handler-php-handlers.72490/)
- [Plesk mail account inventory](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/mail-mail-accounts.39181/)
- [Plesk migration and synchronization](https://support.plesk.com/hc/en-us/articles/12377889325719-Plesk-Migration-and-Transfer-Guide)
- [Plesk migration limitations](https://support.plesk.com/hc/en-us/articles/12377863617559-What-are-known-limitations-of-Plesk-Migrator-extension)

Plesk Migrator targets Plesk. Its prechecks, synchronization and postchecks are
useful process references, not a ready-made Plesk-to-Nakpanel transfer tool.
