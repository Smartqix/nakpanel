# Feature guide

Current development capabilities; platform and release limits are in
[platform qualification](PLATFORM_QUALIFICATION.md).

- [Operations Center](operations-center.md) with Issues, Tasks, History, personal
  notification read receipts, scoped settings links and independently verified
  recovery. Reading or acknowledging an issue never resolves it.
- HTTPS panel runtime with self-signed bootstrap TLS certificates.
- Login, Argon2id password verification, secure sessions, and role-aware
  dashboards for admins and customers.
- Customer records, service plans, subscriptions, and entitlement checks.
- Production service-plan contracts with draft/active/retired lifecycle,
  live server-readiness validation, immutable revision history, structured
  synchronization previews, and non-destructive subscription compliance.
- Site, database, TLS, backup, restore, DNS, webmail, and reconciliation jobs
  through River.
- First-class, subscription-scoped Mail workspace for domains, mailboxes,
  aliases, DKIM/DMARC, webmail, and administrator Stalwart controls.
- [Maildir/IMAP import](MAIL_IMPORT.md) with reviewed folder mapping,
  encrypted credentials, resumable receipts and verified message preservation.
- [Provider DNS templates](DNS_TEMPLATES.md) with explicit nameservers,
  safe preview/apply, local-deletion preservation and revision-aware jobs.
- `panelctl` operator and recovery commands that work without the web listener,
  while retaining subscription, quota, lifecycle, audit, and River gates.
- ACME, self-signed, and system-trusted custom site certificates with atomic
  agent installation and custom-certificate expiry warnings.
- Website and subdomain creation can secure hosting with free SSL in one setup
  flow when the subscription permits it. Setup waits for DNS, certificate
  installation and HTTPS activation; DNS delays continue in the background.
  SSL-only retry preserves the website, and hidden files remain protected.
- Privileged Unix-socket agent for Linux provisioning work.
- Subscription system accounts with honest account-level disk quotas and
  per-domain document-root usage.
- Domain-centered hosting tools for File Manager, confined SFTP, TLS-only
  FTPS, dedicated PHP-FPM services, structured nginx controls, logs,
  statistics, scheduled tasks, Git, protected directories, and staging.
- GoAccess web statistics in each domain's Statistics workspace, with inherited
  plan settings, daily generation, manual refresh, protected detailed reports,
  and administrator controls for retention, schedule, and IP anonymization.
- Operational OCI containers with digest-pinned images, rootless
  subscription identities, loopback-only nginx ingress, health-gated
  generations, encrypted write-only secrets, rollback, and reboot
  reconciliation.
- One disposable, socket-only Valkey cache per entitled subscription with
  memory/CPU/process ceilings and restricted ACL commands.
- Detailed, readiness-gated PHP 8.3, 8.4, and 8.5 inventory, with PHP 8.4 as
  the default for new eligible sites and explicit older selections preserved.
- Classic PHP hosting for mutable applications, plus native Managed PHP from a
  hosted or remote Git repository with pinned Composer installs, immutable
  health-gated releases, rollback retention, encrypted write-only environment
  secrets, bounded workers, suspension, and reboot reconciliation.
- WordPress 7.1 compatibility on Classic PHP, including trusted custom TLS,
  WP-CLI 2.12.0, backups containing files and tracked MariaDB data, clean
  permalinks, media, cron, sessions, and OPcache.
- A domain-scoped WordPress Toolkit for entitled Classic PHP sites, with
  guided installation, discovery, inventory, checksum verification,
  maintenance mode, hardening, password reset, and backup-gated core,
  plugin, and theme updates.
- Safe WordPress removal with distinct **Detach** and **Uninstall** workflows.
  Detach removes Toolkit tracking without touching hosted data. Uninstall
  removes WordPress files, defaults to a recovery backup, permits deletion only
  for a Toolkit-managed database covered by that backup, and preserves the
  domain, DNS, TLS, PHP, mail, and unrelated databases.
- Adminer SSO for database access from the authenticated panel.
- Owned Ubuntu 26.04 Multipass deployment verification.
- Explicit experimental Ubuntu 26.04 profiles and owned, native OS/architecture
  qualification. [Current evidence and limits](verification/2026-10-18-ubuntu-platform-implementation.md).

The WordPress Toolkit deliberately stops short of cloning, staging, automatic
update policies, multisite orchestration, or plugin/theme installation from
arbitrary sources. Nakpanel does not offer Node.js or Python applications.
Advanced OCI workloads remain separate under the domain's Containers workspace.
