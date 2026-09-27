# nakpanel Recovery

The panel is served directly by the `panel` binary on HTTPS port `7443`.
It does not depend on the tenant nginx listener.

Use this URL when nginx is stopped, broken, or has invalid tenant vhost config:

```text
https://<server-ip>:7443
```

On a fresh install, the panel generates a self-signed bootstrap certificate in
`/var/lib/nakpanel/tls`. The browser warning is expected until an operator later
installs a real certificate for the panel hostname.

For Phase 1 Ubuntu/Multipass testing, the seeded accounts are:

```text
admin@nakpanel.test  / NakpanelAdmin!2026
client@nakpanel.test / NakpanelClient!2026
```

Operational checks:

```bash
sudo systemctl status nakpanel.service
sudo systemctl status nakpanel-agent.service
sudo ss -ltnp | grep 7443
curl -k https://127.0.0.1:7443/healthz
```

## Recovery CLI

`panelctl` uses PostgreSQL directly and does not require the HTTPS listener.
Run it as `nakpanel` so file staging and `agent ping` use the same UID as the
panel service:

```bash
sudo -u nakpanel env \
  NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  panelctl user list
```

Bootstrap an administrator when no usable admin login remains:

```bash
sudo -u nakpanel env \
  NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  panelctl --actor recovery-console create-admin --email recovery@example.test
```

The password prompt is hidden. For non-interactive recovery, provide
`--password` through a protected process environment or invocation mechanism
and clear shell history as appropriate. Useful recovery commands include:

```bash
sudo -u nakpanel panelctl session revoke-user user@example.test --yes
sudo -u nakpanel panelctl user suspend user@example.test --yes
sudo -u nakpanel panelctl user unsuspend user@example.test
sudo -u nakpanel panelctl site reconcile example.test
sudo -u nakpanel panelctl reconcile --system
sudo -u nakpanel panelctl agent ping
```

All successful mutations create `audit_events` entries labeled with the OS
actor or `--actor`. Provisioning commands enqueue River work and continue to
enforce the selected subscription's entitlement snapshot.

## Custom Site Certificates

Custom certificates are validated against the Ubuntu system trust store before
being staged, and revalidated by the root agent before installation. The
staging directory is `/var/lib/nakpanel/tls-staging`; abandoned private `0600`
files are removed after 24 hours. Installed files are under
`/var/lib/nakpanel/certs/<domain>` with a `0700` directory and `0600` certificate
and key files.

```bash
sudo -u nakpanel panelctl ssl set-custom example.test \
  --cert /secure/example.crt --key /secure/example.key \
  --chain /secure/intermediate.crt --yes
```

The agent runs `nginx -t` before reload and restores the previous certificate,
key, and vhost if testing or reload fails. Check state without exposing key
material:

```bash
sudo -u postgres psql -d nakpanel -c \
  "SELECT domain,tls_issuer,tls_status,tls_auto_renew,tls_expires_at,tls_last_error FROM sites ORDER BY domain"
sudo journalctl -u nakpanel -u nakpanel-agent -u nginx --no-pager -n 200
sudo nginx -t
```

Custom certificates are excluded from ACME renewal. Nakpanel creates a
deduplicated `certificate_expiring` warning during the certificate maintenance
sweep when fewer than 14 days remain.

The panel must not bind ports `80` or `443`; those remain reserved for tenant
sites served by nginx.

Phase 3 adds a River-backed provisioning worker inside the panel process. On a
fresh install, run both schema steps before starting `nakpanel.service`:

```bash
sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' task goose:up
sudo -u nakpanel env NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' task river:up
```

Generated site state is intentionally split:

```text
/home/<subscription-user>/domains/<domain>/public_html
/etc/nginx/sites-available/<domain>.conf
/etc/nginx/sites-enabled/<domain>.conf
/etc/nakpanel/php-fpm/sites/<site-id>.conf
/etc/systemd/system/nakpanel-php-fpm@<site-id>.service
```

If a site create job fails, check:

```bash
sudo -u postgres psql -d nakpanel -c "SELECT id, domain, status, last_error FROM sites ORDER BY id"
sudo journalctl -u nakpanel -u nakpanel-agent -u nginx -u php8.3-fpm --no-pager -n 200
sudo nginx -t
```

Phase 6 adds the operations lane:

```text
/var/lib/nakpanel/backups/<domain>-<timestamp>.tar.gz
/etc/nginx/sites-available/webmail.<domain>.conf
/etc/nginx/sites-enabled/webmail.<domain>.conf
/etc/bind/nakpanel/zones/db.<domain>
```

Sign in as an admin, open **Operations**, and use the backup, webmail, DNS, and
regenerate controls. Adminer SSO is issued from `/db` on the same authenticated
`:7443` listener.

Phase 7 makes restore executable from the backup table. A restore creates a
`restore_runs` row, extracts `files/` from the selected archive into a fresh
docroot, moves the previous docroot aside as
`.nakpanel-before-restore-<timestamp>`, restores selected database dumps from
`databases/*.sql`, and marks the run active or failed. Treat restore as
destructive: check the selected backup ID and current tenant state before
submitting it.

Phase 7 DNS writes both the zone file and BIND include files:

```text
/etc/bind/nakpanel/zones/db.<domain>
/etc/bind/nakpanel/zones.d/<domain>.conf
/etc/bind/nakpanel/named.conf
```

Validate DNS recovery with:

```bash
sudo named-checkzone <domain> /etc/bind/nakpanel/zones/db.<domain>
sudo named-checkconf /etc/bind/nakpanel/named.conf
sudo systemctl status named.service
```

Phase 6 also extends admin retry for exhausted provisioning jobs. Use **Retry
job** on a `discarded` `create_site`, `create_database`, `issue_cert`,
`create_backup`, `configure_webmail`, `configure_dns_zone`, or
`reconcile_system` row after fixing the underlying OS or agent problem. Phase 7
also includes `restore_backup` jobs in retry handling. The
panel validates the job kind and state, then atomically moves only matching
discarded provisioning jobs, including `install_custom_cert`, back to River's
`available` state. Completed and
in-flight jobs are not retried from the UI.

The full deployment smoke test uses one fresh Ubuntu 24.04 Multipass VM named
`nakpanel-lab`. It removes old `nakpanel-phase*` Nakpanel test VMs, rebuilds
`nakpanel-lab`, runs the complete Phase 25 hosting-toolkit chain, preserves the
Phase 26 server-operations checks, and finishes with the adversarial security
suite:

```bash
deploy/multipass/deployment-verify.sh
```

Individual phase verifiers are still useful for debugging. They now reuse the
same VM by default, or you can set it explicitly:

```bash
NAKPANEL_MULTIPASS_VM=nakpanel-lab deploy/multipass/phase25-verify.sh
```

## Phase 26 Upgrade Recovery

`deploy/install/phase26-install.sh` creates a timestamped recovery set before
changing binaries or schema:

```text
/var/lib/nakpanel/upgrade-backups/phase26-<UTC timestamp>/
```

It contains the previous binaries and systemd units, the previous secret-key
file when present, and `nakpanel-before-phase26.dump`. Start by identifying the
latest set and checking whether the Phase 26 schema committed:

```bash
backup="$(sudo find /var/lib/nakpanel/upgrade-backups -maxdepth 1 -type d -name 'phase26-*' | sort | tail -1)"
sudo -u postgres psql -Atqd nakpanel -c \
  "SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1"
sudo systemctl status nakpanel.service nakpanel-agent.service
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200
```

If the latest applied migration is Phase 26 or later, keep the Phase 26
`panel`, `agent`, and `panelctl` binaries together. Do not restore only one old
binary onto the newer schema. A failed secret conversion can be retried
idempotently:

```bash
sudo -u nakpanel env \
  NAKPANEL_DATABASE_URL='postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable' \
  NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json \
  /usr/local/bin/panelctl secret-key migrate --path /etc/nakpanel/secret-keys.json
sudo systemctl restart nakpanel-agent.service nakpanel.service
curl -kfsS https://127.0.0.1:7443/healthz
```

To abandon the upgrade completely, restore the database dump and the matching
pre-upgrade binaries as one recovery operation. The following assumes the
default local `nakpanel` database:

```bash
sudo systemctl stop nakpanel.service nakpanel-agent.service
sudo -u postgres dropdb --if-exists --force nakpanel
sudo -u postgres createdb -O nakpanel nakpanel
sudo -u postgres pg_restore --exit-on-error --dbname=nakpanel \
  "${backup}/nakpanel-before-phase26.dump"
sudo install -m 0755 "${backup}/nakpanel-panel" /usr/local/bin/nakpanel-panel
sudo install -m 0755 "${backup}/nakpanel-agent" /usr/local/bin/nakpanel-agent
sudo install -m 0755 "${backup}/panelctl" /usr/local/bin/panelctl
sudo cp -a "${backup}/nakpanel.service" /etc/systemd/system/nakpanel.service
sudo cp -a "${backup}/nakpanel-agent.service" /etc/systemd/system/nakpanel-agent.service
sudo systemctl daemon-reload
sudo systemctl restart nakpanel-agent.service nakpanel.service
```

Verify `backup` is non-empty and inspect its contents before running the
destructive restore. For a remote or non-default PostgreSQL deployment, restore
through that deployment's normal database procedure instead.

## Hosting Toolkit Recovery

Phase 21-25 generated state is rebuilt from PostgreSQL intent. Do not hand-edit
these files:

```text
/etc/nakpanel/proftpd/proftpd.conf
/etc/nakpanel/proftpd/AuthUserFile
/etc/ssh/sshd_config.d/90-nakpanel-<subscription-user>.conf
/etc/nginx/nakpanel/protected/site-<site-id>/
/var/lib/nakpanel/git/site-<site-id>/
/etc/nakpanel/valkey/sub-<subscription-id>/
/etc/systemd/system/nakpanel-valkey@<subscription-id>.service
```

After correcting intent or a missing package, reconcile and validate:

```bash
sudo -u nakpanel panelctl reconcile --system
sudo nginx -t
sudo sshd -t
sudo proftpd -t -c /etc/nakpanel/proftpd/proftpd.conf
sudo systemctl status nakpanel-proftpd.service
sudo systemctl status 'nakpanel-php-fpm@*.service'
sudo systemctl status 'nakpanel-valkey@*.service'
```

Valkey has no TCP listener and no persistence. Its application credential is
shown once; rotate it from the subscription Cache workspace if lost. A restart
or reactivation intentionally returns an empty cache. Protected-directory,
FTPS, mailbox, webhook, and cache credentials are write-only and cannot be
recovered from the panel.

Phase 8 originally adds account quotas and Linux user disk quotas. In a pure
Phase 8 deployment, missing `account_quotas` rows are treated as unlimited and
explicit zero values are real zero limits. Phase 9 replaces runtime quota
entitlement with plans and subscriptions; review the Phase 9 notes below before
changing quotas on an upgraded system. Site creates still derive PHP-FPM and
disk limits server-side, and the agent enforces them with per-pool PHP-FPM
settings plus `setquota` on the filesystem that contains `/home/<site-user>`.

Quota recovery checks:

```bash
sudo quota -u <site-user>
sudo repquota -a
sudo findmnt -n -o TARGET,OPTIONS --target /home/<site-user>
sudo journalctl -u nakpanel-agent --no-pager -n 200
```

If provisioning fails with a quota error, install/enable quota tooling on the
tenant filesystem, then restart the agent and retry the failed job from the
dashboard:

```bash
sudo apt-get install -y quota
sudo apt-get install -y "linux-modules-extra-$(uname -r)"
sudo modprobe quota_v2
sudo quotacheck -ugm "$(findmnt -n -o TARGET --target /home)"
sudo quotaon -uv "$(findmnt -n -o TARGET --target /home)"
sudo systemctl restart nakpanel-agent.service nakpanel.service
```

Phase 9 moves entitlement from `account_quotas` to active subscriptions on
plans. A customer without an active subscription is denied site, database, and
backup provisioning before any agent job is queued. `-1` plan limits mean
unlimited, while explicit `0` still means zero allowed. The `/quotas` route is
kept only as a compatibility path that creates a custom legacy plan and active
subscription.

Plan/subscription recovery checks:

```bash
sudo -u postgres psql -d nakpanel -c "SELECT id, name, is_active FROM plans ORDER BY id"
sudo -u postgres psql -d nakpanel -c "SELECT id, customer_id, plan_id, name, status FROM subscriptions ORDER BY customer_id, id"
sudo -u postgres psql -d nakpanel -c "SELECT oversell_policy, server_disk_capacity_mb, valkey_capacity_mb FROM settings"
sudo journalctl -u nakpanel --no-pager -n 200
```

If provisioning fails with `no active subscription`, assign the customer an
active plan from the admin dashboard or insert a corrected active subscription
after verifying the intended customer and plan. If `oversell cap exceeded`
blocks a plan assignment, either raise `settings.server_disk_capacity_mb`,
switch `settings.oversell_policy` to `warn`, or move active customers to finite
plans that fit the cap.

The agent also rejects Unix socket clients whose Linux peer UID is not the
panel user. If panel-to-agent RPC fails after a user or service change, confirm
the panel service runs as `nakpanel`, the agent can resolve that UID, and the
socket is still owned `root:nakpanel` with mode `0660`.

For a full quota/plans/subscriptions integration check, prefer the single-VM
deployment verifier:

```bash
deploy/multipass/deployment-verify.sh
```

## Server Backup & Full Disaster Recovery (Phase 29)

Phase 29 adds whole-server backups and a one-command rebuild. An archive
(`*.nkbk`) contains the panel PostgreSQL dump, `/etc/nakpanel` (including the
secret keyring), tenant MariaDB dumps, home directories, mail configuration
and data, DNS zones, certificates, nginx vhosts, and the managed systemd
units — everything a fresh Ubuntu 24.04 server needs to become this server
again. Archives are always encrypted (chunked AES-256-GCM).

### Key custody

```bash
sudo -u nakpanel panelctl backup-server key init
```

The `nkbk1-...` key is displayed exactly once. Store it offline. Without the
key, archives are unrecoverable — by design, since they contain the secret
keyring and password hashes. `backup-server key status` shows the fingerprint.

### Destinations and schedules

```bash
sudo -u nakpanel panelctl backup-server destination add --name offsite --kind sftp \
  --settings-file sftp.json --credential-file sftp-cred.json \
  --schedule '0 2 * * *' --retention-count 7 --retention-days 30
sudo -u nakpanel panelctl backup-server destination test offsite
sudo -u nakpanel panelctl backup-server run --destination offsite --wait
```

Kinds: `local` (default `/var/lib/nakpanel/server-backups`), `sftp`
(`{"host","port","path","username","host_key"}` with a
`{"private_key"| "password"}` credential), and `s3`
(`{"endpoint","region","bucket","prefix"}` with
`{"access_key","secret_key"}`). Credentials are sealed in the encrypted
service-secret store. Schedules are standard cron expressions evaluated by a
sweep every minute — edits apply without a panel restart. Every backup is
verified after upload: the archive is streamed back through its
authentication layer and the PostgreSQL dump is checked with
`pg_restore --list`. Failures raise a `server_backup_failed` notification to
the destination's notify address or all administrators.

### Rebuilding a destroyed server

On a fresh Ubuntu 24.04 host, from a checkout of this repository:

```bash
sudo deploy/install/install.sh --restore /path/to/archive.nkbk --backup-key-file /path/to/key --yes
```

or, after a plain `sudo deploy/install/install.sh --fresh`:

```bash
sudo panelctl restore-server --archive /path/to/archive.nkbk --backup-key-file /path/to/key --yes
```

The restore stops services, recreates the managed Linux accounts with their
original numeric ids, replaces the panel database (`dropdb --force` +
`pg_restore`), cancels stale queued jobs, re-imports tenant MariaDB dumps and
recreates their users from the restored encrypted credentials, extracts every
state tree, realigns the `stalwart_directory` role password, restarts
services, queues a full system reconciliation, and health-checks the panel.
The binaries on the fresh host must carry the same migration set as the
archive; on mismatch the restore aborts with instructions
(`--allow-schema-mismatch` proceeds and expects `make goose-up` afterwards).

`deploy/multipass/phase29-verify.sh` automates this exact drill (populate,
upgrade with rollback drills, reboot, destroy-and-restore onto a second VM)
and `docs/SOAK.md` describes the 30–60 day soak window.

### Upgrade rollback (generalizing Phase 26)

`deploy/install/install.sh` auto-detects upgrades, takes a pre-upgrade backup
set under `/var/lib/nakpanel/upgrade-backups/<version>-<stamp>/` (binaries,
units, `/etc/nakpanel`, `pg_dump`), and rolls back automatically:

- failure **before** migrations: previous binaries/units/config restored
  byte-identically;
- failure **after** migrations (including a failed health gate): the database
  is restored from the pre-upgrade dump, then the previous binaries return —
  pass `--rollback-schema manual` to keep the new binaries and hand off
  instead (the old Phase 26 behavior).

Version state lives in `/etc/nakpanel/version` and `panelctl version`;
same-version reruns are no-ops and downgrades are refused without
`--allow-downgrade`.

### Administrator recovery (Phase 29)

```bash
sudo -u nakpanel panelctl user set-password admin@example.com    # revokes sessions
sudo -u nakpanel panelctl user disable-2fa admin@example.com --yes
sudo -u nakpanel panelctl user recovery-codes admin@example.com --yes
sudo -u nakpanel panelctl user unlock admin@example.com          # clears login throttle
```

All work over root SSH with the panel down (they talk to PostgreSQL
directly). Failed logins are throttled durably (10 per email / 20 per IP in
15 minutes) and logged to journald in the format the `nakpanel-login`
fail2ban jail matches.

## Production PHP Application Recovery (Phase 30)

Phase 30 adds Classic PHP and native Managed PHP hosting on the subscription
system account. PHP 8.3, 8.4, and 8.5 are accepted only when the agent reports
the CLI, required extensions, OPcache, and a dedicated PHP-FPM validation as
ready. Composer and WP-CLI are root-owned pinned tools; their self-update paths
are disabled. A missing runtime or stale host artifact fails closed instead of
silently selecting another binary.

Classic sites keep mutable `public_html` ownership and use the existing site
backup flow. A backup includes both the site files and every panel-tracked
database assigned to that site. For a WordPress recovery, restore through the
panel or the supported CLI and wait for the durable restore row:

```bash
sudo -u nakpanel panelctl backup list example.test
sudo -u nakpanel panelctl restore <backup-id> --yes
sudo -u nakpanel panelctl site reconcile example.test
```

Each Managed PHP application keeps Git source, environment intent, worker
intent, and deployment history in PostgreSQL while immutable releases and
root-only environment files live on the host. An unhealthy candidate does not
replace the active release.
After repairing Git, runtime, Composer, malware signatures, or policy, use the
domain's **PHP Application** workspace to queue another deployment or request
reconciliation. A server restore deliberately does not start PHP-FPM or worker
units from archived systemd state; the startup sweep reconstructs only the
active release and each desired-active worker from current control-plane
intent.

For diagnosis, keep values out of terminal output and inspect identities and
states rather than environment contents:

```bash
sudo systemctl status 'nakpanel-php-fpm@<site-id>.service'
sudo systemctl status 'nakpanel-php-worker@<worker-id>.service'
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200
sudo -u nakpanel panelctl site reconcile example.test
```

The canonical live acceptance is `deploy/multipass/phase30-verify.sh`. It
installs the current worktree on Ubuntu 24.04, proves WordPress 7.1
compatibility and Managed PHP rollback/suspension/reboot behavior, and verifies
cross-subscription access denial. This is compatibility coverage, not a
WordPress Toolkit, and it does not add Node.js or Python application runtimes.

## Service Plan Recovery (Phase 31)

Plan rows are current intent; `plan_revisions` is immutable history. Never
repair a subscription by editing `subscription_entitlements` or a revision row
directly. Open the plan in **Service Plans**, review readiness and preview,
save a new revision with a reason, then wait for synchronized subscriptions to
return to `in_sync`.

An activation blocked by runtime readiness is deliberate. Repair the reported
server capability first, confirm it under **Tools & Settings**, then activate
the draft again. A failed check leaves the plan draft and records the readiness
error; it does not make an undeliverable offer assignable.

Lowering a limit never deletes existing customer data. A synchronized
subscription already beyond the new contract is marked `over_limit` and shows
the violated count or measured limit. Restore compliance through normal
product operations or a new plan revision. Collect fresh usage before judging
disk or traffic; `unknown` means measurement is incomplete, not compliant.

Useful read-only diagnostics:

```bash
sudo -u postgres psql nakpanel -c \
  "SELECT id,name,lifecycle_status,revision,last_validated_at,readiness_error FROM plans ORDER BY id"
sudo -u postgres psql nakpanel -c \
  "SELECT plan_id,revision,definition_hash,actor_label,change_reason,created_at FROM plan_revisions ORDER BY id DESC LIMIT 20"
sudo -u postgres psql nakpanel -c \
  "SELECT id,name,sync_status,compliance_status,compliance_error,compliance_checked_at FROM subscriptions ORDER BY id"
```

The final live contract gate is `deploy/multipass/phase31-verify.sh`. It runs
Phase 30 unless explicitly told to reuse an already verified lab.

## WordPress Toolkit Recovery (Phase 32)

The Toolkit treats PostgreSQL intent, the encrypted service-secret row, the
panel-tracked MariaDB database, and the site document root as one managed
installation. Do not place credentials in River rows or repair an installation
by editing `wordpress_instances` directly.

Every core, plugin, theme, or aggregate update first creates a normal Nakpanel
backup and waits for it to become active. If an update fails, keep that recovery
point, restore it through the supported backup workflow, and then refresh the
domain's **WordPress** workspace. A failed candidate never deletes its backup.

For an interrupted install, first confirm whether WordPress was configured in
the document root. Retrying the same Toolkit install is safe when the generated
database identity matches; the agent observes the existing installation instead
of replacing `wp-config.php`. A failed discovery placeholder can be retried from
the same domain without creating a second Toolkit identity.

Useful diagnostics avoid printing database or administrator credentials:

```bash
sudo -u postgres psql nakpanel -c \
  "SELECT site_id,installed_version,desired_revision,applied_revision,convergence_status,last_error FROM wordpress_instances ORDER BY site_id"
sudo -u postgres psql nakpanel -c \
  "SELECT instance_id,kind,target_type,status,backup_id,last_error,created_at FROM wordpress_operations ORDER BY id DESC LIMIT 20"
sudo journalctl -u nakpanel -u nakpanel-agent --no-pager -n 200
```

Use the WordPress workspace to refresh inventory, verify checksums, reapply
hardening, or explicitly disable maintenance mode after service recovery.
Password resets are write-only and cannot be recovered from the panel; set a
new password instead.

The final live Toolkit gate is `deploy/multipass/phase32-verify.sh`. It runs
Phase 31 unless explicitly told to reuse an already verified lab.

## Safe WordPress Uninstall Recovery (Phase 33)

**Detach** and **Uninstall** have different recovery contracts. Detach removes
the Toolkit record and operation history but leaves WordPress files and its
database unchanged. Uninstall keeps the site, subscription, DNS, TLS, PHP,
mail, and unrelated databases while replacing WordPress with the Nakpanel
placeholder. Never imitate either operation with manual deletes.

An uninstall normally moves through these states:

- `waiting_backup`: the recovery backup is still being created or verified.
- `removing`: backup evidence is complete and the agent is converging files
  and, when explicitly requested, the Toolkit-managed database.
- `removed` with `in_sync`: PostgreSQL intent is committed, the domain serves
  the placeholder, and the asynchronous quarantine cleanup may be finishing.
- `failed`: convergence stopped safely. Read `last_error`, repair the reported
  dependency, confirm the original site state, then retry from the WordPress
  workspace. Do not edit the instance revision or operation status.

Find the recovery point without printing secrets or archive paths:

```bash
sudo -u postgres psql nakpanel -c \
  "SELECT operation.id,operation.status,operation.backup_id,backup.status AS backup_status,backup.size_bytes,(backup.checksum_sha256<>'') AS checksum_present,backup.database_names FROM wordpress_operations operation LEFT JOIN backups backup ON backup.id=operation.backup_id WHERE operation.kind='uninstall' ORDER BY operation.id DESC LIMIT 20"
sudo -u postgres psql nakpanel -c \
  "SELECT site_id,desired_state,observed_state,desired_revision,applied_revision,convergence_status,last_error FROM wordpress_instances ORDER BY site_id"
```

Database removal is allowed only for a Toolkit-managed database and only after
the active same-site recovery backup lists that exact database in
`database_names`. A discovered or external database is always preserved. If a
database check fails before mutation, the agent leaves or restores the original
WordPress document root and records a retryable failure; repair MariaDB before
retrying.

The agent owns the root-only removal marker and quarantine under the domain
account. Do not delete, rename, chown, or edit these artifacts manually. They
are the idempotency and rollback record used after worker interruption or
restart. Reinstall from the removed workspace reuses the tombstone identity and
creates fresh managed application data through normal product routes.

The final live safety gate is `deploy/multipass/phase33-verify.sh`. It runs
Phase 32 unless explicitly told to reuse an already verified lab.

## Web Statistics Recovery (Phase 34)

GoAccess reports supplement the existing disk and traffic quota counters.
Report generation failures do not suspend hosting or change quota usage.
Open the domain's Statistics workspace to inspect the latest successful
generation, report period, pending work, and any collection error. A manual
refresh queues background work and is rate-limited.

Administrators manage the engine, daily schedule, retention, and IP privacy
under Tools & Settings > Web Statistics. Domain settings inherit from the
subscription's entitlement snapshot; updating a service plan requires the
normal subscription synchronization workflow. A site override requires the
plan's statistics-management permission.

When a refresh fails, the last complete report remains available. A privacy
settings change may temporarily make an older report unavailable until a new
report has been generated under the new settings. Do not publish report files
inside a tenant document root or bypass the panel's report access checks.

Reports can only cover retained nginx logs. Increasing report retention cannot
reconstruct logs already removed by log rotation. Visitor counts are log-based
estimates, and origin logs do not include requests served entirely by a CDN.

Check the installed engine with `goaccess --version`, and inspect panel/agent
service logs when generation fails. Fix the underlying package, filesystem,
or parsing issue, then use Refresh report. Do not alter quota cursors to
repair analytics. The Phase 34 verifier exercises report generation through
the panel and the privileged agent on the existing single-VM stack.
