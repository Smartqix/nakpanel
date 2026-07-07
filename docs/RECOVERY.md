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
/home/<site-user>/public_html
/etc/nginx/sites-available/<domain>.conf
/etc/nginx/sites-enabled/<domain>.conf
/etc/php/<version>/fpm/pool.d/nakpanel-<site-user>-<domain>.conf
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
discarded provisioning jobs back to River's `available` state. Completed and
in-flight jobs are not retried from the UI.

The Multipass recovery smoke test is:

```bash
deploy/multipass/phase6-recovery-verify.sh
```

The full Phase 6 Multipass smoke test is:

```bash
deploy/multipass/phase6-verify.sh
```

The full Phase 7 Multipass smoke test is:

```bash
deploy/multipass/phase7-verify.sh
```

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
sudo -u postgres psql -d nakpanel -c "SELECT customer_user_id, plan_id, status FROM subscriptions ORDER BY customer_user_id"
sudo -u postgres psql -d nakpanel -c "SELECT oversell_policy, server_disk_capacity_mb FROM settings"
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

The full Phase 8 Multipass smoke test is:

```bash
deploy/multipass/phase8-verify.sh
```

The full Phase 9 Multipass smoke test is:

```bash
deploy/multipass/phase9-verify.sh
```
