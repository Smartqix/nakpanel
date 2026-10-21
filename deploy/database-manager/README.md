# Isolated Database Manager Runtime

Target: opt-in installation on Ubuntu 26.04 LTS using validated internal PHP
8.5. Hosting PHP 8.3/8.4/8.5 remains independent. Installer/service alignment is complete locally;
operational qualification is pending; this documentation change
does not establish production readiness. The existing entrypoint is:

```sh
sudo bash deploy/install/database-manager-install.sh --yes
```

This installs phpMyAdmin 5.2.3 from the official release archive, verifies the
pinned SHA-256 before extraction, and enables two dedicated non-root services.
Existing public nginx and panel service definitions are not replaced. A panel
drop-in adds only the bridge directory write permission and runtime supplementary
group. Restart the panel separately after deploying the matching Go bridge.

## Contract

- Fixed HTTP upstream: `http://127.0.0.1:9082` (never expose this listener publicly).
- Runtime identity: `nakpanel-dbmgr:nakpanel-dbmgr`, never a panel group member.
- Panel environment: `NAKPANEL_DATABASE_MANAGER_KEY_FILE=/etc/nakpanel/database-manager.key`.
- Panel key: root-owned, `root:nakpanel`, mode `0640`. Runtime receives only a copy
  of this runtime-specific key at `/etc/nakpanel-database-manager/proxy.key`.
- Bridge socket: `/run/nakpanel-db-manager/bridge.sock`, mode `0660`,
  `nakpanel:nakpanel-dbmgr`. Tmpfiles creates its parent with mode `0750` at boot.
- Each request requires `X-Nakpanel-Manager-Key`, a 64-hex namespace in
  `X-Nakpanel-Manager-Grant`, original validated `Host`, and the manager-relative
  prefix `/database-manager/<token>/` in `X-Nakpanel-Manager-Path`.
- First request additionally carries `X-Nakpanel-Manager-Capability`. The adapter
  redeems it once with `POST /redeem` over the Unix socket and JSON
  `{"capability":"..."}`. Response fields: `grant`, `username`, `password`, `database`.
- `GET /__nakpanel_health` requires only the runtime key, returns `204` when PHP,
  application files, and the bridge socket exist. This is readiness, not a full
  database authentication test.
- MariaDB uses `/run/mysqld/mysqld.sock` and the selected existing restricted
  `@localhost` principal. Signon rejects global/role/proxy/other-schema privileges,
  grant option, and unescaped wildcard database grants. Existing unsafe grants
  must be explicitly reconciled before launch; this installer does not alter data
  or account grants.

The Go proxy must validate every panel session/grant request, keep its 15-minute
idle and 60-minute absolute limits, strip incoming internal headers and panel
cookies, rewrite phpMyAdmin cookies to the manager-only path, intercept logout,
and disable logging of manager paths. The adapter does not replace these checks.
Private per-grant PHP sessions prevent cross-tab credential mixing. Credentials
expire at one hour; tmpfiles removes inactive grant storage after two hours.

Maximum upload is 16 MiB (17 MiB total body); PHP execution is 60 seconds with
four workers and 128 MiB per process. Setup/examples are removed, remote server
selection and error reporting are disabled, and neither runtime service has
access to the panel database, encryption keys, tenant homes, or agent state.

## Verification And Rollback

Apply migrations `20260909000044` and `20260909000045` using the panel database
owner before deploying the new panel. If migrations run as a separate PostgreSQL
administrator, grant the panel role SELECT, INSERT, UPDATE and DELETE on
`database_create_requests` and `database_manager_grants`. Do not grant access to
other roles or expose the runtime listener.

```sh
php deploy/database-manager/adapter_test.php
go test ./deploy/multipass -run TestDatabaseManager -count=1
bash -n deploy/install/database-manager-install.sh
```

The non-destructive browser verifier requires a disposable-test-enabled site:

```sh
NAKPANEL_TEST_BASE_URL=https://<vm-ip>:7443 NAKPANEL_TEST_SITE_ID=<site-id> \
  node deploy/multipass/database-workspace-browser-smoke.cjs
```

It creates a uniquely named database, checks progress, idempotency, scoped
signon, SQL/import/export, logout and credential rotation. It writes the exact
fixture ID/name to `/tmp/nakpanel-database-smoke-result.json` for deliberate
cleanup; it never deletes existing databases. Set `PLAYWRIGHT_MODULE` when
Playwright is installed outside the default Node module path.

Local syntax and protocol tests do not prove the FPM/systemd/phpMyAdmin/MariaDB
integration. Before production enablement, verify real signon, cross-tenant SQL
denial, two tabs, import/export, expiry, logout and restart on the lab VM.

To disable, stop and disable `nakpanel-database-manager-http.service` and
`nakpanel-database-manager.service`, disable panel manager configuration, and
restart the panel. Preserve keys and private state for diagnosis; do not touch
existing customer databases. Back up `/etc/nakpanel-database-manager`, the panel
runtime drop-in, and the `current` symlink before an upgrade.

## Upstream References

- [Official 5.2.3 release](https://www.phpmyadmin.net/files/5.2.3/)
- [Pinned archive checksum](https://files.phpmyadmin.net/phpMyAdmin/5.2.3/phpMyAdmin-5.2.3-all-languages.tar.xz.sha256)
- [Signon configuration](https://docs.phpmyadmin.net/en/latest/config.html#cfg_Servers_SignonScript)
- [MariaDB wildcard grants](https://mariadb.com/kb/en/mariadb-maxscale-2208-authentication-modules/)
