# Phase 32 WordPress Toolkit Design

## Product Boundary

Phase 32 turns the WordPress 7.1 compatibility proven by Phase 30 into an
operational, domain-scoped toolkit. It supports Classic PHP sites only. Managed
PHP releases remain immutable and therefore cannot host a self-updating
WordPress installation.

The toolkit provides installation, discovery, inventory, safe updates,
checksum verification, maintenance mode, administrator password reset,
security hardening, operation history, and periodic inventory
reconciliation. It does not add a marketplace, paid plugin licensing,
multisite network administration, cloning/staging, automatic update policy,
arbitrary WP-CLI input, or browser-supplied shell commands.

## Entitlement Model

Hosting policy schema version 4 adds `permissions.wordpress_toolkit` and
`resources.max_wordpress_sites`. Zero disables new toolkit attachments, `-1`
is unlimited, and positive values are enforced per subscription. Existing
subscriptions retain WordPress hosting compatibility but receive no toolkit
management permission until their plan is updated and synchronized.

The effective subscription snapshot remains authoritative. A provider or
add-on may grant the permission and increase the count. Runtime plan readiness
requires healthy WP-CLI and a ready allowed PHP runtime whenever the toolkit is
enabled.

## Data Model

`wordpress_instances` has one optional row per site and stores the selected
database, desired update policy, installed version, inventory snapshots,
checksum/security state, convergence state, and scan timestamps. No password
or database credential is stored on the row.

`wordpress_operations` records install, discover, refresh, update, verify,
harden, maintenance, password-reset, and detach requests. River arguments carry
only the operation ID, instance ID, and desired revision. Secret values use the
existing encrypted `service_secrets` keyring, are decrypted only inside the
worker immediately before the protected Unix-socket RPC, and are deleted in the
same transaction that completes a successful install or password reset.

Operation output is bounded and sanitized. Updates record a required Nakpanel
backup ID. An update worker waits for that backup to become active before it
contacts the agent; failed or missing backups prevent mutation.

## Control Plane

`internal/control/wordpress` owns validation, authorization, durable state,
River jobs, secret handling, and periodic sweeps. It reuses the central
`CanManageDomain` site ownership decision, quota-aware database and backup
managers, and encrypted secret store.

Installation first creates a durable pending instance, provisions a generated
MariaDB database through the normal quota gate, attaches the database, stores
the write-only WordPress administrator credential, and queues the install. The
worker retries while database provisioning is pending and fails closed if the
database fails.

Every mutating operation is revision fenced and idempotent. A six-hour sweep
queues refreshes for stale healthy instances and runs once at panel startup.
Dependency polling snoozes without consuming the operation retry budget.
Suspended sites or inherited account suspension block mutations.

## Agent

The privileged agent receives only validated structured WordPress requests.
It re-derives `/home/<subscription-user>/domains/<domain>/public_html`, verifies
the system user and Classic PHP runtime, and invokes the fixed
`/usr/local/bin/wp` executable without a shell.

Install accepts an empty document root or the exact generated Nakpanel
placeholder for that domain, and refuses all other non-WordPress content. It downloads the
selected fixed official WordPress ZIP, verifies the downloaded version and
core checksums, writes `wp-config.php` atomically with mode `0600`, and sends
the administrator password to WP-CLI through protected standard input. The
complete installation is bootstrapped and granted nginx access in staging
before an atomic document-root activation. Password reset supplies the new
password to WP-CLI through protected standard input. Administrator passwords
never enter process arguments, River arguments, files, logs, audit metadata, or
responses. The generated database credential exists only in the encrypted
secret store during provisioning and the account-owned `0600` `wp-config.php`
required by WordPress.

Inspection uses bounded JSON from fixed WP-CLI commands. Updates accept only
typed targets (`core`, `plugin`, `theme`, `all`) and validated slugs. Security
hardening applies a fixed Nakpanel profile: checksum verification, safe file
permissions, and disabled dashboard file editing. Installation generates fresh
cryptographic salts; routine hardening does not rotate them or invalidate active
sessions. The agent
never accepts arbitrary WP-CLI subcommands.

## UI And Routes

`/sites/{id}/wordpress` uses the existing domain shell and exposes Overview,
Plugins, Themes, Security, Updates, and Activity tabs. It shows an honest
not-installed state with Install and Discover actions, or inventory, update
availability, checksum/security state, backup fencing, and operation history.

POST routes are CSRF protected and preserve support-view redirects:

- `/sites/{id}/wordpress/install`
- `/sites/{id}/wordpress/operations` for allowlisted discover, refresh, update,
  verify, harden, maintenance, password-reset, and failed-install retry actions
- `/sites/{id}/wordpress/detach`

Cross-tenant access returns `404`. Secret fields are never repopulated.
Confirmed detach removes only Nakpanel tracking and never deletes site files or
the database.

## Failure And Recovery

No update runs without a completed backup. Agent errors leave WordPress files
intact where possible, mark the operation failed, create a deduplicated panel
notification, and retain the backup for operator recovery. Periodic refreshes
repair stale inventory and never perform an update automatically. Update
policy automation, cloning, and staging are later work.

The Ubuntu verifier installs a real WordPress 7.1 site through the toolkit,
verifies checksums and inventory, exercises maintenance and password reset,
performs a backup-fenced update check, proves client isolation, and verifies
that secrets are absent from River arguments, HTML, audit rows, and logs.
