# Server installation

Nakpanel is in active development and is not yet a production-qualified release.
Read [platform qualification](PLATFORM_QUALIFICATION.md) before choosing a server.

## Platform contract

- **Ubuntu 26.04 LTS (Resolute)** is the only supported server OS.
- The default signed Resolute **Surý** provider supplies hosting PHP **8.3, 8.4
  and 8.5**, including required extensions and isolated FPM/CLI execution.
- Internal tools use validated PHP **8.5**. The native 8.5-only profile is an
  explicit diagnostic configuration, not the full hosting contract.
- Runtime discovery and readiness checks determine actual availability. Ubuntu
  24.04 and in-place Ubuntu release upgrades are unsupported.

Use a fresh, dedicated host for a new installation and keep its administrator
credential in a private, root-owned file with mode `0600`. Obtain the checkout
from a trusted source. From that checkout, supply both bootstrap options:

```bash
sudo deploy/install/install.sh --fresh --yes \
  --php-provider sury \
  --admin-email admin@example.com \
  --admin-password-file /root/nakpanel-admin-password
```

Replace the example address with the actual administrator. The file must already
contain the chosen password; it is not a shared installer default. The installer
creates the administrator before starting the panel, disables known test logins
and removes its temporary password copy. Do not use migration-seeded logins on a
public host. Source installations build the application; see the
[release guide](../deploy/release/README.md) for signed-bundle installation and
independently obtained verification keys.

The panel listens at `https://<server-address>:7443`. Tenant websites use nginx
ports `80` and `443`. Bootstrap panel TLS is self-signed; configure the trusted
panel-hostname certificate using [Recovery](RECOVERY.md) before relying on a
public hostname. The separate panel listener remains reachable when tenant
nginx configuration needs repair, provided the panel itself is healthy.

## Repository-owner development installations

Reuse the owner-approved credential in the operator workstation's private
`~/.config/nakpanel/admin-bootstrap-password`. The private installation record is
`~/.config/nakpanel/INSTALLATION.md`. Transfer it through verified SSH to the
server's `/root/nakpanel-admin-password`, owned by root with mode `0600`, and
supply the explicit bootstrap options above. Never place the password value in
source, a screenshot, an issue, a fixture or a public installation command.
See [AGENTS.md](../AGENTS.md) for the operator policy.

## Application updates and restore

The installer detects fresh installs and application upgrades using
`panelctl version` and `/etc/nakpanel/version`. Updates take a pre-upgrade backup
set and roll back when migrations or the post-upgrade health gate fail.
Downgrades are refused without `--allow-downgrade`.

An installed PHP provider is read from trusted platform metadata. Changing a
populated host's provider requires a separately reviewed migration; a mismatching
provider request is rejected. Development signatures do not establish production
release trust.

A current-format encrypted backup can rebuild a compatible fresh Ubuntu 26.04
host with the same architecture and PHP profile:

```bash
sudo deploy/install/install.sh --restore /path/to/archive.nkbk \
  --backup-key-file /path/to/key --yes
```

Read the complete [Recovery guide](RECOVERY.md) before an update or restore.
For settings and operator commands, see [Configuration](CONFIGURATION.md).
For release promotion and soak requirements, see [Verification](VERIFICATION.md)
and [Soak](SOAK.md).
