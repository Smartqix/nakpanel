# Configuration reference

Important environment variables:

| Variable | Purpose |
| --- | --- |
| `NAKPANEL_DATABASE_URL` | PostgreSQL DSN for panel, migrations, and River tasks. |
| `NAKPANEL_TLS_DIR` | Directory for the panel bootstrap TLS certificate and key. Defaults to `/var/lib/nakpanel/tls`. |
| `NAKPANEL_AGENT_ALLOWED_UID` | Optional numeric UID allowed to connect to the agent socket. |
| `NAKPANEL_AGENT_SOCKET` | Agent socket used by `panelctl agent ping`. Defaults to `/run/nakpanel/agent.sock`. |
| `NAKPANEL_MARIADB_DSN` | Optional MariaDB connection string used by the agent database provisioner. |
| `NAKPANEL_ACME_DIRECTORY_URL` | ACME directory URL for certificate issuance. |
| `NAKPANEL_ACME_ACCOUNT_KEY` | Path to the ACME account key. |
| `NAKPANEL_ACME_EMAIL` | ACME account email. |
| `NAKPANEL_FTPS_PUBLIC_ADDRESS` | Public address advertised for FTPS passive data connections. |
| `NAKPANEL_FTPS_TLS_CERT` | Certificate path for the Nakpanel-managed TLS-only ProFTPD service. |
| `NAKPANEL_FTPS_TLS_KEY` | Private-key path for the Nakpanel-managed TLS-only ProFTPD service. |
| `NAKPANEL_VALKEY_IMAGE` | Optional official `docker.io/valkey/valkey` image pinned by SHA-256 digest. The Ubuntu installer resolves and pins `8.1-alpine` when omitted. |
| `NAKPANEL_PUBLIC_URL` | Canonical HTTPS panel origin used for five-minute customer SSO links. |
| `NAKPANEL_BILLING_WEBHOOK_URL` | Optional external billing webhook endpoint; HTTPS is required except for loopback tests. |
| `NAKPANEL_BILLING_WEBHOOK_SECRET` | HMAC-SHA256 webhook secret. Configure it only with the webhook URL. |
| `NAKPANEL_MULTIPASS_VM` | Multipass VM name for deployment verification. Defaults to `nakpanel-lab`. |
| `NAKPANEL_MULTIPASS_IMAGE` | Multipass image for deployment verification. Defaults to `26.04`; the default PHP provider is Surý with 8.3/8.4/8.5. |

The panel always listens on `:7443` using the configured TLS directory. It must
not bind tenant ports `80` or `443`; those stay reserved for nginx.

## Operator CLI

Install `bin/panelctl` as `/usr/local/bin/panelctl` on an Ubuntu host. Commands
use `NAKPANEL_DATABASE_URL`; only `agent ping` contacts the privileged socket.
The default audit label is `SUDO_USER` or the current OS username, and can be
overridden with `--actor`.

```bash
sudo -u nakpanel panelctl create-admin --email admin@example.test
sudo -u nakpanel panelctl user list
sudo -u nakpanel panelctl session list --user admin@example.test
sudo -u nakpanel panelctl site reconcile example.test
sudo -u nakpanel panelctl backup create example.test
sudo -u nakpanel panelctl reconcile --system
sudo -u nakpanel panelctl agent ping
sudo -u nakpanel panelctl api-key create --name billing --cidrs 203.0.113.0/24
sudo -u nakpanel panelctl api-key list
```

The API key command prints the full `npk_...` value exactly once. Nakpanel stores
only its prefix, per-key salt, and SHA-256 digest. External billing uses the
bearer-authenticated `/api/v1` provisioning API; cookie sessions and CSRF tokens
are intentionally not accepted on those routes. Provider-scoped plans are
discoverable through `/api/v1/plans?provider=admin` or a `reseller:{id}` provider.

Hosting-toolkit verification is split across
`deploy/multipass/phase21-verify.sh` through
`deploy/multipass/phase25-verify.sh`. `deployment-verify.sh` remains the canonical
clean deployment gate, with uniquely owned guests and explicitly skipped prior
phases for its individual checks. `deploy/multipass/phase34-verify.sh` checks
statistics/privacy and chains Phase 33 unless `NAKPANEL_SKIP_PRIOR_PHASES=1`
is set by the canonical runner. The canonical sequence finishes with
`deploy/multipass/domain-removal-verify.sh` after Phase 34. Use `deploy/multipass/phase30-verify.sh` directly
for PHP compatibility or `deploy/multipass/phase32-verify.sh` for the Toolkit
feature gate without the uninstall acceptance cases.

Destructive commands require an interactive confirmation or `--yes`. Custom
site certificates can be queued without placing key material in River:

```bash
sudo -u nakpanel panelctl ssl set-custom example.test \
  --cert /secure/example.crt \
  --key /secure/example.key \
  --chain /secure/intermediate.crt
```

The chain must verify to the host system trust store. Arbitrary private roots,
self-signed leaves, encrypted keys, mismatched keys, and wrong-domain or
out-of-date certificates are rejected.

Useful recovery and operations notes live in:

- [Recovery](RECOVERY.md)
- [Implementation plan](../IMPLEMENTATION_PLAN.md)
- [Deployment verifier](../deploy/multipass/deployment-verify.sh)
