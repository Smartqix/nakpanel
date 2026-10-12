# Local SMTP, Mail TLS and FTPS

Nakpanel can submit notifications through its own Stalwart server. SMTP relay
configuration in Tools & Settings is optional; leave it blank for direct delivery.
The panel's notification sender is configured separately in the root-owned,
`0600` `/etc/nakpanel/panel.env` systemd environment file:

```ini
NAKPANEL_SMTP_HOST=mail.example.com
NAKPANEL_SMTP_PORT=587
NAKPANEL_SMTP_TLS_MODE=starttls
NAKPANEL_SMTP_USERNAME=notifications@example.com
NAKPANEL_SMTP_PASSWORD=<dedicated-mailbox-password>
NAKPANEL_SMTP_FROM=notifications@example.com
```

Enable mail in the hosting plan and synchronize the subscription before creating
the mail domain and notification mailbox. Do not use the panel administrator
password or Stalwart management credential for SMTP. Recipient mailboxes and
mail aliases remain subscription-scoped. Panel SMTP acceptance is not proof of
delivery: check Stalwart's remote delivery response and the recipient inbox.

## Trusted Service Certificates

Publish the mail and FTPS hostnames before requesting certificates. Use a
root-managed HTTP-01 webroot on port 80, outside tenant-writable directories.
Install these helpers and timer units from the repository:

```sh
install -m 0755 deploy/install/sync-service-certificates.sh /usr/local/libexec/nakpanel/sync-service-certificates
install -m 0755 deploy/install/import-service-certificate.sh /usr/local/libexec/nakpanel/import-service-certificate
install -m 0644 deploy/systemd/nakpanel-service-cert@.* /etc/systemd/system/
systemctl daemon-reload
```

For a Certbot lineage, configure this deployment hook (replace the example name
and lineage with the actual values):

```sh
/usr/local/libexec/nakpanel/import-service-certificate mail.example.com /etc/letsencrypt/live/nakpanel-services
systemctl enable --now nakpanel-service-cert@mail.example.com.timer
```

The import verifies hostname coverage, trust, expiry and matching keys before
updating the root-owned source under `/var/lib/nakpanel/certs/<hostname>`.
Synchronization installs private copies in `/etc/stalwart/tls` and
`/etc/nakpanel/service-tls/<hostname>`. It probes the served IMAPS, submission and
active FTPS certificates, and restores previous files when activation fails.
Certbot renews its lineage; the deployment hook imports renewals and the timer
checks consumer convergence. The panel's existing hostname certificate timer is
independent. Validate renewal with `certbot renew --dry-run`.

## Hosting Access

Configure `/etc/nakpanel/agent.env` with:

```ini
NAKPANEL_FTPS_PUBLIC_ADDRESS=<server-public-IP>
NAKPANEL_FTPS_TLS_CERT=/etc/nakpanel/service-tls/mail.example.com/fullchain.pem
NAKPANEL_FTPS_TLS_KEY=/etc/nakpanel/service-tls/mail.example.com/privkey.pem
NAKPANEL_MAIL_TLS_HOSTNAME=mail.example.com
NAKPANEL_WEBMAIL_TLS_HOSTNAME=webmail.example.com
NAKPANEL_WEBMAIL_TLS_CERT=/etc/letsencrypt/live/nakpanel-webmail/fullchain.pem
NAKPANEL_WEBMAIL_TLS_KEY=/etc/letsencrypt/live/nakpanel-webmail/privkey.pem
```

The mail TLS hostname enables system-trust and hostname verification for
Roundcube's loopback IMAP/SMTP connections. Without it, the development bootstrap
configuration still accepts the local self-signed certificate.
The optional webmail TLS settings apply to that exact webmail hostname: the
agent validates its certificate chain/key/domain before generating HTTPS and an
HTTP redirect. Other hosted webmail hostnames retain their existing behavior.
Obtain this separate certificate with Certbot's nginx authenticator and a
validated nginx reload deployment hook; test its renewal as well. Include
`/etc/letsencrypt` in operator recovery backups.

FTPS requires its plan permission, `ftps_enabled`, and an account allowance.
Create a primary subscription account or domain-scoped account through the
Access workspace. Use **explicit TLS on port 21**, including encrypted data
connections, and passive ports **49152–49252**. Plain FTP and anonymous access are
not supported. Generated active FTPS services are enabled at boot; disabling the
last account removes the service and boot link.

## Reboot Verification

Before reboot, verify a fresh PostgreSQL/MariaDB, configuration, certificate,
hosting-file and stopped-Stalwart data backup. Wait for mutation jobs to drain,
check nginx configuration, quota mount flags, SSH firewall access, enabled
services and renewal timers. After reboot, confirm the boot ID changed, all
required units recovered, the failed-unit list is empty, TLS is trusted, and
database/hosting intent remains intact. Exercise SMTP/IMAP authentication,
notification delivery, FTPS upload/download and confinement, PHP, databases,
backup/restore and ownership denial again.

For direct Internet mail, configure matching forward/reverse DNS at the server
provider, plus MX, SPF, DKIM and DMARC. Delivery to one mailbox does not establish
reputation or guarantee acceptance by every recipient provider.
