# Mail hosting (Stalwart)

Nakpanel hosts tenant mailboxes on one multi-tenant [Stalwart](https://stalw.art)
instance per node (pinned to v0.11.8). The panel treats Stalwart exactly like
nginx and BIND: intent lives in PostgreSQL, the agent renders
`/etc/stalwart/config.toml` deterministically from that intent
(`configure_mail` op), writes it atomically, and restarts the service.

## How provisioning works

- **Domains** — enabling mail on a domain (`panelctl mail enable <domain>` or
  the subscription's Mail tab) inserts a `mail_domains` row. The
  `configure_mail` job then generates an RSA-2048 DKIM keypair (selector
  `nak1`, private key root-only under `/var/lib/nakpanel/dkim/<domain>/`),
  renders the Stalwart config, and reconciles `MX`, `SPF`, `DKIM`, and `DMARC`
  records in the selected primary BIND zone. External DNS receives publication
  requirements instead. Re-running is
  idempotent: the key is never regenerated and unchanged intent skips the
  service restart. (Stalwart normalizes and rewrites `config.toml` at boot,
  so the agent tracks the last rendered intent in
  `config.toml.nakpanel-intent` and compares against that.)
- **Mailboxes and aliases** — Stalwart's directory is the panel database
  itself. The agent config points Stalwart's SQL directory at the read-only
  `stalwart_accounts` / `stalwart_emails` / `stalwart_domains` views, so
  creating a mailbox is a single scoped `INSERT`; no Stalwart API calls, no
  reload. Passwords are stored as argon2id hashes which Stalwart verifies
  natively. Deleting the row removes the account from the directory
  immediately (directory cache TTL is 30 s).
- **Webmail** — `configure_webmail` renders Roundcube's `config.inc.php`
  against the local Stalwart IMAP (`tls://127.0.0.1:143`) and submission
  (`tls://127.0.0.1:587`) listeners, so `https://webmail.<domain>` logs in
  with the full mailbox address.
- **Routing** — inbound recipient domains are looked up live from
  `stalwart_domains` (an expression in `queue.outbound.next-hop`), so a
  disabled or deleted domain stops receiving mail as soon as the row changes.

## Subdomain DNS and readiness

Enable mail from an existing active subdomain's Mail tab. Parent and child
mail identities are separate; `hello@shop.example.test` and
`hello@example.test` do not share a mailbox automatically.

For `shop.example.test` using the `example.test` parent zone, the managed
records are scoped to the child:

| Host in parent zone | Type | Value |
| --- | --- | --- |
| `shop` | MX | `10 mail.shop.example.test` |
| `mail.shop` | A | The mail server's public IPv4 address |
| `shop` | TXT | `v=spf1 mx ~all` |
| `nak1._domainkey.shop` | TXT | The generated public DKIM record for this child |
| `_dmarc.shop` | TXT | `v=DMARC1; p=<selected policy>; rua=mailto:postmaster@shop.example.test` |

Custom/external MX, SPF and authentication records are preserved. Conflicting
custom routing receives a DNS action notice instead of another SPF or mixed
local/external MX records. CNAME conflicts and active service-hostname
collisions stop mail DNS changes and report the reason. A label such as `mail`
is allowed when it does not collide with an active endpoint.

An NS delegation at `shop` means the delegated provider controls that child;
Nakpanel does not publish ineffective mail records below that cut in the
parent zone. A separate local child zone uses apex hosts (`@`, `mail`,
`nak1._domainkey`, `_dmarc`) and needs matching parent/child NS sets. Nakpanel
reports a missing or different delegation and preserves the parent's records.
With external DNS, publish the requirements shown in the Mail page, including
the actual public DKIM key returned by the agent. The private key stays on the
server. Do not combine the local SPF example with a separate existing SPF
policy; explicitly choose or edit the routing policy first.

The Mail page distinguishes mail setup pending/failed, DNS pending/failed,
DNS action required and DNS applied locally. The latter requires the current
zone revision to be acknowledged; it does not verify public delegation,
propagation or external delivery. DNS record and mode edits queue a mail
readiness recheck. After resolving a reported conflict, that existing worker
refreshes the notice. Mail setup failure, malformed acknowledgements and missing
requested DKIM output remain failures.

## Plan limits

`plans.max_mailboxes` flows into the subscription's hosting policy and is
enforced in front of provisioning: the (limit+1)th mailbox returns
`quota exceeded`, the same fail-closed gate sites and databases use. The
per-mailbox storage quota comes from the plan policy (`mail.mailbox_quota_mb`)
and is enforced by Stalwart's account quota.

## Deliverability

- **Outbound rate limiting** — every domain is capped by
  `mail_settings.outbound_rate_limit` (default `200/1h`, rendered as a
  Stalwart outbound queue limiter keyed on the sender domain). Excess mail is
  deferred, not silently dropped. Note that the limiter counts every queued
  delivery for the sender domain, including local ones — size the limit
  accordingly for tenants with heavy internal mail.
- **Spike alerts** — a 15-minute sweep asks the agent for Stalwart's queue
  backlog per sender domain (loopback management API) and raises a deduped
  `mail_outbound_spike` warning notification once a domain's backlog reaches
  `mail_settings.queue_alert_threshold` (default 50). A compromised WordPress
  install shows up here instead of in a blocklist.
- **Smarthost** — `panelctl mail relay set --host smtp.provider.example
  --port 587 --username u --password p` routes all external outbound mail
  through a transactional relay instead of the shared host IP;
  `panelctl mail relay clear` restores direct delivery.

## Operator steps the panel cannot do for you

- **PTR / reverse DNS (required)** — set the reverse DNS of the node's public
  IP to the mail hostname (`panelctl mail settings` shows it; set it with
  `panelctl mail settings --hostname mail.example.com`) at your VPS or IP
  provider. Without a matching PTR record most large providers will junk or
  reject your mail regardless of SPF/DKIM/DMARC.
- Make sure your provider does not block outbound port 25, or configure a
  smarthost.

## Explicit follow-ups (not in v1)

- IP warmup, reputation monitoring, and feedback loops (operational
  discipline, not code).
- Forwarders to external addresses (aliases currently resolve only to
  mailboxes of the same subscription), catch-all policies, Sieve filters,
  per-user autoresponders, and JMAP client features.
- ACME certificates for the mail hostname (Stalwart currently serves the
  self-signed certificate generated at install; clients on the LAN/loopback —
  Roundcube — skip verification).
- Smarthost TLS certificate verification/pinning (v1 requires STARTTLS to the
  relay but accepts its certificate unverified, so private-CA relays work).
- Running Stalwart as a dedicated system user with `CAP_NET_BIND_SERVICE`
  instead of root.
