# Provider DNS Templates

Open **Tools & Settings -> DNS**. The workspace has three sections:

- **Records:** typed template records and root/subdomain scopes.
- **SOA & Nameservers:** provider nameservers, SOA timing and transfer policy.
- **Apply & History:** an impact preview, explicit application and durable results.

Saving publishes an immutable template revision for future zones. It does not
rewrite existing records or registrar delegation. Provider defaults keep SOA's
primary hostname aligned with the configured primary nameserver. Two names on
the same IP are displayed as single-server DNS, not redundant service.

Existing zones change only after a fresh preview and typed confirmation.
Custom records, local overrides, system mail records and explicit template
record deletions are preserved. Custom MX, SPF and DKIM records are not replaced
by a generic template. Duplicate SPF policies are rejected. Zone resets are
separate destructive actions and intentionally clear local deletion history.

Deletion history is available for deletions made after migration 55; older
hard-deleted records cannot be reconstructed. Moving a subdomain between its
parent zone and a separate zone carries that history with the owning site.

Every desired DNS revision has its own queue identity. An accepted request is
not an applied zone: wait for BIND validation/reload and the applied revision.
Stale previews must be regenerated. Failed convergence retains the last working
configuration and reports an actionable result.

For a new domain, enable its authoritative DNS zone when using Nakpanel DNS.
An externally hosted DNS domain need not create a local zone. Set delegation
and any necessary glue at the registrar separately. The template does not
automatically publish mail, DKIM or IPv6 service records for unconfigured services.

## Automatic Service Defaults

The effective zone combines the provider template with service-owned records.
Enabled, converged FTPS accounts receive an `ftp` address; configured webmail
receives a `webmail` address. Nameserver address records are generated only in
the authoritative zone containing the nameserver hostname. For example,
`ns1.nakpanel.com` is an address in the `nakpanel.com` zone, not in every
customer zone. Registrar glue remains a separate registrar operation.

Local mail convergence generates mail/MX/SPF/DMARC and the domain's generated
DKIM public key. It updates only system-owned mail records. Custom records,
external mail routes, external DKIM selectors and unrelated verification TXT
records survive both template synchronization and mail convergence. A custom
answer suppresses the corresponding service default instead of producing a
second, conflicting route. Disabling local mail removes only its managed
records.

## Adopting Existing Records

Normal synchronization preserves custom ownership. Select **Adopt matching
records** when creating a preview to transfer exact matching defaults to
template or service management. The preview lists adoptions separately;
applying it requires typed confirmation. Record values and TTLs are unchanged.
Different addresses, TTL overrides, multi-address custom sets and custom mail
policies are not adopted. Once adopted, a record can receive future managed
updates. This is not a zone reset.

Previews are fenced by template revision, zone revision and the exact planned
record changes. Enabling a service after a preview invalidates the preview if
it changes the plan. Re-preview rather than applying unreviewed defaults.

The domain workspace shows synchronization state separately from its local
record count. **Up to date** can coexist with custom records; it does not prove
public DNS propagation or registrar delegation. **Update available** indicates
a newer provider template, and failed/pending agent changes remain explicit.
