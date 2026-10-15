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
