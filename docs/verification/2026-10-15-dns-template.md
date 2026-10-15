# DNS Template Verification

The provider DNS workspace was tested at desktop and 390px mobile widths, then
against two new authoritative QA zones on nakpanel.com. No existing production
zone was selected for application.

The two live passes verified:

- Provider nameservers and SOA agreed with ns1.nakpanel.com / ns2.nakpanel.com.
- Authoritative A, NS and SOA answers came from the applied BIND configuration.
- A same-IP nameserver pair was labelled single-server, not redundant DNS.
- Custom MX, SPF and TXT records survived template updates unchanged.
- Explicitly deleted template records stayed absent after synchronization.
- Stale previews returned a conflict and required a new preview.
- Each desired revision had its own River identity, including rapid updates
  during an already-running job.
- The temporary QA template record was removed and its removal converged.
- Original zone record fingerprints remained unchanged.

QA zones:

- dns-one-20261015.2-29-45-217.sslip.io (site 56, zone 14)
- dns-two-20261015.2-29-45-217.sslip.io (site 57, zone 16)

Saving the global template intentionally marks older existing zones as needing
review. It does not apply that revision to them. Registrar delegation, glue and
production MX were not changed. No IPv6 records were generated without a
configured IPv6 address.

After the review fix for fallback tombstones, both isolated zone passes were
repeated against build `3bd9d67`. Custom-record fingerprints remained identical,
the deleted `www` record stayed absent, stale apply returned a conflict, and
NS/SOA/A answers remained correct. Original production-zone fingerprints were
again unchanged.
