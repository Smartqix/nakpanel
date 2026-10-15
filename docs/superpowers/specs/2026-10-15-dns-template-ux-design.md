# Provider DNS Template Improvements

Status: proposed for review; not implemented or applied to live zones.

## Intent

Make provider DNS defaults simple to understand and safe to propagate.
Preserve the existing revisioned template engine, ownership checks, BIND
validation, preview tokens, per-zone outcomes, and custom/system record
protection. This is not a rewrite or an automatic zone reset.

## Live Findings

The active template is revision 1 with four records: apex A, www A, one NS
pointing at ns1.<domain>, and its local A record. SOA uses ns1.<domain>.
The public operator nameservers are ns1.nakpanel.com and ns2.nakpanel.com.
Both resolve to the same server; display a single-server resilience warning,
not a false claim of redundant DNS.

## UI

Use three compact tabs under Tools & Settings -> DNS:

1. Records: name, type, target, TTL, scope, and whether a record is a template
   or system-managed value. Add/edit dialogs show an expanded example.
2. SOA & Nameservers: primary/secondary nameservers, responsible mailbox,
   TTL/refresh/retry/expiry, transfer restrictions, and subdomain policy.
3. Apply & History: preview selected/unmodified/all eligible zones, then
   review additions, changes, removals, preserved overrides, skips and
   conflicts. Show durable progress and per-zone retry results.

Saving a template changes future defaults only. An explicit apply action is
required for existing zones. Each zone links to its own preview/apply flow.
Changing tabs preserves unsaved input. Controls have labels, validation,
keyboard access and mobile-safe sizing.

## Provider Defaults

Offer explicit provider nameserver settings using ns1.nakpanel.com and
ns2.nakpanel.com for this installation. NS and SOA targets must agree with
configured delegation and authoritative service. Do not silently replace
existing zone NS, DS, CAA or mail routing.

Keep root and www address records and the current parent-zone subdomain
default. Show supported placeholders and resolved IPv4/IPv6 examples. Omit
AAAA defaults when no usable IPv6 address exists. Validate record conflicts,
CNAME exclusivity, nameserver addresses and SOA values before publishing.

Mail records are service-aware: custom/external MX and SPF remain untouched,
and DKIM values come only from each mail domain's actual generated key.
Do not publish generic DKIM, duplicate SPF policies, or a local MX for an
external-mail domain. Autodiscovery records require their real service.

## Apply Semantics

- Keep the existing immutable revision and stale-preview protection.
- Preserve custom records and locally modified template records under both
  scopes, including explicit local deletions.
- Preserve system-managed ACME/mail/service records.
- Skip disabled/external/secondary zones unless their supported operation
  explicitly permits template changes; describe the reason.
- Update only unchanged template-owned records with proven provenance.
- Validate BIND candidates before reload and keep last valid configuration
  on failure. Report desired and applied revisions separately.
- Never report a database update as successful authoritative convergence.
- A failed or stale preview must be regenerated; do not replay old intent.
- Reset-to-default is a separate destructive operation with an exact impact
  preview and explicit confirmation, never the recommended normal update.

## Data And Compatibility

Reuse dns_template_revisions, dns_template_records, dns_template_sync_runs and
dns_template_sync_items. Add schema only for a demonstrated missing invariant.
Retain existing routes and non-JavaScript forms. Do not expose raw BIND
directives. Existing provider scope, CSRF and audit controls remain mandatory.

## Acceptance Gates

- New domains receive the published defaults and no unsupported service records.
- Preview/apply preserves custom MX/TXT, DKIM, verification records and deletions.
- Parent-zone subdomain changes never alter siblings.
- Stale revisions, duplicate records, conflicting CNAME, invalid nameservers,
  failed BIND validation/reload and partial jobs remain actionable and safe.
- Actual authoritative queries match applied A/AAAA/NS/SOA/MX/TXT values.
- Desktop/mobile dialogs, preserved form input, progress and retry.
- Two live passes use isolated QA zones. Existing nakpanel.com DNS changes
  require a separately reviewed impact; no automatic MX/delegation cutover.

## Reference

https://docs.plesk.com/en-US/obsidian/administrator-guide/dns/dns-settings.72226/
