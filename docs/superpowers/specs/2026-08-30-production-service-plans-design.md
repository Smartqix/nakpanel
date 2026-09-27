# Production Service Plans Design

## Goal

Make a Nakpanel hosting plan a trustworthy provider contract: operators can sell only plans the server can deliver, every published change is immutable and reviewable, synchronized subscriptions receive an explicit revision, and existing customers are never silently deleted or downgraded when limits are reduced.

## Product Model

Hosting plans use three lifecycle states:

- `draft`: editable and unavailable for new subscriptions.
- `active`: validated against current server capabilities and available for assignment.
- `retired`: unavailable for new subscriptions while existing subscriptions retain their snapshots.

The existing `is_active` column remains a compatibility projection of `lifecycle_status = 'active'`. Existing active plans migrate to `active`; existing inactive plans migrate to `retired`. New plans start as `draft` unless the operator explicitly activates them.

Every successful create or update writes a complete immutable definition to `plan_revisions`, including a SHA-256 hash, actor, reason, and timestamp. A subscription continues to pin `plan_revision`; synchronized subscriptions move only after the new snapshot is valid. Locked and custom subscriptions are never rewritten by plan synchronization.

## Enforcement Contract

Each sellable property is classified in one registry:

- `hard_limit`: checked before resource creation, for example sites, databases, backups, workers, releases, and mailboxes.
- `measured_limit`: enforced from complete fresh usage, for example disk and traffic.
- `service_permission`: determines whether the server service may exist, for example hosting, DNS, mail, backups, FTPS, Valkey, and managed PHP.
- `management_permission`: determines which controls customers may change, for example PHP settings, SSH, and custom OCI images.
- `creation_default`: copied as desired configuration at object creation and then governed by inheritance/override rules.
- `stored_only`: retained for future compatibility but not presented as an enforceable sellable feature.

The registry is code-owned, test-covered, and rendered in the editor. A plan may activate only when all enabled capability-dependent services are available. PHP versions must be ready, finite disk quota requires quota support, managed PHP requires Composer, applications require healthy rootless Podman and subordinate IDs, and Valkey requires the installed capability contract. Unknown or unreachable capability state fails closed for activation but does not make existing retired/draft plans unreadable.

Mail storage and system-log storage are not represented as subscription disk usage until the agent can attribute them safely. The UI must state this limitation rather than label the current number as total account storage.

## Compliance

Subscriptions record `compliance_status` as `compliant`, `over_limit`, `capability_blocked`, or `unknown`, plus a sanitized explanation and evaluation timestamp.

Reducing a count or measured limit never deletes resources. Synchronization installs the new entitlement snapshot, marks an over-limit subscription noncompliant, and blocks additional creation through existing gates. Measured-limit suspension remains governed by the existing overuse policy and only occurs from a fresh, complete usage snapshot. Capability failures retain the last valid subscription snapshot and mark synchronization out of sync.

## Preview

The update-and-sync preview is a production change review, not a count dialog. It reports:

- structured old/new property changes;
- synced, locked, and custom subscription counts;
- subscriptions that would be over sites, databases, backups, mailboxes, disk, or traffic;
- provider and global committed-capacity impact;
- server capability blockers and warnings;
- whether activation/update is allowed.

Capability blockers prevent activation. Existing usage conflicts do not prevent a non-destructive update; they are shown as remediation work and become subscription compliance state after synchronization.

## Service Plan Workspace

The editor uses six operator-oriented sections:

1. Overview: lifecycle, provider, revision, subscriptions, readiness, and change reason.
2. Resources: count and measured limits with `Hard` or `Measured` labels.
3. Services: hosting, DNS, mail, TLS, backups, access, applications, and cache availability.
4. Customer Permissions: controls customers may manage without changing provider ceilings.
5. Defaults: PHP, web, mail, DNS, backup, and runtime creation defaults.
6. Advanced: stored presets and provider-only low-level limits.

The list shows Draft, Active, and Retired explicitly. Activation always opens the readiness/impact preview. Price remains a reference catalog value until billing exists and is labeled accordingly.

## Security And Compatibility

- Central provider scope, CSRF, audit, and cross-tenant `404` behavior remain authoritative.
- Browser values never supply observed usage, capabilities, resource ownership, or derived limits.
- `POST /plans`, `/plans/preview`, `/plans/status`, bulk status, cloning, add-ons, and non-JavaScript fallback remain compatible.
- The agent socket remains the only source for runtime capabilities.
- Plan definitions and revision metadata contain no credentials or secret values.
- Existing Phase 1-30 data migrates without losing access.

## Deployment Gate

Phase 31 verifies on the single `nakpanel-lab` Ubuntu 24.04 VM that a draft plan cannot be assigned, activation fails for an unavailable PHP runtime, a valid plan activates, revision history is immutable, sync preview identifies an over-limit subscription, synchronization marks it noncompliant without deleting resources, and increasing the limit restores compliance.
