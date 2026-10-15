# Provider DNS Template Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. Native execution is the selected project preference; no implementation is authorized until this written plan is reviewed.

**Goal:** Provide understandable provider DNS defaults and safe, visible propagation without overwriting local records.

**Architecture:** Preserve the existing template manager, immutable revisions, preview tokens and BIND convergence jobs. Add provider-default intake and consolidated UI around those APIs. Existing domains change only through a reviewed apply operation.

**Tech Stack:** Go, templ, embedded JavaScript, PostgreSQL, River, BIND, Ubuntu 24.04.

**Spec:** docs/superpowers/specs/2026-10-15-dns-template-ux-design.md

## Global Constraints

- Never reset zones as an implementation shortcut.
- Preserve custom records, explicit deletions, system ACME/mail records and external MX.
- Default provider nameservers: ns1.nakpanel.com and ns2.nakpanel.com for this deployment only.
- Both names currently use one server; the UI must not claim redundancy.
- Published defaults affect new zones; existing zones require explicit preview/apply.
- No raw BIND directives, fabricated DKIM or automatic MX/delegation cutover.
- Preserve current public routes and no-JavaScript fallback.
- Prefer existing tables; any new migration requires a demonstrated missing invariant.

## Review Focus

- A changed custom record must remain unchanged even under apply-to-all.
- A deliberately deleted template record must not reappear without explicit reset.
- Parent-zone changes must not cross ownership into siblings.
- Stale preview and failed BIND reload must preserve last working configuration.
- A shared IP for two nameservers must be accurately described.

## File Structure

- internal/control/dnstemplate/provider_defaults.go: validated provider settings.
- internal/control/dnstemplate/{manager,jobs,validation}.go: current synchronization semantics.
- internal/control/http/dns_template.go: existing routes and progressive responses.
- internal/control/web/dns_template.templ: extract focused template UI from pages.templ.
- internal/control/web/static/dns-template.js: accessible tabs, previews and progress.
- deploy/multipass/global-dns-template-verify.sh: extend existing native gate.

### Task 1: Pin Preservation And Convergence Behavior

**Interfaces:** Keep Manager.Preview(ctx, actorID, scope, targetZoneID), ApplyPreview and RetryPreview. Expected/applied revisions remain distinct.

- [ ] Add TestApplyAllPreservesCustomMXTXTAndDKIM, TestLocalDeletionStaysDeleted, TestParentChangePreservesSibling, TestStalePreviewLeavesZone and TestReloadFailureKeepsAppliedRevision.
- [ ] Run go test ./internal/control/dnstemplate ./internal/agent/ops -count=1. Expected: reproduce any missing behavior before changing production code.
- [ ] Fix only verified gaps in provenance, mutation planning or BIND rollback. No broad changes to system-owned record generation.
- [ ] Run complete package/race tests. Expected: PASS, exact custom records preserved.
- [ ] Commit regressions and narrow fixes.

### Task 2: Explicit Provider Nameserver Defaults

**Interfaces:** Add SaveProviderDefaults(ctx, actorID, expectedRevision, ProviderDNSDefaults) (revisionID,error) and PreviewProviderDefaults; values become a normal immutable template revision.

- [ ] Write TestTwoProviderNameservers, TestSOAAgreesWithPrimary, TestSharedIPWarning, TestNoAutomaticExistingZoneChanges and TestServiceAwareMailDefaults.
- [ ] Run go test ./internal/control/dnstemplate -run ProviderDefaults -count=1. Expected: FAIL before implementation.
- [ ] Validate names, glue/address context and SOA. Preserve custom/external mail. Use domain-specific generated DKIM only through existing mail services.
- [ ] Test new-zone expansion, no IPv6 case and root/subdomain scopes. Expected: default record sets valid before publication.
- [ ] Commit defaults service.

### Task 3: Focused DNS Template UI

**Interfaces:** Existing settings/record/preview/apply URLs remain; add only the provider-default POST if existing settings cannot carry it safely.

- [ ] Write tests for Records, SOA & Nameservers, Apply & History; expanded examples; partial/stale results; CSRF and provider restrictions.
- [ ] Implement focused templ components with dialogs and preserved form input. Show add/update/remove/preserve/conflict totals before confirmation.
- [ ] Add bounded status refresh using authoritative applied revisions, not just an accepted queue response.
- [ ] Browser-test desktop/mobile and keyboard operation. Expected: no overflow, correct focus and visible failure recovery.
- [ ] Commit workspace changes.

### Task 4: Native And Controlled Live Rollout

- [ ] Run the full Go suite with disposable PostgreSQL, go vet, task build, JavaScript tests, diff and shell checks.
- [ ] Extend global-dns-template-verify.sh to query actual BIND for NS/SOA/A/AAAA and preserve custom MX/TXT during two revisions.
- [ ] Test validation/reload rollback, stale apply and sibling ownership on Ubuntu.
- [ ] Deploy code only first. Publish provider defaults for future zones through the panel. Preview existing production zones and record impacts; do not apply unexpected deletions, MX or delegation changes.
- [ ] Run two isolated live QA-zone passes. Verify custom records and source revisions before and after, document all results and retain production DNS unchanged unless its explicit preview is approved.
- [ ] Commit factual report and provide reviewed integration options.
