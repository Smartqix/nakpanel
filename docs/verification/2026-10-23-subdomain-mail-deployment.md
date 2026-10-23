# Subdomain mail deployment — 23 October 2026

## Result and authorization

**PASS.** The user authorized completion of main CI, documentation closeout and
deployment to nakpanel.com after PR #14 was merged. The application update
completed at `2026-10-23T04:51:00Z` (12:51 a.m. New York time). The focused live
mail checks, reviewed fixture removal and final health checks subsequently passed.

[PR #14](https://github.com/Smartqix/nakpanel/pull/14) is merged at
`3879f77f7a969ab2747d892d8f85751ffdd67da0`. Its feature branch was deleted locally
and remotely. Required [main CI 39897737049](https://github.com/Smartqix/nakpanel/actions/runs/39897737049)
passed unit/generated-code/full Go checks, both static architecture builds and
the hosted adversarial security/reliability gate before installation. The
successful PR CI remains separately attributed to head `10e53ce`, run
`39829100024`; the focused hosted mail acceptance remains attributed to
`e856cb1`, run `39815224111`. No optional hosted qualification was dispatched.

## Source and installation

The server's ED25519 key matched the provider fingerprint previously verified by
the user. A private per-task known-hosts file enforced that key; global SSH
trust and unrelated connections were not changed. Preflight confirmed Ubuntu
26.04.1 LTS / Resolute, AMD64 and the existing `ubuntu-26.04-sury` profile.

The deployed runtime is `29.0.0+3879f77f7a969ab2747d892d8f85751ffdd67da0`,
replacing `d992462`. An exact Git source archive was authenticated by SHA256
`9be8aacdf9dabb5774451e2795ceb76f6b0fc975893c23dbb8e7e69388e8482d`.
The native source build used pinned Go 1.26.9, `CGO_ENABLED=0`, Linux/AMD64 v1,
trimmed paths and the exact version/commit flags. All three binaries matched
the main CI artifact byte-for-byte:

| Binary | SHA256 |
| --- | --- |
| panel | `95d682a556938bdfef0b8fb002cd8ae0ff9729f7064ecd1dfa17ae5d8c0c83b5` |
| agent | `de346f9346a3f765882f94feb3f2b95e04fe2fdb69807b8fc3c8fe6ce571d1a4` |
| panelctl | `e771165a35fa531da5eb310e8b3b8384fdc9d30e6a0c7153536fe6b9082ed1f2` |

The qualification artifact's signature and complete inventory were checked for
comparison/provenance. Its ephemeral key was not installed as production trust
or promoted as a production release key. This was an authorized source-built
development deployment using the installation's existing build method.

There was no migration, installer, systemd or release-asset difference from the
previous installation. Only panel/agent/panelctl and version metadata were
replaced, with the panel and agent stopped during replacement. No OS/package
upgrade, database migration, restore or production reboot was performed.
Configuration and secret-key file digests remained unchanged.

Previous binaries, exact digests and version metadata are retained in the
root-only rollback directory:

```text
/root/nakpanel-deployment/subdomain-mail-3879f77/rollback
```

The deployment helper would restore those files and restart the original
services on a failed installation health gate. No rollback was needed or
deliberately exercised on this live server.

## Focused live verification

- Trusted panel HTTPS, hostname HTTPS, agent connectivity, nginx, BIND,
  PostgreSQL, MariaDB, Stalwart and fail2ban passed before and after the update.
- PHP 8.3.36, 8.4.27 and 8.5.12 remained available through active FPM services
  and CLI execution as the existing nonroot subscription account. The existing
  PHP 8.5 website also executed through FPM over trusted HTTPS. Provider/profile
  configuration and the internal PHP selection were preserved.
- An owned temporary child under nakpanel.com enabled its own mail domain.
  An actual Chrome browser session with normal TLS verification created its
  mailbox through the child's Mail dialog and returned to that same child.
  No browser page errors were recorded, and the verification session logged out.
- The owned alias was created through the normal authenticated application
  endpoint. SMTPS submission to that alias delivered to the child mailbox;
  SMTP STARTTLS authentication and IMAP retrieval passed using system TLS trust.
- Explicit child mail disable denied a fresh IMAP login. Re-enable restored
  access to the same message UID and exact message bytes.
- The normal preview/approval/permanent-removal flow removed only the owned
  temporary child and its mailbox, alias and DNS records. Original nakpanel.com
  and blog.nakpanel.com site intent, DNS records, website file hashes and the
  existing subscription policy matched their baseline exactly. No pre-existing
  mailboxes or aliases were present on this installation.
- Final checks found zero failed systemd services and zero retryable/discarded
  River jobs. All temporary test credentials were removed; the existing operator
  credential was preserved. Durable audit/removal history and rollback evidence
  remain available.

## Smoke-script correction and limits

The first live smoke attempt failed an incorrect harness assertion: it expected
`max_mail_aliases=0` to deny creation. The current application treats that unset
limit as inheriting the mailbox allowance, which was unlimited here. HTTP 303
and the owned alias row confirmed successful creation. The check was corrected
to use that exact existing alias and prove delivery; no plan, entitlement or
application code changed. The original failed assertion remains recorded in
the private evidence rather than being relabeled as a successful attempt.

This proves local delivery, not receipt in an external inbox. It does not add
mail-only subdomains, qualify ARM64 guests, prove a genuine PHP security-version
advance or establish an elapsed endurance result. Earlier failed hosted runs
retain their original results and source attribution.

The documentation closeout is limited to Markdown files and does not change
the deployed code or workflows. It does not require another unchanged hosted
test run; the deployed source remains bound to the passing main CI above.
