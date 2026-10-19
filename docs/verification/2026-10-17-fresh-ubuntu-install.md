# Fresh Ubuntu Installation Verification

## Starting Point

The operator rebuilt `2.29.45.217` with Ubuntu 24.04.3. The new SSH host
fingerprint was confirmed through the provider console before connecting.
No previous Nakpanel data, configuration, certificate, or backup was restored.
The source baseline was `5c1650c`.

## Installer Corrections

- Bootstrap the selected administrator before component installers start the
  public panel. Disable known migration-seeded logins before the CLI normalizes
  and enables the selected identity.
- Accept a root-owned `0600` password file by staging a private service-readable
  copy, removing that copy on exit. Regression tests cover success, failure,
  interruption, seed-lockdown order, and startup order.
- Check the actual APT candidate for kernel packages. Package metadata alone
  does not prove an obsolete kernel module package is installable.
- Stop with an explicit reboot requirement before changing quota mounts when
  the running kernel cannot load `quota_v2`.

The rebuilt image initially ran `6.8.0-90-generic`. Installing the current
generic kernel and rebooting into `6.8.0-147-generic` allowed the resumed fresh
installer to finish. User and group quotas are enabled on the root filesystem.
The root password had to be changed because the image required a first-login
password rotation. Credentials are retained outside the repository.

## Live Verification

Two core browser/protocol verification passes succeeded, including a final
reboot and recovery check:

- Trusted HTTPS on the panel's `:7443` listener and the hostname website.
- Administrator login, plan assignment and synchronization, subscription and
  website provisioning, authoritative DNS, and certificate issuance.
- PHP 8.4 execution as the subscription account, OPcache, HTTPS redirection,
  and hidden-file access denial.
- Database creation and scoped phpMyAdmin access.
- Trusted explicit FTPS, confined upload/download, and plaintext-login denial.
- Trusted SMTP submission, delivery to the local administrator mailbox, IMAPS
  retrieval, and Roundcube login.
- Desktop and 390px mobile page checks without horizontal document overflow.
- Core services recovered after reboot; disk quotas remained enabled.

Temporary database and FTPS test accounts were removed after verification.
The database engine checked ownership before physical removal. Only the new
hostname website/subscription and two system mailboxes remain; default plans
were retained. FTPS is disabled automatically when it has no configured accounts.
The original install-time mail job completed on its next retry after Stalwart
installation. No retryable or discarded jobs remained; history was not erased.

## Automated Checks And Scope

`go test -p 2 ./... -count=1`, `go vet ./...`, shell syntax checks, and
`git diff --check` passed for the installer changes. The live check was a fresh
VPS core-flow verification, not a claim that every historical phase verifier or
every optional application workflow was executed.

Provider reverse DNS still resolves to the provider's default hostname. Set
the PTR for `2.29.45.217` to `mail.nakpanel.com` in the provider console before
relying on external email deliverability. This run verified local delivery,
not receipt in an external inbox. Both authoritative nameservers currently
share this one server and therefore do not provide DNS redundancy.
