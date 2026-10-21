# PHP security update operations

The accountable owner is **Nakpanel project maintainers**, contacted through
[the project on GitHub](https://github.com/Smartqix/nakpanel/issues). The owner
was selected by the project operator on 19 October 2026. Use an issue to track
published package advisories, affected versions, qualification evidence, rollout
and recovery status. This policy concerns update operations; it does not create
an upstream service agreement or a new vulnerability-disclosure channel.

## Review and response

Maintainers review [PHP releases](https://www.php.net/releases/),
[PHP supported versions](https://www.php.net/supported-versions.php),
[Ubuntu Security Notices](https://ubuntu.com/security/notices) and
[the official Surý project](https://deb.sury.org/) daily. Confirm availability in
the authenticated repository for the actual Ubuntu suite and architecture;
a release announcement alone does not establish installable packages. Check
upstream support dates at each review rather than freezing them in this file.

The internal response targets are:

| Event | Maintainer action |
| --- | --- |
| Published critical or actively exploited issue affecting the installation | Acknowledge within 24 hours; assess exposure and record mitigation or a tested rollout decision within 48 hours. |
| Other high severity issue | Assess within two working days; target qualified delivery within seven days after compatible signed packages become available. |
| Other security update | Assess within seven days; target qualified delivery within 30 days after compatible signed packages become available. |
| No compatible signed fix, failed qualification, or target cannot be met | Record the reason, temporary exposure reduction, next review time and named maintainer responsible; escalate to project maintainers before the target expires. |

These are project operating targets. Surý's public supply does not provide a
Nakpanel response guarantee. An urgent advisory can require disabling an affected
feature or restricting access while a compatible signed fix is unavailable.
A missed target must remain visible in the tracking issue.

## Package and platform boundaries

Ubuntu 26.04 is the sole server OS. Its default Surý profile requires hosting
PHP 8.3/8.4/8.5; native PHP 8.5-only is a diagnostic configuration. Never install Noble packages on
Resolute, add an unrelated repository to obtain a missing version, switch an
installed provider implicitly, or broaden PHP-only repository preferences.
A PHP patch operation must not become an unreviewed operating-system upgrade.

Surý profile enrollment requires internal PHP 8.5 as well as its declared tenant
runtimes. Removing that provider would remove an in-use internal dependency.
The supported maintenance operation must reject provider removal or switching;
migrate to a separately qualified fresh server instead. Nakpanel's private PHP
package removal hook additionally checks conservative current, desired and
retained runtime references. Direct root APT/dpkg changes outside the supported
maintenance operation are outside that guard; Nakpanel cannot constrain an
administrator who replaces its files or bypasses its tools.

## Required delivery and recovery evidence

1. Record the actual installed package versions, trusted profile, OS/suite,
   architecture, active runtime descriptors, PHP configuration and installed
   application digests. Pause tenant mutations for the maintenance transaction.
2. Authenticate the provider's InRelease/Release metadata, package indexes and
   exact package hashes. Retain the original signed metadata and exact currently
   installed PHP packages before the provider retires them. Keep a private
   inventory of size and SHA256, with the rollback packages and configuration.
3. Resolve and simulate the complete proposed transaction. Accept only the
   reviewed PHP package families from the expected origin/suite; reject package
   removal, provider changes and unrelated global dependency replacements.
4. Take and verify a restorable server backup and a separate cold retention
   checkpoint for a disposable rehearsal. Retain the recovery key privately.
   Application-binary rollback does not reverse an APT/dpkg transaction.
5. Rehearse the real signed package update on an owned disposable installation
   for each advertised architecture. Require PHP CLI/extensions, configuration
   validation, nonroot FastCGI, Composer/WP-CLI/workers, tenant isolation,
   Roundcube login/send/read and database-manager checks, then reboot and repeat
   the affected checks. Preserve package versions and original configuration.
6. Rehearse an interrupted/failed PHP package transaction separately. Record
   the actual failure, restore the captured configuration and authenticated
   package set, complete dpkg recovery and repeat the same service/data checks
   after another reboot. Retain failure evidence and the intact checkpoint.
7. Publish the reviewed package versions and evidence in the tracking issue
   before a staged maintenance window. A maintainer records the rollout decision,
   recovery owner and abort conditions. Do not enable unattended provider updates
   or production package publication as a side effect of qualification.

The owned configuration-failure rehearsal finishes the exact half-configured
FPM package with a configuration-only APT transaction after removing its fault.
It verifies the original package inventory and signed installed postinst, rejects
unpacking or configuring other packages, and keeps downloads/removals forbidden.
Before postinst runs, it retains the affected FPM unit's state and clears only
that unit's start counter consumed by the deliberate failure, following the
documented [systemctl behavior](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
Reboot acceptance observes existing application services without starting,
restarting or resetting them to repair their state; recovery actions cannot be
used to claim boot persistence. Separate transient smoke probes remain required.

A same-version download/reinstall and interrupted-transaction recovery drill is
useful delivery evidence. It must be labelled as such; it cannot establish a
security version advance or rollback between two different signed versions.
If the provider publishes only one authenticated version per minor, retain the
baseline and leave that advance pending until a real successor exists. Never
invent package versions or use a different suite/provider to manufacture a pair.

## Promotion status

The explicit Surý Ubuntu 26.04 profile remains experimental until its full native
profile/architecture matrix, genuine security patch and failure recovery evidence,
and required elapsed soak have been accepted.
A development signing key, a passing local test or the presence of this policy
does not authorize production promotion. Private fallback package publication
continues to require the separate qualified inventory and supplied managed key.
