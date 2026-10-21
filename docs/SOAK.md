# 30-60 Day Soak Installation

The current server target is Ubuntu 26.04/resolute with hosting PHP 8.3/8.4/8.5
and internal PHP 8.5. Hosted AMD64 recovery and short scheduled-backup evidence
are recorded in the [transition plan](superpowers/plans/2026-10-18-ubuntu-26-04-support.md);
no 30–60 day elapsed-soak acceptance is claimed. Starting or scheduling a new
soak requires separate authorization. Existing Ubuntu 24.04 labs/soaks and
historical results remain protected without creating a continuing OS-support
requirement.

The soak run answers the question the fast reliability gate cannot: does a
production-shaped nakpanel installation stay healthy for weeks under real
timers, real certificate renewals, real scheduled backups, and repeated
in-place upgrades?

The harness is `deploy/multipass/soak-verify.sh`. Initialization creates a
dedicated uniquely owned run and records its identity in `run.env`. The
historical `nakpanel-soak` guest remains protected. Ordinary verification does
not sweep old guests; cleanup requires matching host and guest ownership plus
actual release/architecture. Preserve soak run identities separately and do
not supply them to disposable qualification cleanup.

## Starting the soak

Use the same signed, architecture-compatible release bundle and out-of-band
public key used for native qualification. Supply the exact application version.
The initializer rejects missing or invalid release inputs before any VM work;
it never falls back to a working-tree build or historical installer.

```bash
NAKPANEL_MULTIPASS_IMAGE=26.04 \
NAKPANEL_RELEASE_BUNDLE=/absolute/path/to/nakpanel-VERSION-linux-arm64 \
NAKPANEL_RELEASE_PUBLIC_KEY=/absolute/path/to/release-public.pem \
NAKPANEL_RELEASE_VERSION=VERSION \
./deploy/multipass/soak-verify.sh --init
```

Ubuntu 26.04 with the default Surý provider exercises hosting PHP 8.3/8.4/8.5.
Each advertised architecture requires its own matching signed bundle and guest.
Use `NAKPANEL_RELEASE_ALLOW_DEVELOPMENT=1` only for intentionally
signed development candidates. Their soak evidence cannot promote them to a
production release.

Initialization launches a uniquely owned VM (2 CPU / 3 GB / 32 GB by default)
and reuses `current-install-verify.sh`. That canonical verifier stages and
installs the exact signed bundle, supplies the fresh installer's administrator
password through a temporary root-only file, verifies that other public seed
logins are disabled, and creates a real tenant/site/database/DNS/TLS workload.
Its administrator is the isolated qualification fixture documented in that
verifier; keep the guest confined to the test environment. The existing
`NAKPANEL_QUALIFICATION_VM_CPUS`, `_MEMORY`, and `_DISK` overrides can increase
the resource budget.

The initializer records `run.env`, the initial signed release manifest and
public key in the run's private log directory. It generates the archive key
and saves only its encoded value in `backup-key.txt` with mode 0600, ready for
`--backup-key-file` during recovery. Move a copy to safe offline custody.
It first proves that the actual scheduler creates and verifies an archive,
then changes the schedule to daily at 02:00 in the guest's timezone. A manually
queued or unverified archive cannot satisfy this check.

Source the printed `run.env` before later operations so the run's release,
architecture, provider, source/DR names and ownership token remain explicit.
Additional representative tenants can be populated through the panel or API.
Record the successful initialization date: the evidence window ends 30–60 days
later. Creating the environment is not evidence of that elapsed window.

## The recurring sweep

Schedule the sweep every 6 hours on the host, for example with cron:

```
0 */6 * * * bash -c 'source /absolute/path/to/run.env; /path/to/nakpanel/deploy/multipass/soak-verify.sh' >> /absolute/path/to/soak/cron.log 2>&1
```

Each sweep is non-destructive and appends one line to
the run's `soak.log`. It checks:

- `/healthz` responds `ok` and reports the installed version;
- no failed systemd units;
- no retryable or discarded River jobs;
- root filesystem below 85%;
- the panel certificate is not within 7 days of expiry;
- the newest verified, scheduler-created server backup is under 26 hours old;
- a freshly queued system reconciliation converges;
- fail2ban is active.

A sweep that finds issues exits non-zero and records them, so the cron log
doubles as the incident timeline.

## Weekly operations during the window

Source the actual run identity, then verify it before each guest operation:

```bash
source /absolute/path/to/run.env
source ./deploy/multipass/common.sh
assert_vm_identity "$NAKPANEL_SOAK_VM" "$NAKPANEL_MULTIPASS_IMAGE" \
  "$NAKPANEL_MULTIPASS_ARCH" "$NAKPANEL_RUN_TOKEN"
```

Upgrade weekly to the next reviewed, signed candidate using the unified
installer's signed-bundle procedure in [README.md](../README.md). Verify the
new bundle on the host with `deploy/release/verify.py`, its trusted public key,
exact version and the run's architecture. Transfer the bundle and public key
to persistent private root-owned guest paths, preserving the authenticated
file inventory and trusted public key. Confirm that the staged files match
the host-verified signed inventory before executing any staged installer.
Invoke that authenticated next bundle's own installer:

```bash
multipass exec "$NAKPANEL_SOAK_VM" -- sudo \
  /root/next-release/deploy/install/install.sh --upgrade --yes \
  --bundle /root/next-release --release-public-key /root/next-release-public.pem
./deploy/multipass/soak-verify.sh
```

The installer seals and authenticates the new bundle before executing that
bundle's own installer and assets. For a development candidate, both the
explicit environment opt-in and `--allow-development-bundle` are required, as
in the signed-bundle instructions. Retain each new manifest and upgrade result
in the run's log directory. Do not re-run `--init` or the fresh-install verifier
against the populated endurance guest. Preserve the guest's PHP provider.
Every real upgrade exercises its pre-upgrade backup and health gate.

Reboot once mid-soak, after the same ownership assertion:

```bash
multipass restart "$NAKPANEL_SOAK_VM"
./deploy/multipass/soak-verify.sh
```

These are operator actions. The harness does not create host cron entries or
schedule Codex automation. Do not target the protected historical
`nakpanel-soak` name or pass the endurance identity to disposable phase-chain
cleanup.

## Exit criteria

The soak passes when, over the full 30-60 day window:

1. zero unexplained service restarts or failed units;
2. zero River jobs stuck in `retryable`/`discarded` at sweep time;
3. disk growth is bounded (retention keeps backups pruned);
4. at least four in-place upgrades completed with no rollback;
5. the mid-soak reboot converged with a passing sweep;
6. a final disaster-recovery drill succeeds: take the newest archive plus the
   stored key, and perform the documented same-profile recovery procedure in
   [RECOVERY.md](RECOVERY.md) on a fresh, separately owned VM using the same
   signed application bundle and explicit secure administrator bootstrap.
   Restore the archive with `panelctl restore-server --backup-key-file`, prove
   the populated workload and mail/SQLite canaries, then reboot and prove them
   again. `phase29-verify.sh` provides the automated reference for this flow;
   do not run its destructive drills against the endurance guest itself.

Only after the final drill is the soak VM allowed to be deleted through a
deliberate ownership-checked cleanup. Starting a soak or passing one sweep does
not complete the 30–60 day evidence window.
