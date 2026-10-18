# 30-60 Day Soak Installation

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

```bash
NAKPANEL_MULTIPASS_IMAGE=24.04 ./deploy/multipass/soak-verify.sh --init
# Start a separate run for the experimental native Resolute profile:
NAKPANEL_MULTIPASS_IMAGE=26.04 ./deploy/multipass/soak-verify.sh --init
```

This launches the VM (2 CPU / 3 GB / 32 GB), runs the one-command installer
(`deploy/install/install.sh --yes`), generates the backup archive key (stored
once in the run-specific directory printed by the initializer; move it
somewhere safe), and configures a scheduled local server backup. Initialization
first proves that the actual scheduler creates and verifies an archive, then
sets its daily schedule. A manually queued archive cannot satisfy this check.
Source the printed `run.env` before later sweeps so the run's release,
architecture, VM and ownership token remain explicit.

Optionally populate a tenant through the panel or the provisioning API so the
soak covers hosted workloads, then note the date: the window ends 30-60 days
later.

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
- the newest verified server backup is under 26 hours old;
- a freshly queued system reconciliation converges;
- fail2ban is active.

A sweep that finds issues exits non-zero and records them, so the cron log
doubles as the incident timeline.

## Weekly operations during the window

- **Upgrade in place** once a week from the current tree:
  `multipass exec nakpanel-soak -- sudo bash -c 'cd /tmp/nakpanel-src && git-less sync as in sync_repo, then deploy/install/install.sh --yes'`
  (or re-run `sync_repo` from the host first). Every upgrade exercises the
  pre-upgrade backup and the health gate.
- **Reboot once mid-soak**: `multipass restart nakpanel-soak`, then run the
  sweep and confirm it passes.

## Exit criteria

The soak passes when, over the full 30-60 day window:

1. zero unexplained service restarts or failed units;
2. zero River jobs stuck in `retryable`/`discarded` at sweep time;
3. disk growth is bounded (retention keeps backups pruned);
4. at least four in-place upgrades completed with no rollback;
5. the mid-soak reboot converged with a passing sweep;
6. a final disaster-recovery drill succeeds: take the newest archive plus the
   stored key, and run the Phase 29 DR procedure (fresh VM,
   `deploy/install/install.sh --fresh`, `panelctl restore-server`) - the same
   flow `phase29-verify.sh` automates.

Only after the final drill is the soak VM allowed to be deleted through a
deliberate ownership-checked cleanup. Starting a soak or passing one sweep does
not complete the 30–60 day evidence window.
