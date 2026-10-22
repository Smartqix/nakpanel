# Ubuntu 26.04 qualification

Ubuntu 26.04 LTS/resolute is the only supported server OS. The product contract
uses the signed Surý provider with hosting PHP 8.3/8.4/8.5 and internal PHP 8.5.
The explicit native 8.5-only configuration is diagnostic, not full product
acceptance. Code/default/workflow alignment is implemented in
[PR #13](https://github.com/Smartqix/nakpanel/pull/13). Hosted AMD64 operational recovery,
all 16 current-version gates and same-version PHP maintenance passed in
[run 39652821843](https://github.com/Smartqix/nakpanel/actions/runs/39652821843)
on runtime `63c00f6`. The focused scheduled local-backup/restore and reboot slice
passed in [run 39676085171](https://github.com/Smartqix/nakpanel/actions/runs/39676085171)
on runtime `0654aa3`. The later `1140165` verifier diagnostics fix is locally
verified and changes no served runtime.

Ubuntu 26.04 remains experimental pending remaining release qualification.
PR #13 required CI passed in
[run 39696504919](https://github.com/Smartqix/nakpanel/actions/runs/39696504919).
ARM64 qualification, genuine PHP security-version advancement and elapsed-soak
evidence remain separate. Current authorization is repository consolidation into
main and deletion of merged branches. The combined Backup Manager and Ubuntu
result has its own verification requirement; see the
[consolidation record](verification/2026-10-21-main-consolidation.md).
Do not deploy or dispatch optional hosted qualification.

## Guest and runner requirements

Qualify `26.04/amd64` and `26.04/arm64` independently on native hosts. A static
cross-build or a runner label alone cannot establish guest architecture support.
The guest needs booted systemd, ext4 backing `/home`, and cgroup v2 CPU, memory
and PID controllers. Preflight reports actual filesystem space/inodes and
writability before package or application mutation.

Use dedicated trusted self-hosted runners labelled `self-hosted`, `multipass`,
`nakpanel-qualification` and the actual `amd64` or `arm64` architecture. Provide
Multipass daemon access, GNU Bash 5+, Python 3, OpenSSL, curl, dig, jq, tar, Make,
Git and the verifier's browser dependencies. `actions/setup-go` selects the
pinned toolchain from `deploy/release/GO_VERSION`. macOS Bash 3.2 is rejected
before guest operations. Existing lab/soak VMs must remain untouched.

Unique run tokens, verified host/guest identities, distinct source/DR names and
host ownership records are mandatory. Cleanup enumerates only the current
run's records. A VM name prefix alone does not establish ownership. Observe the
configured runner-capacity preflight and bounded per-architecture concurrency.
No historical-upgrade guest is required.

## Signed current artifacts

Pre-stage the current architecture-compatible application bundle, its
independently obtained public verification key and exact version. No prior
binary or prior-OS image is required. Configure
`NAKPANEL_QUALIFICATION_ARTIFACTS` (or the matching manual workflow input):

```json
{
  "amd64": {
    "current": {
      "bundle": "/srv/nakpanel/releases/current-amd64",
      "public_key": "/srv/nakpanel/trust/current-public.pem",
      "version": "29.0.0"
    }
  },
  "arm64": {
    "current": {
      "bundle": "/srv/nakpanel/releases/current-arm64",
      "public_key": "/srv/nakpanel/trust/current-public.pem",
      "version": "29.0.0"
    }
  }
}
```

Replace example paths/versions with actual pre-staged inputs. Signature,
manifest, architecture/CPU policy and the complete executable inventory are
checked before guest work. Production signing secrets are not required on the
qualification runner. Explicit development artifacts remain nonpromotable.

Selected release/trust anchors and frozen harness sources remain under the
root-owned `/var/lib/nakpanel-qualification/<run-token>/` tree across reboot.
Transfer archives are digest/size-bound, parsed safely and staged privately;
changed guest-writable transfers cannot provide privileged verifier code.
Missing signed assets cannot trigger an unsigned working-tree fallback.
Only explicit nonsecret run configuration is retained in `run.env`.

Use the official Resolute image with exact SHA256 and signed Ubuntu image sums.
Configured local cloud images must remain immutable during the run. Assert the
actual installed guest OS/architecture after launch even for a hash-pinned image.
A CI host labelled `ubuntu-24.04` may build artifacts or host a verified 26.04 VM;
it does not create Ubuntu 24.04 server support.

## Current-version gates and acceptance

The canonical `ubuntu-platform-verify.sh` runs exactly 16 gates:
`bundle`, `fresh-install`, `inventory`, `phase28`, `valkey-platform`, `security`,
`phase29`, `phase30`, `phase31`, `phase32`, `internal-tools`, `mail-workspace`,
`phase33`, `phase34`, `domain-removal`, `release-artifacts`.

Reports record `qualification_scope: CURRENT_VERSION_ONLY` and
`excluded_gates: [real-upgrade]`; excluded history is not a passing gate. Fresh
installation, current-version application update/failure recovery, all hosting
PHP runtimes, tenant/resource boundaries, quotas, mail/webmail, DNS/TLS,
SQL/files, WordPress/workers, containers/Valkey, reboot and fresh 26.04 recovery
remain required. Request the optional database-manager browser coverage when
qualifying that feature; PHP maintenance requires it.

The summary requires both advertised architecture cells, complete evidence and
the full Resolute multi-PHP contract. Every failure stays a failure; retain
useful diagnostics before owned cleanup. Missing/skipped gates cannot promote.
The accepted AMD64 maintenance and local scheduled-backup results retain the
source bindings above. Genuine security-version advancement, ARM64 acceptance,
other destinations and the 30–60 day endurance window remain unproved by those
runs. The measured LVFS outage is excluded only for explicitly owned disposable
hosted KVM guests; no physical-firmware or upstream LVFS repair is claimed.
Failed earlier runs remain failures. See the
[transition plan](superpowers/plans/2026-10-18-ubuntu-26-04-support.md) for current
merge preparation and broader release requirements.
