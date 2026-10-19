#!/usr/bin/env bash
# Reclaim and prepare only the disposable GitHub-hosted AMD64 runner assigned
# to this job. Never run this helper on a developer machine or persistent host.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'This preparation requires a disposable GitHub-hosted Linux AMD64 runner.' >&2
  exit 1
fi
: "${RUNNER_TEMP:?GitHub runner temporary directory is required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
evidence="${RUNNER_TEMP}/hosted-evidence"
mkdir -p "${evidence}"
df -h / | tee "${evidence}/disk-before.log"
# These unused SDK trees belong to this disposable hosted VM only.
sudo rm -rf /usr/share/dotnet /usr/local/lib/android /usr/share/swift /usr/local/.ghcup /opt/ghc /opt/hostedtoolcache/CodeQL /usr/lib/jvm /usr/local/share/powershell /usr/share/miniconda
sudo docker system prune --all --force
sudo apt-get update
sudo apt-get install -y acl cpu-checker curl dnsutils jq make openssl python3 ubuntu-keyring gnupg
sudo snap install multipass
sudo udevadm control --reload-rules
sudo udevadm trigger --name-match=kvm
sudo apt-get clean
# Multipass restricts its root-owned socket to an administrative group. A
# hosted runner can have passwordless sudo without membership in that group.
# Authorize only this job's existing UID after the daemon creates its socket;
# keep the client query below as the actual daemon readiness condition.
multipass_socket=/var/snap/multipass/common/multipass_socket
for _ in $(seq 1 120); do
  if sudo test -S "${multipass_socket}"; then break; fi
  sleep 1
done
if ! sudo test -S "${multipass_socket}" || sudo test -L "${multipass_socket}" || [[ "$(sudo stat -c %u "${multipass_socket}")" != 0 ]]; then
  echo 'Multipass did not create its root-owned non-symlink socket.' | tee "${evidence}/multipass-socket-error.log" >&2
  sudo journalctl -u snap.multipass.multipassd.service --no-pager -n 100 >"${evidence}/multipass-journal.log" 2>&1 || true
  exit 1
fi
sudo setfacl -m "u:$(id -u):rw" "${multipass_socket}"
sudo getfacl -n -p "${multipass_socket}" | tee "${evidence}/multipass-socket-acl.log"
# snap install may return before multipassd has created its root certificate.
# A successful bounded daemon query is the readiness condition, never elapsed time.
python3 "${SCRIPT_DIR}/hosted-multipass-ready.py" --output-dir "${evidence}"
timeout --kill-after=2s 15s multipass version | tee "${evidence}/multipass.log"
# Device creation and uaccess rules run asynchronously after udev trigger.
# Finish those events before granting this UID access, after snap/daemon setup.
sudo udevadm settle --timeout=30
if ! sudo test -c /dev/kvm || sudo test -L /dev/kvm || [[ "$(sudo stat -c %u /dev/kvm)" != 0 ]]; then
  echo 'KVM did not create its root-owned non-symlink character device.' | tee "${evidence}/kvm-device-error.log" >&2
  exit 1
fi
sudo setfacl -m "u:$(id -u):rw" /dev/kvm
{
  sudo stat -c 'uid=%u gid=%g mode=%a type=%F' /dev/kvm
  sudo getfacl -n -p /dev/kvm
} | tee "${evidence}/kvm-device-acl.log"
# Diagnostic only; the separate ioctl capacity/KVM preflight is mandatory.
sudo kvm-ok >"${evidence}/kvm.log" 2>&1 || cat "${evidence}/kvm.log"
