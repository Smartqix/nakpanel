#!/usr/bin/env bash
set -euo pipefail

VM_NAME="${NAKPANEL_MULTIPASS_VM:-nakpanel-phase2}"
IMAGE="${NAKPANEL_MULTIPASS_IMAGE:-24.04}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REMOTE_SRC="/tmp/nakpanel-src"

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass is required" >&2
  exit 1
fi

if ! multipass info "${VM_NAME}" >/dev/null 2>&1; then
  multipass launch "${IMAGE}" --name "${VM_NAME}" --cpus 2 --memory 2G --disk 12G
fi

cloud_init_done=0
for _ in $(seq 1 90); do
  if multipass exec "${VM_NAME}" -- cloud-init status 2>/dev/null | grep -q 'status: done'; then
    cloud_init_done=1
    break
  fi
  sleep 2
done

if [[ "${cloud_init_done}" != "1" ]]; then
  multipass exec "${VM_NAME}" -- cloud-init status --long || true
  echo "cloud-init did not finish in time" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- sudo rm -rf "${REMOTE_SRC}"
multipass transfer -r "${ROOT_DIR}" "${VM_NAME}:${REMOTE_SRC}"

multipass exec "${VM_NAME}" -- bash -se <<'REMOTE'
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y ca-certificates curl nginx build-essential python3

arch="$(uname -m)"
case "${arch}" in
  x86_64) goarch="amd64" ;;
  aarch64|arm64) goarch="arm64" ;;
  *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;;
esac

if ! command -v go >/dev/null 2>&1 || ! go version | grep -Eq 'go1\.(23|24|25|26)'; then
  curl -fsSL "https://go.dev/dl/go1.23.12.linux-${goarch}.tar.gz" -o /tmp/go.tgz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
  sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi

export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"
if ! command -v task >/dev/null 2>&1; then
  sudo env PATH="${PATH}" GOBIN=/usr/local/bin go install github.com/go-task/task/v3/cmd/task@v3.38.0
fi

if ! id nakpanel >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/nakpanel --create-home --shell /usr/sbin/nologin nakpanel
fi

sudo systemctl enable --now nginx

sudo chown -R nakpanel:nakpanel /tmp/nakpanel-src
cd /tmp/nakpanel-src

sudo -u nakpanel env PATH="${PATH}" HOME=/var/lib/nakpanel task build
sudo systemctl stop nakpanel-agent.service 2>/dev/null || true
sudo install -m 0755 bin/agent /usr/local/bin/nakpanel-agent
sudo install -m 0644 deploy/systemd/nakpanel-agent.service /etc/systemd/system/nakpanel-agent.service
sudo systemctl daemon-reload
sudo systemctl enable nakpanel-agent.service
sudo systemctl restart nakpanel-agent.service
sudo systemctl is-active --quiet nakpanel-agent.service

sudo test -S /run/nakpanel/agent.sock
socket_mode="$(sudo stat -c '%a' /run/nakpanel/agent.sock)"
socket_group="$(sudo stat -c '%G' /run/nakpanel/agent.sock)"
if [[ "${socket_mode}" != "660" || "${socket_group}" != "nakpanel" ]]; then
  echo "unexpected socket permissions: mode=${socket_mode} group=${socket_group}" >&2
  exit 1
fi

ss -xlnp | tee /tmp/nakpanel-agent-ssx.txt
grep -q '/run/nakpanel/agent.sock' /tmp/nakpanel-agent-ssx.txt
if ss -ltnp | grep -q 'nakpanel-agent'; then
  echo "agent unexpectedly has a TCP listener" >&2
  exit 1
fi

sudo -u nakpanel env \
  PATH="${PATH}" \
  HOME=/var/lib/nakpanel \
  NAKPANEL_LIVE_AGENT_SOCKET=/run/nakpanel/agent.sock \
  NAKPANEL_LIVE_AGENT_RELOAD_SERVICE=nginx \
  go test ./internal/control/agentclient -run TestLiveAgent -count=1 -v

sudo -u nakpanel python3 - <<'PY'
import json
import socket

SOCK = "/run/nakpanel/agent.sock"

def call(payload):
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(SOCK)
    conn.sendall(json.dumps(payload).encode() + b"\n")
    data = conn.recv(65536)
    conn.close()
    return json.loads(data.decode())

unknown = call({"op": "run_shell", "id": "phase2-live-unknown", "data": {"command": "id"}})
assert unknown["ok"] is False, unknown
assert "unknown op" in unknown["error"], unknown

bad_reload = call({"op": "reload_service", "id": "phase2-live-bad-service", "data": {"name": "postgresql"}})
assert bad_reload["ok"] is False, bad_reload
assert "service is not allowed" in bad_reload["error"], bad_reload

first = call({"op": "reload_service", "id": "phase2-live-idempotent", "data": {"name": "nginx"}})
second = call({"op": "reload_service", "id": "phase2-live-idempotent", "data": {"name": "nginx"}})
assert first == second, (first, second)
PY
REMOTE

VM_IP="$(multipass info "${VM_NAME}" | awk '/IPv4/{print $2; exit}')"
echo "Phase 2 Multipass verification passed on ${VM_NAME} (${VM_IP})"
