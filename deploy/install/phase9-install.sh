#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
"${SCRIPT_DIR}/phase8-install.sh"

systemctl restart nakpanel-agent.service nakpanel.service
echo "Phase 9 plans/subscriptions entitlement gate is installed and nakpanel services restarted."
