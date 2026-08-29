package multipass

import (
	"os"
	"strings"
	"testing"
)

// TestSecurityVerifierCoversEveryPart keeps the adversarial suite honest: it
// must attack every boundary (Parts A–H), fail closed, and clean up. If a part
// is removed the gate silently weakens, so this guard fails instead.
func TestSecurityVerifierCoversEveryPart(t *testing.T) {
	data, err := os.ReadFile("security-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{
		"common.sh",
		"Part A — Filesystem boundary",
		"Part B — Config template injection",
		"Part C — Cross-tenant isolation",
		"Part D — Entitlement / quota bypass",
		"Part E — Provisioning API auth",
		"Part F — Agent socket boundary",
		"Part G — Destructive-op safety",
		"Part H — Secret handling",
		"agentprobe",         // real agent-socket client, not a mock
		"provision_tenant A", // two real tenants
		"provision_tenant B",
		"SO_PEERCRED",             // socket peer-uid attack
		"plan_downgrade_conflict", // quota bypass
		"external_ref",            // concurrent idempotency
		"SECURITY-FAIL",           // fails closed
		"exit 1",
		"trap cleanup EXIT",     // self-cleaning
		"api-key revoke",        // no live verifier credentials remain
		"outbox.status<>'sent'", // teardown events drain before sink shutdown
		"NAKPANEL_PUBLIC_URL",   // production-like panel environment restored
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("security-verify.sh is missing %q", want)
		}
	}
}
