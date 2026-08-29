package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestPhaseVerifiersUseSingleDefaultVM(t *testing.T) {
	scripts := []string{
		"phase1-verify.sh",
		"phase2-verify.sh",
		"phase3-verify.sh",
		"phase4-verify.sh",
		"phase4-tls-verify.sh",
		"phase5-ui-verify.sh",
		"phase6-verify.sh",
		"phase6-recovery-verify.sh",
		"phase7-verify.sh",
		"phase8-verify.sh",
		"phase9-verify.sh",
		"phase10-verify.sh",
		"phase11-verify.sh",
		"phase12-verify.sh",
		"phase13-verify.sh",
		"phase14-verify.sh",
		"phase15-verify.sh",
		"phase16-verify.sh",
		"phase17-verify.sh",
		"phase19-verify.sh",
		"phase20-verify.sh",
		"phase21-verify.sh",
		"phase22-verify.sh",
		"phase23-verify.sh",
		"phase24-verify.sh",
		"phase25-verify.sh",
		"phase26-verify.sh",
		"phase27-verify.sh",
		"phase28-verify.sh",
		"phase29-verify.sh",
		"security-verify.sh",
	}
	for _, path := range scripts {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%q) returned error: %v", path, err)
			}
			script := string(data)
			for _, want := range []string{
				"common.sh",
				"VM_NAME=\"${NAKPANEL_MULTIPASS_VM}\"",
				"IMAGE=\"${NAKPANEL_MULTIPASS_IMAGE}\"",
			} {
				if !strings.Contains(script, want) {
					t.Fatalf("%s is missing %q", path, want)
				}
			}
			if strings.Contains(script, "${NAKPANEL_MULTIPASS_VM:-nakpanel-phase") {
				t.Fatalf("%s still contains a phase-specific VM default", path)
			}
		})
	}
}

func TestDeploymentVerifierResetsOneCanonicalVM(t *testing.T) {
	const path = "deployment-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) returned error: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable", path)
	}
	script := string(data)
	for _, want := range []string{
		"common.sh",
		"destroy_legacy_phase_vms",
		"require_nakpanel_vm_name \"${NAKPANEL_MULTIPASS_VM}\"",
		"destroy_vm \"${NAKPANEL_MULTIPASS_VM}\"",
		"ensure_vm 2 3G 16G",
		"security-verify.sh",
		"phase28-verify.sh",
		"phase29-verify.sh",
		"nakpanel-lab",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s is missing %q", path, want)
		}
	}
}

func TestCommonHelperListsLegacyPhaseVMs(t *testing.T) {
	const path = "common.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) returned error: %v", path, err)
	}
	script := string(data)
	for _, want := range []string{
		`NAKPANEL_MULTIPASS_VM="${NAKPANEL_MULTIPASS_VM:-nakpanel-lab}"`,
		`NAKPANEL_MULTIPASS_IMAGE="${NAKPANEL_MULTIPASS_IMAGE:-24.04}"`,
		"require_nakpanel_vm_name()",
		"nakpanel-phase1",
		"nakpanel-phase4-tls",
		"nakpanel-phase6-recovery",
		"nakpanel-phase10",
		"nakpanel-phase11",
		"nakpanel-phase12",
		"nakpanel-phase16",
		"nakpanel-phase17",
		"nakpanel-phase25",
		"nakpanel-phase26",
		"nakpanel-phase27",
		"nakpanel-phase28",
		"nakpanel-phase29",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s is missing %q", path, want)
		}
	}
}

// TestVerifiersDoNotMaskExitStatusInTraps guards against a bash 3.2 pitfall:
// an `EXIT` trap that runs a successful command (e.g. `rm -rf tmpdir`) resets
// $? to 0, silently masking a fatal error that aborted the script. Every
// tmpdir cleanup trap must preserve and re-exit the original status, or the
// phase would "pass" after aborting partway (which happened to phase 28).
func TestVerifiersDoNotMaskExitStatusInTraps(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, "-verify.sh") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", name, err)
		}
		script := string(data)
		if strings.Contains(script, `trap 'rm -rf "${tmpdir}"' EXIT`) {
			t.Errorf("%s uses a status-masking EXIT trap; it must capture and re-exit $? "+
				"(trap 'status=$?; rm -rf \"${tmpdir}\"; exit \"${status}\"' EXIT)", name)
		}
	}
}
