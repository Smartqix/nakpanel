package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestQuotaFormatIsLoadedBeforeBootQuotaActivation(t *testing.T) {
	data, err := os.ReadFile("../install/phase8-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"nakpanel-quota.modules-load.conf", "quotaon.service.d/nakpanel.conf", "/etc/modules-load.d/nakpanel-quota.conf", "systemctl daemon-reload", "quota_packages+=(linux-generic)"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing boot quota prerequisite %q", want)
		}
	}
	for path, want := range map[string]string{"../systemd/nakpanel-quota.modules-load.conf": "quota_v2", "../systemd/quotaon.service.d/nakpanel.conf": "After=systemd-modules-load.service"} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), want) {
			t.Errorf("boot prerequisite %s: %v", path, err)
		}
	}
}

func TestPhase8VerifierCoversQuotasAndDiskIsolation(t *testing.T) {
	const path = "phase8-verify.sh"
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
		"phase7-verify.sh",
		"post_admin phase8-quota quotas",
		"quotaon",
		"setquota",
		"pm.max_children = 2",
		"php_admin_value[memory_limit] = 64M",
		"quota exceeded",
		"phase8 verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase8 verifier is missing %q", want)
		}
	}
}

func TestPhase8QuotaRejectionsRequestTheJSONErrorContract(t *testing.T) {
	data, err := os.ReadFile("phase8-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "post_expect_quota_exceeded() {")
	if start < 0 {
		t.Fatal("quota rejection helper is missing")
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatal("quota rejection helper is incomplete")
	}
	helper := script[start : start+end]
	for _, want := range []string{"X-Nakpanel-SPA: true", "Accept: application/json", `"400"`, "'quota exceeded'"} {
		if !strings.Contains(helper, want) {
			t.Errorf("quota rejection helper is missing %q", want)
		}
	}
	if strings.Count(script, `-d "subscription_id=${quota_subscription_id}"`) != 3 {
		t.Error("all three quota rejections must select the fixture subscription")
	}
}

func TestPhase8InstallerInstallsQuotaTooling(t *testing.T) {
	const path = "../install/phase8-install.sh"
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
		"phase7-install.sh",
		"quota",
		"quotacheck",
		"quotaon",
		"systemctl restart nakpanel-agent.service nakpanel.service",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase8 installer is missing %q", want)
		}
	}
}
