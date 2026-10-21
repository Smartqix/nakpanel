package multipass

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformIdentityProfileContracts(t *testing.T) {
	for _, tc := range []struct {
		release, provider, want string
		valid                   bool
	}{
		{"24.04", "native", "", false},
		{"26.04", "native", "8.5:8.5:8.5:ubuntu-26.04-native", true},
		{"26.04", "sury", "8.4:8.3:8.5,8.4,8.3:ubuntu-26.04-sury", true},
		{"24.04", "sury", "", false}, {"26.04", "unknown", "", false},
	} {
		t.Run(tc.release+"/"+tc.provider, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `source ./common.sh; validate_run_identity testtoken || exit 1; printf '%s:%s:%s:%s' "$NAKPANEL_FIXTURE_PHP" "$NAKPANEL_BASELINE_PHP" "$NAKPANEL_PHP_VERSIONS" "$NAKPANEL_QUALIFICATION_PROFILE"`)
			cmd.Env = append(os.Environ(), "NAKPANEL_MULTIPASS_IMAGE="+tc.release, "NAKPANEL_QUALIFICATION_PHP_PROVIDER="+tc.provider)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.valid || (tc.valid && string(out) != tc.want) {
				t.Fatalf("profile: %s %v", out, err)
			}
		})
	}
}

func TestFreshAndDRInstallForwardSelectedProvider(t *testing.T) {
	for _, path := range []string{"current-install-verify.sh", "phase29-verify.sh"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"NAKPANEL_QUALIFICATION_PHP_PROVIDER", "--php-provider"} {
			if !strings.Contains(string(data), want) {
				t.Fatalf("%s missing explicit Sury fresh contract %s", path, want)
			}
		}
	}

}

func TestPlatformCellInvalidBundleRecordsFailureBeforeVMWork(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report")
	calls := filepath.Join(dir, "calls")
	fake := `#!/bin/bash
printf '%s\n' "$*" >> "$FAKE_LOG"
exit 99
`
	if err := os.WriteFile(filepath.Join(dir, "multipass"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "./ubuntu-platform-verify.sh")
	archOut, err := exec.Command("bash", "-c", "source ./common.sh; multipass_host_arch").Output()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "FAKE_LOG="+calls, "NAKPANEL_RUN_TOKEN=run123", "NAKPANEL_MULTIPASS_VM=nakpanel-26-04-native-run123", "NAKPANEL_MULTIPASS_ARCH="+strings.TrimSpace(string(archOut)), "NAKPANEL_MULTIPASS_IMAGE=26.04", "NAKPANEL_RELEASE_BUNDLE="+dir, "NAKPANEL_RELEASE_PUBLIC_KEY="+filepath.Join(dir, "missing.pem"), "NAKPANEL_RELEASE_VERSION=29.0.0", "NAKPANEL_CELL_REPORT_DIR="+report, "NAKPANEL_OWNERSHIP_DIR="+filepath.Join(dir, "ownership"))
	cmd.Env = append(cmd.Env, "NAKPANEL_RELEASE_SIGNING_KEY=SECRET_PRIVATE_KEY_SHOULD_NOT_BE_SAVED")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("invalid bundle accepted: %s", out)
	}
	data, err := os.ReadFile(filepath.Join(report, "report.json"))
	if err != nil {
		t.Fatalf("no failure evidence: %s %v", out, err)
	}
	var result struct {
		QualificationPassed bool `json:"qualification_passed"`
		PromotionEligible   bool `json:"promotion_eligible"`
		Gates               []struct {
			Status string `json:"status"`
		}
	}
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.QualificationPassed || result.PromotionEligible || len(result.Gates) != 1 || result.Gates[0].Status != "FAIL" {
		t.Fatalf("false success evidence: %s", data)
	}
	if data, _ := os.ReadFile(calls); len(data) > 0 {
		t.Fatalf("VM calls before valid bundle: %s", data)
	}
	run, err := os.ReadFile(filepath.Join(report, "run.env"))
	if err != nil || !strings.Contains(string(run), "/var/lib/nakpanel-qualification/run123/source") || strings.Contains(string(run), "SECRET_PRIVATE_KEY_SHOULD_NOT_BE_SAVED") {
		t.Fatalf("missing durable path contract or leaked unapproved environment: %s %v", run, err)
	}
}

func TestRequestedDatabaseManagerInstallsAndVerifiesRealRuntime(t *testing.T) {
	data, err := os.ReadFile("internal-tools-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	requested := strings.Index(script, `if [[ "${NAKPANEL_VERIFY_DATABASE_MANAGER:-0}" == 1 ]]`)
	install := strings.Index(script, "deploy/install/database-manager-install.sh")
	health := strings.Index(script, "/__nakpanel_health")
	browser := strings.Index(script, "database-workspace-browser-smoke.cjs")
	if requested < 0 || install <= requested || health <= install || browser <= health {
		t.Fatal("requested manager must actually install then prove FastCGI and browser behavior")
	}
}

func TestInventoryRequiresUserQuotaStateDespiteAggregateQuotaExit(t *testing.T) {
	data, err := os.ReadFile("ubuntu-platform-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_inventory_user_quota", true)
	for _, state := range []string{"on", "off"} {
		cmd := exec.Command("bash", "-c", `set -euo pipefail
findmnt(){ echo /; }
quotaon(){ echo "user quota on / (/dev/sda1) is $STATE"; echo 'group quota off'; return 1; }
`+function+`assert_inventory_user_quota`)
		cmd.Env = append(os.Environ(), "STATE="+state)
		out, err := cmd.CombinedOutput()
		if (err == nil) != (state == "on") {
			t.Fatalf("state %s: %s %v", state, out, err)
		}
	}
}

func TestValkeyFixtureCreatesMissingPolicyParent(t *testing.T) {
	data, err := os.ReadFile("valkey-platform-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "'{valkey}',") || strings.Contains(string(data), "'{valkey,enabled}'") {
		t.Fatal("jsonb_set cannot populate nested Valkey fields when policy parent is absent; fixture must create complete object")
	}
	if !strings.Contains(string(data), "X-Nakpanel-SPA: true") || !strings.Contains(string(data), "json.load") {
		t.Fatal("real Valkey request must fail HTTP errors and parse explicit JSON one-time credential")
	}
}

func TestValkeyPrivateACLAndSocketDenialsBothRequired(t *testing.T) {
	data, err := os.ReadFile("valkey-platform-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_private_valkey_paths", true)
	for _, mode := range []string{"private", "acl readable", "socket readable"} {
		cmd := exec.Command("bash", "-c", `set -euo pipefail
runuser(){ case "$*" in *users.acl) [[ "$MODE" == 'acl readable' ]];; *valkey.sock) [[ "$MODE" == 'socket readable' ]];; *) return 78;; esac; }
`+function+`assert_private_valkey_paths 1`)
		cmd.Env = append(os.Environ(), "MODE="+mode)
		out, err := cmd.CombinedOutput()
		if (err == nil) != (mode == "private") {
			t.Fatalf("mode %s: %s %v", mode, out, err)
		}
	}
}

func TestModernReinstallsUseStagedSignedCandidateWhenPresent(t *testing.T) {
	for _, path := range []string{"phase31-verify.sh", "phase32-verify.sh", "phase34-verify.sh"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			start := strings.Index(script, `multipass exec "${VM_NAME}" --working-directory / -- sudo bash -se --`)
			if start < 0 {
				t.Fatal("canonical installer block missing")
			}
			block := script[start:]
			start = strings.Index(block, "<<'REMOTE'\n")
			if start < 0 {
				t.Fatal("installer body missing")
			}
			block = block[start+len("<<'REMOTE'\n"):]
			end := strings.Index(block, "\nsystemctl is-active")
			if end < 0 {
				t.Fatal("installer health boundary missing")
			}
			block = block[:end]
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			bundle := filepath.Join(dir, "signed-bundle")
			if err := os.MkdirAll(filepath.Join(source, "deploy", "install"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(bundle, "bin"), 0700); err != nil {
				t.Fatal(err)
			}
			fake := "#!/bin/bash\nprintf '%s\\n' \"$*\"\nprintf 'development=%s\\n' \"${NAKPANEL_RELEASE_ALLOW_DEVELOPMENT:-}\"\n"
			if err := os.WriteFile(filepath.Join(source, "deploy", "install", "install.sh"), []byte(fake), 0700); err != nil {
				t.Fatal(err)
			}
			block = strings.ReplaceAll(block, "/tmp/nakpanel-release", bundle)
			cmd := exec.Command("bash", "-c", "timeout(){ shift; \"$@\"; }; goaccess(){ :; };\n"+block, "_", source, "1", bundle, bundle+"-public.pem")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("installer: %s %v", out, err)
			}
			for _, want := range []string{"--bundle " + bundle, "--release-public-key " + bundle + "-public.pem", "--allow-development-bundle", "development=1"} {
				if !strings.Contains(string(out), want) {
					t.Fatalf("signed candidate bypassed (%s): %s", want, out)
				}
			}
		})
	}
}

func TestValkeyBoundarySeparatesCacheAndContainerMemory(t *testing.T) {
	data, err := os.ReadFile("valkey-platform-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"100663296", "maxmemory 64mb", "/etc/nakpanel/valkey/sub-$1/valkey.conf"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("Valkey cache64MiB requires intentional96MiB container bound plus real maxmemory proof: missing %s", want)
		}
	}
	if strings.Contains(string(data), "= 67108864") {
		t.Fatal("physical cache/container budgets conflated")
	}
}

func TestModernFreshInstallerChoosesAdminAndDisablesOtherPublicSeeds(t *testing.T) {
	for _, path := range []string{"current-install-verify.sh", "phase29-verify.sh"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"--admin-email admin@nakpanel.test", "--admin-password-file", "umask 077", "NakpanelAdmin!2026"} {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s missing explicit private admin bootstrap %s", path, want)
			}
		}
	}
	current, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), "NOT login_disabled") {
		t.Fatal("fresh bootstrap does not prove other public seeds disabled")
	}
	for _, path := range []string{"phase34-verify.sh", "domain-removal-verify.sh"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "email=client@nakpanel.test") {
			t.Errorf("%s still depends on intentionally disabled public client", path)
		}
		if !strings.Contains(string(data), "unrelated_email") {
			t.Errorf("%s missing explicit unrelated customer identity", path)
		}
	}
}

func TestValkeyTraversalACLRequiredBeforeAndAfterReboot(t *testing.T) {
	data, err := os.ReadFile("valkey-platform-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	function := shellFixtureFunction(t, script, "assert_valkey_traversal", true)
	for _, mode := range []string{"present", "missing"} {
		cmd := exec.Command("bash", "-c", `set -euo pipefail
VM_NAME=owned;username=tenant
fail(){ echo "$*" >&2;exit 1; }
multipass_exec_short(){ if [[ "$*" == *getfacl* ]]; then if [[ "$MODE" == present ]]; then echo user:tenant:--x;fi; else echo '750 root:nakpanel'; fi; }
`+function+`assert_valkey_traversal`)
		cmd.Env = append(os.Environ(), "MODE="+mode)
		out, err := cmd.CombinedOutput()
		if (err == nil) != (mode == "present") {
			t.Fatalf("mode%s: %s %v", mode, out, err)
		}
	}
	restart := strings.Index(script, `multipass restart "${VM_NAME}"`)
	if restart < 0 || !strings.Contains(script[restart:], "assert_valkey_traversal") {
		t.Fatal("postboot ACL observation missing")
	}
}
