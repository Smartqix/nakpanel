package install

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func platformFixture(t *testing.T, content string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestPlatformProfilesResolveOnlyExplicitUbuntuContracts(t *testing.T) {
	for _, tt := range []struct {
		name, data, arch, want string
		reject                 bool
	}{
		{"noble", "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n", "amd64", "ubuntu-24.04|8.3|8.3 8.4 8.5", false},
		{"resolute", "ID=ubuntu\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\n", "arm64", "ubuntu-26.04-native|8.5|8.5", false},
		{"wrong codename", "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=noble\n", "arm64", "", true},
		{"future", "ID=ubuntu\nVERSION_ID=26.10\nVERSION_CODENAME=stonking\n", "amd64", "", true},
		{"other distro", "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n", "amd64", "", true},
		{"wrong architecture", "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", "riscv64", "", true},
		{"missing fields", "ID=ubuntu\n", "amd64", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file := platformFixture(t, tt.data)
			cmd := exec.Command("bash", "-c", `set -eu; source ./platform.sh; nakpanel_load_platform "$1" "$2"; printf '%s|%s|%s' "$NAKPANEL_PLATFORM_ID" "$NAKPANEL_INTERNAL_PHP_VERSION" "${NAKPANEL_HOSTING_PHP_VERSIONS[*]}"`, "platform-test", file, tt.arch)
			out, err := cmd.CombinedOutput()
			if tt.reject {
				if err == nil {
					t.Fatalf("unsupported platform accepted: %s", out)
				}
				return
			}
			if err != nil || string(out) != tt.want {
				t.Fatalf("platform result=%q error=%v; want %q", out, err, tt.want)
			}
		})
	}
}

func TestPlatformRejectsMissingMetadataBeforeCallingMutation(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "mutated")
	cmd := exec.Command("bash", "-c", `set -eu; source ./platform.sh; nakpanel_load_platform "$1" amd64; touch "$2"`, "platform-test", filepath.Join(t.TempDir(), "absent"), marker)
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("missing metadata accepted: %s", out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("mutation occurred: %v", err)
	}
}

func TestPlatformMetadataIsDataAndNotExecuted(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	file := platformFixture(t, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\nIGNORED=$(touch "+marker+")\n")
	cmd := exec.Command("bash", "-c", `set -eu; source ./platform.sh; nakpanel_load_platform "$1" amd64`, "platform-test", file)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load: %v: %s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("metadata was executed: %v", err)
	}
}

func TestInstalledPlatformMismatchCannotPassNoopPreflight(t *testing.T) {
	for _, profile := range []string{
		`{"os_id":"ubuntu","version_id":"26.04","codename":"resolute","architecture":"amd64","profile":"ubuntu-26.04-native","internal_php_version":"8.5","hosting_php_versions":["8.5"]}`,
		`{"os_id":"ubuntu","version_id":"24.04","codename":"noble","architecture":"arm64","profile":"ubuntu-24.04","internal_php_version":"8.3","hosting_php_versions":["8.3","8.4","8.5"]}`,
		`not JSON`,
	} {
		state := platformFixture(t, profile)
		osRelease := platformFixture(t, "ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n")
		cmd := exec.Command("bash", "-c", `set -eu; source ./platform.sh; nakpanel_load_platform "$1" amd64; nakpanel_check_platform_state "$2"`, "platform-test", osRelease, state)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("mismatched installed profile accepted: %s", out)
		}
		if !strings.Contains(string(out), "platform") {
			t.Fatalf("missing platform diagnostic: %s", out)
		}
	}
}

func TestPackagePolicyRejectsWrongCandidateOriginAndRelease(t *testing.T) {
	for _, tt := range []struct {
		name, codename, policy string
		reject                 bool
	}{
		{"native", "resolute", "php8.5-cli:\n  Installed: (none)\n  Candidate: 8.5.4\n  Version table:\n     8.5.4 500\n        500 http://archive.ubuntu.com/ubuntu resolute-updates/universe arm64 Packages\n", false},
		{"noble ppa", "noble", "php8.4-cli:\n  Installed: (none)\n  Candidate: 8.4.26\n  Version table:\n     8.4.26 500\n        500 https://ppa.launchpadcontent.net/ondrej/php/ubuntu noble/main amd64 Packages\n", false},
		{"wrong suite", "resolute", "pkg:\n  Candidate: 1\n  Version table:\n     1 500\n        500 http://archive.ubuntu.com/ubuntu noble/main arm64 Packages\n", true},
		{"foreign origin", "resolute", "pkg:\n  Candidate: 1\n  Version table:\n     1 500\n        500 https://unknown.example/repo resolute/main arm64 Packages\n", true},
		{"only noncandidate trusted", "resolute", "pkg:\n  Candidate: 2\n  Version table:\n     2 999\n        999 https://unknown.example/repo resolute/main arm64 Packages\n     1 500\n        500 http://archive.ubuntu.com/ubuntu resolute/main arm64 Packages\n", true},
		{"installed only", "resolute", "pkg:\n  Candidate: 1\n  Version table:\n *** 1 100\n        100 /var/lib/dpkg/status\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("python3", "./package_policy.py", tt.codename)
			cmd.Stdin = strings.NewReader(tt.policy)
			out, err := cmd.CombinedOutput()
			if tt.reject && err == nil {
				t.Fatalf("unsafe origin accepted: %s", out)
			}
			if !tt.reject && err != nil {
				t.Fatalf("valid origin rejected: %v: %s", err, out)
			}
		})
	}
}

func TestRoundcubeRejectsAlteredReleaseBeforeSignatureOrExtraction(t *testing.T) {
	archive := platformFixture(t, "altered release")
	cmd := exec.Command("bash", "-c", `set -eu; source ./roundcube.sh; nakpanel_verify_roundcube_release "$1" "$1"`, "roundcube-test", archive)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Roundcube SHA-256") {
		t.Fatalf("altered archive must fail its pinned digest before GPG: %v: %s", err, out)
	}
}

func TestPackagePreflightConsumesCompleteAptPolicy(t *testing.T) {
	bin := t.TempDir()
	cache := "#!/usr/bin/env python3\nimport sys\nprint('pkg:\\n  Candidate: 1\\n  Version table:\\n     1 500\\n        500 http://archive.ubuntu.com/ubuntu resolute/main arm64 Packages')\nsys.stdout.write('\\n' * 100000)\n"
	if err := os.WriteFile(filepath.Join(bin, "apt-cache"), []byte(cache), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "apt-get"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$SIMULATION_LOG\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	metadata := platformFixture(t, "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n")
	log := filepath.Join(t.TempDir(), "simulation")
	cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./platform.sh; nakpanel_load_platform "$1" arm64; nakpanel_preflight_packages`, "platform-test", metadata)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "SIMULATION_LOG="+log)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("valid package policy must not fail with SIGPIPE: %v: %s", err, out)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "--simulate install") || !strings.Contains(string(data), "php8.5-fpm") || strings.Contains(string(data), "php8.3") {
		t.Fatalf("incorrect native transaction: %s", data)
	}
	if strings.Contains(string(data), "postgresql-contrib") || !strings.Contains(string(data), "postgresql-18") {
		t.Fatalf("Resolute must install actual PostgreSQL18 provider of contrib extensions, not removed metapackage: %s", data)
	}
}

func TestLegacyUnrecordedResoluteInstallRejectsBeforeMutation(t *testing.T) {
	for _, tt := range []struct {
		name, version, binaries, database string
		reject                            bool
	}{
		{"new resolute", "26.04", "0", "0", false},
		{"legacy noble", "24.04", "1", "1", false},
		{"same-version binaries", "26.04", "1", "0", true},
		{"forced fresh database", "26.04", "0", "1", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			codename := "noble"
			if tt.version == "26.04" {
				codename = "resolute"
			}
			metadata := platformFixture(t, "ID=ubuntu\nVERSION_ID="+tt.version+"\nVERSION_CODENAME="+codename+"\n")
			marker := filepath.Join(t.TempDir(), "mutated")
			cmd := exec.Command("bash", "-c", `set -euo pipefail; source ./platform.sh; nakpanel_load_platform "$1" arm64; nakpanel_check_legacy_installation "$2" "$3" "$4"; touch "$5"`, "legacy-test", metadata, filepath.Join(t.TempDir(), "absent.json"), tt.binaries, tt.database, marker)
			out, err := cmd.CombinedOutput()
			if tt.reject {
				if err == nil {
					t.Fatalf("unsafe existing installation accepted: %s", out)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("mutation after rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("safe baseline rejected: %v: %s", err, out)
			}
		})
	}
}

func TestUpgradeFailedPreflightDoesNotRestartServices(t *testing.T) {
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	functions := ""
	for _, name := range []string{"cleanup_upgrade", "upgrade_install"} {
		match := regexp.MustCompile(`(?ms)^` + name + `\(\) \{.*?^\}`).Find(data)
		if match == nil {
			t.Fatalf("missing callable installer function %s", name)
		}
		functions += string(match) + "\n"
	}
	log := filepath.Join(t.TempDir(), "services")
	script := `set -euo pipefail
completed=0; schema_migrated=0; backup_dir=''; APP_TRANSACTION_STARTED=0
cleanup_stages(){ :; }
prepare_platform_install(){ return 55; }
systemctl(){ printf '%s\n' "$*" >> "$1_LOG"; }
` + functions + "\nupgrade_install\n"
	// Environment-backed sink lets the real cleanup function run against a safe boundary.
	script = strings.ReplaceAll(script, `"$1_LOG"`, `"$SERVICE_LOG"`)
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "SERVICE_LOG="+log)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("failed preflight accepted: %s", out)
	}
	if entries, _ := os.ReadFile(log); len(entries) > 0 {
		t.Fatalf("preflight failure mutated live services: %s", entries)
	}
}

func TestStalwartPreflightFailurePrecedesApplicationMutation(t *testing.T) {
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := regexp.MustCompile(`(?ms)^prepare_platform_install\(\) \{.*?^\}`).Find(data)
	if function == nil {
		t.Fatal("platform preflight function missing")
	}
	for _, version := range []string{"24.04", "26.04"} {
		for _, failure := range []string{"0", "73"} {
			t.Run(version+"/"+failure, func(t *testing.T) {
				log := filepath.Join(t.TempDir(), "events")
				script := `set -euo pipefail
MODE=upgrade
RESUMING_NATIVE_BOOTSTRAP=0
SCRIPT_DIR=unused
source(){ :; }
nakpanel_preflight_host(){ echo host >> "$EVENT_LOG"; }
nakpanel_prepare_package_sources(){ echo packages >> "$EVENT_LOG"; }
nakpanel_prepare_roundcube_artifact(){ echo roundcube >> "$EVENT_LOG"; }
nakpanel_prepare_stalwart_artifact(){ echo stalwart >> "$EVENT_LOG"; return "$ARTIFACT_RESULT"; }
` + string(function) + `
prepare_platform_install
echo application-mutation >> "$EVENT_LOG"
`
				cmd := exec.Command("bash", "-c", script)
				cmd.Env = append(os.Environ(), "NAKPANEL_OS_VERSION="+version, "ARTIFACT_RESULT="+failure, "EVENT_LOG="+log)
				out, runErr := cmd.CombinedOutput()
				if (runErr != nil) != (failure != "0") {
					t.Fatalf("artifact failure boundary: %v: %s", runErr, out)
				}
				want := "host\npackages\n"
				if version == "26.04" {
					want += "roundcube\n"
				}
				want += "stalwart\n"
				if failure == "0" {
					want += "application-mutation\n"
				}
				events, _ := os.ReadFile(log)
				if string(events) != want {
					t.Fatalf("preflight events %q, want %q", events, want)
				}
			})
		}
	}
}

func TestHostPreflightReportsRequirementsAndRejectsBeforePackagePreparation(t *testing.T) {
	if out, err := exec.Command("python3", "./host_preflight_test.py").CombinedOutput(); err != nil {
		t.Fatalf("host requirements: %v: %s", err, out)
	}
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := regexp.MustCompile(`(?ms)^prepare_platform_install\(\) \{.*?^\}`).Find(data)
	if function == nil {
		t.Fatal("platform preflight missing")
	}
	log := filepath.Join(t.TempDir(), "mutation")
	script := `set -euo pipefail
nakpanel_preflight_host(){ return 72; }
nakpanel_prepare_package_sources(){ touch "$MUTATION_LOG"; }
` + string(function) + "\nprepare_platform_install\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "MUTATION_LOG="+log)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		t.Fatalf("unsupported host accepted: %s", out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatalf("package preparation ran after rejected host: %v", err)
	}
}

func TestInterruptedNativeBootstrapCannotTakeSameVersionNoop(t *testing.T) {
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, `if [[ "${MODE}" == "upgrade" || "${RESUMING_NATIVE_BOOTSTRAP}"`)
	end := strings.Index(script, `if [[ "${MODE}" == "upgrade" && "${ASSUME_YES}"`)
	if start < 0 || end <= start {
		t.Fatal("installer version decision boundary missing")
	}
	for _, tc := range []struct{ pending, mode, resuming, installed string }{
		{"true", "upgrade", "0", "29.0.0"},
		{"true", "fresh", "1", "29.0.0"},
		{"false", "upgrade", "0", "29.0.0"},
		{"true", "fresh", "1", "30.0.0"},
	} {
		cmd := exec.Command("bash", "-c", `set -euo pipefail
MODE="$2"
RESUMING_NATIVE_BOOTSTRAP="$3"
installed_version="$4"
TARGET_VERSION=29.0.0
FORCE=0
ALLOW_DOWNGRADE=0
PLATFORM_BOOTSTRAP_PENDING="$1"
`+script[start:end]+"\necho resume-bootstrap\n", "version-test", tc.pending, tc.mode, tc.resuming, tc.installed)
		out, err := cmd.CombinedOutput()
		if tc.installed == "30.0.0" {
			if err == nil || !strings.Contains(string(out), "refusing downgrade") {
				t.Fatalf("resuming fresh transaction bypassed downgrade refusal: %v: %s", err, out)
			}
			continue
		}
		if err != nil {
			t.Fatalf("version check: %v: %s", err, out)
		}
		if tc.pending == "true" && string(out) != "resume-bootstrap\n" {
			t.Fatalf("pending install did not resume its secured bootstrap: %s", out)
		}
		if tc.pending == "false" && (!strings.Contains(string(out), "already installed") || strings.Contains(string(out), "resume-bootstrap")) {
			t.Fatalf("completed offline same-version no-op changed: %s", out)
		}
	}
}

func TestNativePendingInstallResumesFreshPrerequisitesAtEveryBinaryBoundary(t *testing.T) {
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := regexp.MustCompile(`(?ms)^resolve_install_mode\(\) \{.*?^\}`).Find(data)
	if function == nil {
		t.Fatal("resumable installer mode resolver missing")
	}
	for _, tc := range []struct{ profile, pending, binaries, explicit, want string }{
		{"ubuntu-26.04-native", "true", "0", "", "fresh|1"},
		{"ubuntu-26.04-native", "true", "1", "", "fresh|1"},
		{"ubuntu-26.04-native", "true", "1", "upgrade", "fresh|1"},
		{"ubuntu-26.04-native", "true", "1", "fresh", "fresh|1"},
		{"ubuntu-26.04-native", "false", "1", "", "upgrade|0"},
		{"ubuntu-24.04", "false", "1", "", "upgrade|0"},
		{"ubuntu-26.04-sury", "false", "0", "", "fresh|0"},
	} {
		cmd := exec.Command("bash", "-c", `set -euo pipefail
MODE="$1"; FORCE=0; RESTORE_ARCHIVE=''
`+string(function)+"\nresolve_install_mode\nprintf '%s|%s' \"$MODE\" \"$RESUMING_NATIVE_BOOTSTRAP\"\n", "mode-test", tc.explicit)
		cmd.Env = append(os.Environ(), "NAKPANEL_PLATFORM_ID="+tc.profile, "PLATFORM_BOOTSTRAP_PENDING="+tc.pending, "have_binaries="+tc.binaries)
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != tc.want {
			t.Fatalf("%+v: mode=%q, error=%v", tc, out, err)
		}
	}
}

func TestBundleStagingSealsAnIndependentPrivateCopy(t *testing.T) {
	source := t.TempDir()
	file := filepath.Join(source, "VERSION")
	if err := os.WriteFile(file, []byte("29.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "./stage_bundle.py", source)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stage: %v: %s", err, out)
	}
	stage := strings.TrimSpace(string(out))
	t.Cleanup(func() { os.RemoveAll(stage) })
	info, err := os.Stat(stage)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("staged bundle accessible to other users: %v", info.Mode())
	}
	if err := os.WriteFile(file, []byte("attacker replacement\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(filepath.Join(stage, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) != "29.0.0\n" {
		t.Fatalf("source write changed verified staging: %s", sealed)
	}
}

func TestBundleStagingRejectsSymlinkPayload(t *testing.T) {
	source := t.TempDir()
	if err := os.Symlink("/etc/passwd", filepath.Join(source, "VERSION")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "./stage_bundle.py", source)
	if out, err := cmd.CombinedOutput(); err == nil {
		os.RemoveAll(strings.TrimSpace(string(out)))
		t.Fatal("untrusted bundle symlink copied into privileged staging")
	}
}

func TestRoundcubeArchiveAllowsInternalLinksButRejectsEscapes(t *testing.T) {
	for _, tt := range []struct {
		name, target string
		reject       bool
	}{
		{"legitimate upstream", "../plugins", false},
		{"escape", "../../etc", true},
		{"absolute", "/etc", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "release.tar.gz")
			file, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(file)
			tw := tar.NewWriter(gz)
			for _, header := range []*tar.Header{
				{Name: "roundcubemail-1.6.19/", Mode: 0755, Typeflag: tar.TypeDir},
				{Name: "roundcubemail-1.6.19/plugins/", Mode: 0755, Typeflag: tar.TypeDir},
				{Name: "roundcubemail-1.6.19/public_html/", Mode: 0755, Typeflag: tar.TypeDir},
				{Name: "roundcubemail-1.6.19/public_html/plugins", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: tt.target},
			} {
				if err := tw.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			file.Close()
			cmd := exec.Command("python3", "archive_policy.py", archive, "roundcubemail-1.6.19")
			out, err := cmd.CombinedOutput()
			if tt.reject && err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if !tt.reject && err != nil {
				t.Fatalf("legitimate upstream link rejected: %v: %s", err, out)
			}
		})
	}
}

func TestSuryProviderRequiresExplicitResoluteOptIn(t *testing.T) {
	for _, tt := range []struct {
		name, release, provider, want string
		reject                        bool
	}{
		{"unchanged native", "26.04", "native", "ubuntu-26.04-native|8.5|8.5", false},
		{"explicit sury", "26.04", "sury", "ubuntu-26.04-sury|8.5|8.3 8.4 8.5", false},
		{"noble unchanged", "24.04", "native", "ubuntu-24.04|8.3|8.3 8.4 8.5", false},
		{"noble not enrolled", "24.04", "sury", "", true},
		{"arbitrary source", "26.04", "custom", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			codename := "resolute"
			if tt.release == "24.04" {
				codename = "noble"
			}
			metadata := platformFixture(t, "ID=ubuntu\nVERSION_ID="+tt.release+"\nVERSION_CODENAME="+codename+"\n")
			command := exec.Command("bash", "-c", `set -eu; source ./platform.sh; nakpanel_load_platform "$1" arm64; nakpanel_select_php_provider "$2"; printf '%s|%s|%s' "$NAKPANEL_PLATFORM_ID" "$NAKPANEL_INTERNAL_PHP_VERSION" "${NAKPANEL_HOSTING_PHP_VERSIONS[*]}"`, "provider-test", metadata, tt.provider)
			output, err := command.CombinedOutput()
			if tt.reject {
				if err == nil {
					t.Fatalf("unsupported enrollment accepted: %s", output)
				}
				return
			}
			if err != nil || string(output) != tt.want {
				t.Fatalf("provider result %q, %v; want %q", output, err, tt.want)
			}
		})
	}
}

func TestSuryCandidateCannotSupplyGlobalDependenciesOrNativeProfile(t *testing.T) {
	policy := "pkg:\n  Candidate: 1\n  Version table:\n     1 500\n        -1 https://packages.sury.org/php resolute/main arm64 Packages\n"
	for _, tt := range []struct {
		provider, pkg string
		reject        bool
	}{
		{"sury", "php8.3-cli", false}, {"sury", "php-common", false},
		{"native", "php8.3-cli", true}, {"sury", "libssl3t64", true}, {"sury", "nginx", true},
	} {
		command := exec.Command("python3", "./package_policy.py", "resolute", tt.provider, tt.pkg)
		command.Stdin = strings.NewReader(policy)
		output, err := command.CombinedOutput()
		if tt.reject && err == nil {
			t.Fatalf("unsafe candidate accepted for %s/%s: %s", tt.provider, tt.pkg, output)
		}
		if !tt.reject && err != nil {
			t.Fatalf("approved scoped candidate rejected: %v %s", err, output)
		}
	}
}

func TestBootstrapGatePersistsBeforeStateAndClearsOnlyAfterCommit(t *testing.T) {
	if output, err := exec.Command("python3", "./platform_state_test.py").CombinedOutput(); err != nil {
		t.Fatalf("persistent bootstrap gate: %v: %s", err, output)
	}
}

func TestSuryCandidateDoesNotInheritTrustFromNegativePriorityOtherVersion(t *testing.T) {
	policy := `php8.5-cli:
  Candidate: 8.5.10-wrong
  Version table:
     8.5.10-wrong 500
        500 https://packages.sury.org/php noble/main arm64 Packages
     8.5.9-correct -1
        -1 https://packages.sury.org/php resolute/main arm64 Packages
`
	command := exec.Command("python3", "./package_policy.py", "resolute", "sury", "php8.5-cli")
	command.Stdin = strings.NewReader(policy)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("wrong selected suite inherited another version's trust: %s", output)
	}
}

func TestInterruptedNativeAdministratorIntentRemainsRequired(t *testing.T) {
	if output, err := exec.Command("python3", "./native_admin_test.py").CombinedOutput(); err != nil {
		t.Fatalf("native administrator intent: %v: %s", err, output)
	}
}

func TestNativeBootstrapHoldsStartupGateUntilAdministratorSucceeds(t *testing.T) {
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?ms)^bootstrap_native_plans\(\) \{\n.*?^\}`).Find(data)
	if len(block) == 0 {
		t.Fatal("bootstrap function missing")
	}
	for _, failAdmin := range []string{"0", "1"} {
		t.Run("admin_failure_"+failAdmin, func(t *testing.T) {
			trace := filepath.Join(t.TempDir(), "trace")
			program := `set -euo pipefail
NAKPANEL_PLATFORM_ID=ubuntu-26.04-native
PLATFORM_BOOTSTRAP_PENDING=true
RESTORE_ARCHIVE=''
DB_DSN=unused
ADMIN_EMAIL=''
sudo(){ printf 'bootstrap\n' >> "$TRACE"; }
resolve_native_admin_intent(){ printf 'resolve\n' >> "$TRACE"; printf 'admin@example.com\n'; }
ensure_admin(){ printf 'admin\n' >> "$TRACE"; test "$FAIL_ADMIN" = 0; }
nakpanel_write_platform_state(){ printf 'clear-gate:%s\n' "$1" >> "$TRACE"; }
clear_native_admin_intent(){ printf 'clear-intent\n' >> "$TRACE"; }
` + string(block) + "\nbootstrap_native_plans\n"
			command := exec.Command("bash", "-c", program)
			command.Env = append(os.Environ(), "TRACE="+trace, "FAIL_ADMIN="+failAdmin)
			output, runErr := command.CombinedOutput()
			actual, readErr := os.ReadFile(trace)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if failAdmin == "1" {
				if runErr == nil || string(actual) != "bootstrap\nresolve\nadmin\n" {
					t.Fatalf("failed admin cleared gate: %s %v %s", actual, runErr, output)
				}
			} else if runErr != nil || string(actual) != "bootstrap\nresolve\nadmin\nclear-gate:false\nclear-intent\n" {
				t.Fatalf("incorrect successful ordering: %s %v %s", actual, runErr, output)
			}
		})
	}
}

func TestVerifiedBundleRunsItsOwnInstallerWithMatchingPrivateAssets(t *testing.T) {
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?ms)^run_verified_bundle_installer\(\) \{\n.*?^\}`).Find(data)
	if len(block) == 0 {
		t.Fatal("authenticated bundle installer handoff missing")
	}
	root := t.TempDir()
	bundle := filepath.Join(root, "sealed")
	trace := filepath.Join(root, "args")
	if err := os.MkdirAll(filepath.Join(bundle, "deploy/install"), 0700); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$TRACE\"\nexit 37\n"
	if err := os.WriteFile(filepath.Join(bundle, "deploy/install/install.sh"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	program := `set -euo pipefail
MODE=fresh
REQUESTED_PHP_PROVIDER=sury
FORCE=0
ALLOW_DOWNGRADE=0
ASSUME_YES=1
ROLLBACK_SCHEMA=auto
RESTORE_ARCHIVE=''
BACKUP_KEY_FILE=''
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD_FILE=relative-admin-secret
` + string(block) + "\nrun_verified_bundle_installer\n"
	command := exec.Command("bash", "-c", program)
	command.Dir = root
	command.Env = append(os.Environ(), "TRACE="+trace, "BUNDLE_DIR="+bundle)
	output, runErr := command.CombinedOutput()
	exit, ok := runErr.(*exec.ExitError)
	if !ok || exit.ExitCode() != 37 {
		t.Fatalf("bundle status was not retained: %v %s", runErr, output)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--fresh\n", "--php-provider\nsury\n", "--bin-dir\n" + filepath.Join(bundle, "bin") + "\n", "--admin-password-file\n" + filepath.Join(canonicalRoot, "relative-admin-secret") + "\n"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("matching assets/arguments missing %q from %s", want, args)
		}
	}
	if strings.Contains(string(args), "--bundle\n") {
		t.Fatal("verified handoff would recursively restage bundle")
	}
}
