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
