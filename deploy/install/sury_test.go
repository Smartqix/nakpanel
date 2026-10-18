package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSuryVerifierPinsPublicKeyAndReleaseIdentity(t *testing.T) {
	script := "sury_verify.py"
	check := exec.Command("python3", script, "key", "sury-php-archive-keyring.gpg")
	output, err := check.CombinedOutput()
	if err != nil {
		t.Fatalf("pinned official key rejected: %s %v", output, err)
	}
	if !strings.Contains(string(output), "15058500A0235D97F5D10063B188E2B695BD4743") {
		t.Fatalf("wrong fingerprint: %s", output)
	}
	key, err := os.ReadFile("sury-php-archive-keyring.gpg")
	if err != nil {
		t.Fatal(err)
	}
	key[8] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.gpg")
	os.WriteFile(bad, key, 0600)
	if exec.Command("python3", script, "key", bad).Run() == nil {
		t.Fatal("modified key accepted")
	}
	base := "Origin: deb.sury.org\nSuite: resolute\nCodename: resolute\nArchitectures: amd64 arm64 armhf\n"
	for _, tc := range []struct {
		name, data, arch string
		ok               bool
	}{
		{"amd64", base, "amd64", true}, {"arm64", base, "arm64", true},
		{"wrong origin", strings.Replace(base, "deb.sury.org", "Ubuntu", 1), "amd64", false},
		{"wrong suite", strings.Replace(base, "Suite: resolute", "Suite: noble", 1), "arm64", false},
		{"wrong codename", strings.Replace(base, "Codename: resolute", "Codename: noble", 1), "arm64", false},
		{"missing host arch", strings.Replace(base, "amd64 arm64 armhf", "amd64", 1), "arm64", false},
		{"duplicate identity", base + "Origin: hostile\n", "amd64", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "Release")
			os.WriteFile(p, []byte(tc.data), 0600)
			output, err := exec.Command("python3", script, "release", p, tc.arch).CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v output=%s error=%v", tc.ok, output, err)
			}
		})
	}
}

func TestSuryIdentityTreatsOSMetadataAsData(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	data := "ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\nUNTRUSTED=$(touch " + marker + ")\n"
	path := filepath.Join(dir, "os-release")
	os.WriteFile(path, []byte(data), 0600)
	output, err := exec.Command("python3", "sury_verify.py", "identity", path).CombinedOutput()
	if err != nil {
		t.Fatalf("valid identity rejected: %s %v", output, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("OS metadata executed")
	}
	os.WriteFile(path, []byte("ID=$(touch "+marker+")\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n"), 0600)
	if exec.Command("python3", "sury_verify.py", "identity", path).Run() == nil {
		t.Fatal("injected OS identity accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("injected OS metadata executed")
	}
}

func TestSuryPreparationRejectsNonOptInBeforeAnyHostChange(t *testing.T) {
	for _, profile := range []string{"ubuntu-26.04-native", "ubuntu-24.04", "", "sury"} {
		output, err := exec.Command("bash", "sury.sh", "prepare", profile).CombinedOutput()
		if err == nil || !strings.Contains(string(output), "explicit ubuntu-26.04-sury profile required") {
			t.Fatalf("profile=%q output=%s error=%v", profile, output, err)
		}
	}
}

func TestSurySignatureStatusRequiresPinnedValidPrimary(t *testing.T) {
	const fingerprint = "15058500A0235D97F5D10063B188E2B695BD4743"
	valid := "[GNUPG:] VALIDSIG " + fingerprint + " 2026-10-14 1791936000 0 4 0 1 10 01 " + fingerprint + "\n"
	for _, tc := range []struct {
		name, status string
		ok           bool
	}{
		{"valid", valid, true},
		{"missing", "[GNUPG:] GOODSIG B188E2B695BD4743 Sury\n", false},
		{"wrong primary", strings.ReplaceAll(valid, fingerprint, strings.Repeat("A", 40)), false},
		{"expired", valid + "[GNUPG:] EXPKEYSIG B188E2B695BD4743 Sury\n", false},
		{"revoked", valid + "[GNUPG:] REVKEYSIG B188E2B695BD4743 Sury\n", false},
		{"bad", valid + "[GNUPG:] BADSIG B188E2B695BD4743 Sury\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "status")
			if err := os.WriteFile(p, []byte(tc.status), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("python3", "sury_verify.py", "status", p).CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v output=%s error=%v", tc.ok, output, err)
			}
		})
	}
}
