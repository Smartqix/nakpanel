package ops

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerBackupMariaDBIncludesRoutinesEventsAndTriggers(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mariadb-dump"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	path := filepath.Join(dir, "tenant.sql.gz")
	p := NewServerBackupProvisioner(ServerBackupProvisionerOptions{})
	if err := p.dumpMariaDB(context.Background(), "tenant", path); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	body, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--single-transaction", "--routines", "--events", "--triggers", "--databases", "tenant"} {
		if !strings.Contains(string(body), flag+"\n") {
			t.Fatalf("dump lacks %s: %s", flag, body)
		}
	}
}

func TestBackupReadyInventoryUsesTrustedProfileExtensionsAndFPM(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		unready       bool
		mutate        func(*fakeRuntimeCapabilityProbe)
	}{
		{name: "stray 8.4 outside native profile", version: "8.4"},
		{name: "ready native", version: "8.5"},
		{name: "missing required extension", version: "8.5", unready: true, mutate: func(p *fakeRuntimeCapabilityProbe) {
			p.outputs[runtimeCommandKey("/usr/bin/php8.5", "-m")] = []byte("OpenSSL\n")
		}},
		{name: "isolated FPM startup failure", version: "8.5", unready: true, mutate: func(p *fakeRuntimeCapabilityProbe) {
			p.startErrors[runtimeCommandKey("/usr/sbin/php-fpm8.5", "-F", "-y")] = errors.New("cannot start isolated FPM")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := filepath.Join(t.TempDir(), "platform.json")
			if err := os.WriteFile(profile, []byte(`{"os_id":"ubuntu","version_id":"26.04","codename":"resolute","architecture":"arm64","profile":"ubuntu-26.04-native","internal_php_version":"8.5","hosting_php_versions":["8.5"],"bootstrap_pending":false}`), 0600); err != nil {
				t.Fatal(err)
			}
			probe := completeRuntimeProbe("8.4", "8.5")
			if tc.mutate != nil {
				tc.mutate(probe)
			}
			ready, err := readyBackupPHPVersions(context.Background(), probe, installedPHPRuntimeResolver{path: profile, ownerUID: uint32(os.Getuid())})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, v := range ready {
				if v == tc.version {
					found = true
				}
			}
			want := tc.version == "8.5" && !tc.unready
			if found != want {
				t.Fatalf("ready=%v version=%s wantPresent=%t", ready, tc.version, want)
			}
		})
	}
}
