package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func platformFixture(version string) PlatformProvenance {
	p := PlatformProvenance{OSID: "ubuntu", VersionID: version, Codename: "noble", Architecture: "amd64", Profile: "ubuntu-24.04", InternalPHPVersion: "8.3", HostingPHPVersions: []string{"8.3", "8.4"}, RequiredPHPVersions: []string{"8.3"}, PHPInventoryComplete: true, PostgresServerVersion: "16.11", PostgresDumpVersion: "16.11", PostgresRestoreVersion: "16.11", MariaDBServerVersion: "10.11.14", MariaDBDumpVersion: "10.11.14", MariaDBClientVersion: "10.11.14", StalwartVersion: "0.15.4"}
	if version == "26.04" {
		p.Profile = "ubuntu-26.04-native"
		p.Codename = "resolute"
		p.InternalPHPVersion = "8.5"
		p.PostgresServerVersion = "18.0"
		p.PostgresDumpVersion = "18.0"
		p.PostgresRestoreVersion = "18.0"
		p.MariaDBServerVersion = "11.8.3"
		p.MariaDBDumpVersion = "11.8.3"
		p.MariaDBClientVersion = "11.8.3"
	}
	return p
}
func TestPlatformManifestRoundTripAndLegacy(t *testing.T) {
	key := testKey(t)
	for _, p := range []*PlatformProvenance{nil, ptrPlatform(platformFixture("24.04"))} {
		m := Manifest{FormatVersion: 1, Platform: p}
		data, _ := json.Marshal(m)
		var buf bytes.Buffer
		w, err := NewArchiveWriter(&buf, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = w.AddBytes(ManifestName, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := ReadManifest(bytes.NewReader(buf.Bytes()), key)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Platform, p) {
			t.Fatalf("platform=%+v want %+v", got.Platform, p)
		}
	}
}
func ptrPlatform(p PlatformProvenance) *PlatformProvenance { return &p }
func TestRestoreCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   RestoreMode
		source *PlatformProvenance
		target PlatformProvenance
		mail   bool
		want   string
	}{
		{"same release", "", ptrPlatform(platformFixture("24.04")), platformFixture("24.04"), true, ""},
		{"legacy 24", RestoreSamePlatform, nil, platformFixture("24.04"), true, ""},
		{"legacy cannot assume 26", RestoreSamePlatform, nil, platformFixture("26.04"), true, "legacy"},
		{"legacy forward", RestoreForwardMigration, nil, platformFixture("26.04"), false, "provenance"},
		{"default blocks cross release", "", ptrPlatform(platformFixture("24.04")), platformFixture("26.04"), false, "same-platform"},
		{"qualified shape forward", RestoreForwardMigration, ptrPlatform(platformFixture("24.04")), platformFixture("26.04"), true, ""},
		{"no backward migration", RestoreForwardMigration, ptrPlatform(platformFixture("26.04")), platformFixture("24.04"), false, "direction"},
		{"bad mode", RestoreMode("anything"), ptrPlatform(platformFixture("24.04")), platformFixture("24.04"), false, "mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckRestoreCompatibility(Manifest{Platform: tc.source, IncludeMailData: tc.mail}, tc.target, tc.mode)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %s", err, tc.want)
			}
		})
	}
}
func TestRestoreCompatibilityRejectsUnavailableRequirements(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*PlatformProvenance, *PlatformProvenance)
		want   string
	}{
		{"foreign OS", func(s, t *PlatformProvenance) { t.OSID = "debian" }, "OS"},
		{"foreign arch", func(s, t *PlatformProvenance) { t.Architecture = "arm64" }, "architecture"},
		{"missing php83", func(s, t *PlatformProvenance) { t.HostingPHPVersions = []string{"8.5"} }, "PHP 8.3"},
		{"missing php84", func(s, t *PlatformProvenance) {
			s.RequiredPHPVersions = []string{"8.4"}
			t.HostingPHPVersions = []string{"8.3", "8.5"}
		}, "PHP 8.4"},
		{"missing inventory", func(s, t *PlatformProvenance) { s.PHPInventoryComplete = false }, "inventory"},
		{"postgres backwards", func(s, t *PlatformProvenance) { t.PostgresServerVersion = "15.9" }, "PostgreSQL"},
		{"old pg restore", func(s, t *PlatformProvenance) { t.PostgresRestoreVersion = "15.9" }, "pg_restore"},
		{"dump newer than target", func(s, t *PlatformProvenance) { s.PostgresDumpVersion = "19.1" }, "PostgreSQL"},
		{"mariadb backwards", func(s, t *PlatformProvenance) { t.MariaDBServerVersion = "10.6.1" }, "MariaDB"},
		{"old maria client", func(s, t *PlatformProvenance) { t.MariaDBClientVersion = "10.5.1" }, "client"},
		{"unknown dump", func(s, t *PlatformProvenance) { s.MariaDBDumpVersion = "" }, "provenance"},
		{"mail mismatch", func(s, t *PlatformProvenance) { t.StalwartVersion = "0.16.0" }, "Stalwart"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, tgt := platformFixture("24.04"), platformFixture("26.04")
			tc.mutate(&s, &tgt)
			err := CheckRestoreCompatibility(Manifest{Platform: &s, IncludeMailData: true}, tgt, RestoreForwardMigration)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}
func TestRestoreNeverOverwritesTargetPlatform(t *testing.T) {
	for _, name := range []string{"files/etc/nakpanel/platform.json", "files/etc/nakpanel/./platform.json"} {
		// This entry would fail as an unprivileged user or modify the host if extracted.
		if err := extractTreeEntry(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: 3}, strings.NewReader("bad")); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRunRestoreCompatibilityBeforeMutation(t *testing.T) {
	oldUID := restoreEffectiveUID
	restoreEffectiveUID = func() int { return 0 }
	t.Cleanup(func() { restoreEffectiveUID = oldUID })
	for _, tc := range []struct {
		name, want string
		mutate     func(*PlatformProvenance)
	}{
		{"foreign architecture", "architecture", func(p *PlatformProvenance) { p.Architecture = "arm64" }},
		{"foreign OS", "OS", func(p *PlatformProvenance) { p.OSID = "debian" }},
		{"missing source PHP", "PHP 8.3", func(p *PlatformProvenance) { p.HostingPHPVersions = []string{"8.5"} }},
		{"older database", "PostgreSQL", func(p *PlatformProvenance) { p.PostgresServerVersion = "15.1" }},
		{"incompatible mail", "Stalwart", func(p *PlatformProvenance) { p.StalwartVersion = "0.16.0" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey(t)
			s, tgt := platformFixture("24.04"), platformFixture("26.04")
			tc.mutate(&tgt)
			var buf bytes.Buffer
			w, _ := NewArchiveWriter(&buf, key)
			data, _ := json.Marshal(Manifest{FormatVersion: 1, Platform: &s, IncludeMailData: true})
			_ = w.AddBytes(ManifestName, data, 0600)
			_ = w.Close()
			calls := t.TempDir()
			for _, name := range []string{"systemctl", "runuser", "mariadb", "dropdb", "createdb"} {
				if err := os.WriteFile(filepath.Join(calls, name), []byte("#!/bin/sh\necho mutation >> \"$MUTATION_LOG\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", calls)
			t.Setenv("MUTATION_LOG", filepath.Join(calls, "mutations"))
			opens := 0
			_, err := RunRestore(context.Background(), RestoreOptions{Key: key, OpenArchive: func() (io.ReadCloser, error) { opens++; return io.NopCloser(bytes.NewReader(buf.Bytes())), nil }, TargetPlatform: &tgt, Mode: RestoreForwardMigration, ReadyPHPVersions: func(context.Context) ([]string, error) { return tgt.HostingPHPVersions, nil }, RegenerateTargetConfiguration: func(context.Context) error { t.Fatal("regeneration before compatibility"); return nil }})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %s", err, tc.want)
			}
			if opens != 1 {
				t.Fatalf("extraction opened before preflight: %d", opens)
			}
			if _, err := os.Stat(filepath.Join(calls, "mutations")); !os.IsNotExist(err) {
				t.Fatal("stop/drop/query mutation occurred")
			}
		})
	}
}

func TestForwardRestoreSkipsSourceNativeConfiguration(t *testing.T) {
	for _, name := range []string{"files/etc/nakpanel/platform.json", "files/etc/roundcube/config.inc.php", "files/etc/nginx/sites-enabled/mail.conf", "files/etc/nginx/sites-available/example.conf", "files/etc/systemd/system/nakpanel-proftpd.service", "files/etc/systemd/system/multi-user.target.wants/nakpanel-proftpd.service"} {
		if !preserveTargetNativeEntry(name, RestoreForwardMigration) {
			t.Fatalf("would replace target-native entry %s", name)
		}
	}
	if preserveTargetNativeEntry("files/home/tenant/index.php", RestoreForwardMigration) {
		t.Fatal("tenant tree skipped")
	}
	if preserveTargetNativeEntry("files/etc/nginx/sites-available/example.conf", RestoreSamePlatform) {
		t.Fatal("changed legacy restoration")
	}
}

func TestCompatibilityRejectsIncompleteForwardProfile(t *testing.T) {
	s, tgt := platformFixture("24.04"), platformFixture("26.04")
	tgt.Profile = "unknown"
	if err := CheckRestoreCompatibility(Manifest{Platform: &s}, tgt, RestoreForwardMigration); err == nil {
		t.Fatal("unknown profile accepted")
	}
}
func TestCheckArchiveIntegrityDetectsTruncatedTailBeforeRestore(t *testing.T) {
	key := testKey(t)
	var buf bytes.Buffer
	w, _ := NewArchiveWriter(&buf, key)
	_ = w.AddBytes(ManifestName, []byte(`{"format_version":1}`), 0600)
	_ = w.Close()
	if err := CheckArchiveIntegrity(bytes.NewReader(buf.Bytes()), key); err != nil {
		t.Fatal(err)
	}
	if err := CheckArchiveIntegrity(bytes.NewReader(buf.Bytes()[:buf.Len()-5]), key); err == nil {
		t.Fatal("truncated archive accepted")
	}
}

func TestForwardAgentEnvKeepsNativeSelectorAndSourceSettings(t *testing.T) {
	source := []byte("# recovered settings\nNAKPANEL_INTERNAL_PHP_VERSION=8.3\nNAKPANEL_VALKEY_IMAGE=registry.test/cache@sha256:abc\nNAKPANEL_FTPS_PUBLIC_ADDRESS=192.0.2.1\n")
	got, err := forwardAgentEnvironment(source, "8.5")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "=8.3") || !strings.Contains(string(got), "NAKPANEL_INTERNAL_PHP_VERSION=8.5\n") || !strings.Contains(string(got), "NAKPANEL_FTPS_PUBLIC_ADDRESS=192.0.2.1\n") {
		t.Fatalf("wrong recovered env %s", got)
	}
}

func TestRunRestoreRequiresAuthoritativeReadyPHPBeforeMutation(t *testing.T) {
	old := restoreEffectiveUID
	restoreEffectiveUID = func() int { return 0 }
	t.Cleanup(func() { restoreEffectiveUID = old })
	for _, name := range []string{"stray-binary", "profile-disallowed", "missing-extension", "isolated-fpm-not-ready"} {
		t.Run(name, func(t *testing.T) {
			key := testKey(t)
			source, target := platformFixture("24.04"), platformFixture("26.04")
			source.RequiredPHPVersions = []string{"8.4"}
			target.HostingPHPVersions = []string{"8.4", "8.5"}
			var buf bytes.Buffer
			w, _ := NewArchiveWriter(&buf, key)
			data, _ := json.Marshal(Manifest{FormatVersion: 1, Platform: &source})
			_ = w.AddBytes(ManifestName, data, 0600)
			_ = w.Close()
			calls := t.TempDir()
			for _, binary := range []string{"systemctl", "mariadb", "runuser", "dropdb"} {
				if err := os.WriteFile(filepath.Join(calls, binary), []byte("#!/bin/sh\necho mutation >> \"$MUTATION_LOG\"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", calls)
			t.Setenv("MUTATION_LOG", filepath.Join(calls, "mutations"))
			opens := 0
			_, err := RunRestore(context.Background(), RestoreOptions{Key: key, OpenArchive: func() (io.ReadCloser, error) { opens++; return io.NopCloser(bytes.NewReader(buf.Bytes())), nil }, TargetPlatform: &target, Mode: RestoreForwardMigration, ReadyPHPVersions: func(context.Context) ([]string, error) { return []string{"8.5"}, nil }, RegenerateTargetConfiguration: func(context.Context) error { t.Fatal("mutated before readiness"); return nil }})
			if err == nil || !strings.Contains(err.Error(), "PHP 8.4") {
				t.Fatalf("err=%v", err)
			}
			if opens != 1 {
				t.Fatalf("extraction opened %d times", opens)
			}
			if _, err := os.Stat(filepath.Join(calls, "mutations")); !os.IsNotExist(err) {
				t.Fatal("service/database command ran")
			}
		})
	}
}

func TestRestoreCompatibilitySuryProfileIsExplicit(t *testing.T) {
	native := platformFixture("26.04")
	sury := native
	sury.Profile = "ubuntu-26.04-sury"
	sury.HostingPHPVersions = []string{"8.3", "8.4", "8.5"}
	if err := CheckRestoreCompatibility(Manifest{Platform: &native}, sury, RestoreSamePlatform); err == nil {
		t.Fatal("ordinary native-to-Sury restore accepted")
	}
	if err := CheckRestoreCompatibility(Manifest{Platform: &sury}, native, RestoreSamePlatform); err == nil {
		t.Fatal("ordinary Sury-to-native restore accepted")
	}
	if err := CheckRestoreCompatibility(Manifest{Platform: &sury}, sury, RestoreSamePlatform); err != nil {
		t.Fatal(err)
	}
	source := platformFixture("24.04")
	source.RequiredPHPVersions = []string{"8.3", "8.4"}
	if err := CheckRestoreCompatibility(Manifest{Platform: &source}, sury, RestoreForwardMigration); err != nil {
		t.Fatal(err)
	}
}
