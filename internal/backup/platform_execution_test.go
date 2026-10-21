package backup

import (
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

func decodeExecutionPlatform(t *testing.T, extra map[string]any) (PlatformProvenance, error) {
	t.Helper()
	fixture := platformFixture("26.04")
	fixture.HostingPHPVersions = []string{"8.3", "8.4", "8.5"}
	fixture.RequiredPHPVersions = []string{"8.2", "8.3", "8.4", "8.5"}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "execution_php_versions")
	delete(fields, "execution_php_inventory_complete")
	for key, value := range extra {
		fields[key] = value
	}
	data, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var got PlatformProvenance
	err = json.Unmarshal(data, &got)
	return got, err
}

func TestSameProfileRestoreRetainsUnavailableOffersWithoutLosingExecution(t *testing.T) {
	source, err := decodeExecutionPlatform(t, map[string]any{"execution_php_versions": []string{"8.3"}, "execution_php_inventory_complete": true})
	if err != nil {
		t.Fatal(err)
	}
	target := platformFixture("26.04")
	target.HostingPHPVersions = []string{"8.3", "8.4", "8.5"}
	before, _ := json.Marshal(source)
	if err = CheckRestoreCompatibility(Manifest{Platform: &source}, target, RestoreSamePlatform); err != nil {
		t.Fatalf("stale unselected offer blocked equivalent recovery: %v", err)
	}
	after, _ := json.Marshal(source)
	if !bytes.Equal(before, after) || !reflect.DeepEqual(source.RequiredPHPVersions, []string{"8.2", "8.3", "8.4", "8.5"}) {
		t.Fatal("restore rewrote authenticated PHP intent")
	}

}

func TestSameProfilePHPRequirementsStayStrict(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  map[string]any
		target []string
		want   string
	}{
		{"selected unavailable on source", map[string]any{"execution_php_versions": []string{"8.2", "8.3"}, "execution_php_inventory_complete": true}, []string{"8.3", "8.4", "8.5"}, "PHP 8.2"},
		{"desired unavailable on source", map[string]any{"hosting_php_versions": []string{"8.3", "8.5"}, "execution_php_versions": []string{"8.3", "8.4"}, "execution_php_inventory_complete": true}, []string{"8.3", "8.5"}, "PHP 8.4"},
		{"source ready capability lost", map[string]any{"execution_php_versions": []string{"8.3"}, "execution_php_inventory_complete": true}, []string{"8.3", "8.4"}, "PHP 8.5"},
		{"legacy marker missing", nil, []string{"8.3", "8.4", "8.5"}, "PHP 8.2"},
		{"false marker conservative", map[string]any{"execution_php_versions": []string{"8.3"}, "execution_php_inventory_complete": false}, []string{"8.3", "8.4", "8.5"}, "PHP 8.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := decodeExecutionPlatform(t, tc.extra)
			if err != nil {
				t.Fatal(err)
			}
			target := platformFixture("26.04")
			target.HostingPHPVersions = tc.target
			err = CheckRestoreCompatibility(Manifest{Platform: &source}, target, RestoreSamePlatform)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("requirement not preserved: %v, want %s", err, tc.want)
			}
		})
	}
}

func TestExecutionPHPInventoryRejectsMalformedOrIncompleteMetadata(t *testing.T) {
	for _, extra := range []map[string]any{
		{"execution_php_inventory_complete": true},
		{"execution_php_inventory_complete": true, "execution_php_versions": nil},
		{"execution_php_inventory_complete": nil, "execution_php_versions": []string{}},
		{"execution_php_inventory_complete": "true", "execution_php_versions": []string{}},
		{"execution_php_inventory_complete": true, "execution_php_versions": []string{"8.3", "8.3"}},
		{"execution_php_inventory_complete": true, "execution_php_versions": []string{"8.3;bad"}},
		{"execution_php_inventory_complete": true, "execution_php_versions": "8.3"},
		{"execution_php_inventory_complete": true, "execution_php_versions": []string{"8.1"}},
		{"execution_php_inventory_complete": true, "execution_php_versions": []string{}, "php_inventory_complete": false},
	} {
		data, _ := json.Marshal(extra)
		t.Run(string(data), func(t *testing.T) {
			source, err := decodeExecutionPlatform(t, extra)
			if err == nil {
				err = CheckRestoreCompatibility(Manifest{Platform: &source}, platformFixture("26.04"), RestoreSamePlatform)
			}
			if err == nil {
				t.Fatal("malformed execution provenance accepted")
			}
		})
	}
}

func TestCompleteEmptyExecutionInventorySurvivesArchiveRoundTrip(t *testing.T) {
	source, err := decodeExecutionPlatform(t, map[string]any{"execution_php_versions": []string{}, "execution_php_inventory_complete": true})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(source)
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["execution_php_versions"]) != "[]" {
		t.Fatalf("complete empty inventory became missing: %s", fields["execution_php_versions"])
	}
	key := testKey(t)
	var archive bytes.Buffer
	writer, err := NewArchiveWriter(&archive, key)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, _ := json.Marshal(Manifest{FormatVersion: 1, Platform: &source})
	if err = writer.AddBytes(ManifestName, manifestData, 0600); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := ReadManifest(bytes.NewReader(archive.Bytes()), key)
	if err != nil {
		t.Fatal(err)
	}
	if roundtrip.Platform == nil || roundtrip.Platform.ExecutionPHPVersions == nil || !roundtrip.Platform.ExecutionPHPInventoryComplete {
		t.Fatal("authenticated empty execution inventory was lost")
	}
	target := platformFixture("26.04")
	target.HostingPHPVersions = []string{"8.3", "8.4", "8.5"}
	if err = CheckRestoreCompatibility(roundtrip, target, RestoreSamePlatform); err != nil {
		t.Fatal(err)
	}
}

func TestRunRestoreRequiresReadyCollectorForSourceCapabilitiesWithoutSelections(t *testing.T) {
	old := restoreEffectiveUID
	restoreEffectiveUID = func() int { return 0 }
	t.Cleanup(func() { restoreEffectiveUID = old })
	source, err := decodeExecutionPlatform(t, map[string]any{"required_php_versions": []string{}, "execution_php_versions": []string{}, "execution_php_inventory_complete": true})
	if err != nil {
		t.Fatal(err)
	}
	target := platformFixture("26.04")
	target.HostingPHPVersions = []string{"8.3", "8.4", "8.5"}
	key := testKey(t)
	var buf bytes.Buffer
	writer, err := NewArchiveWriter(&buf, key)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Manifest{FormatVersion: 1, Platform: &source})
	if err = writer.AddBytes(ManifestName, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	calls := t.TempDir()
	log := filepath.Join(calls, "mutations")
	for _, name := range []string{"systemctl", "mariadb", "runuser", "dropdb"} {
		if err = os.WriteFile(filepath.Join(calls, name), []byte("#!/bin/sh\necho mutation >> \"$MUTATION_LOG\"\nexit 97\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", calls)
	t.Setenv("MUTATION_LOG", log)
	opens := 0
	_, err = RunRestore(context.Background(), RestoreOptions{Key: key, OpenArchive: func() (io.ReadCloser, error) { opens++; return io.NopCloser(bytes.NewReader(buf.Bytes())), nil }, TargetPlatform: &target, Mode: RestoreSamePlatform})
	if err == nil || !strings.Contains(err.Error(), "authoritative ready PHP") {
		t.Fatalf("source-ready capability accepted without authoritative collector: %v", err)
	}
	if opens != 1 {
		t.Fatalf("opened extraction/integrity before readiness gate: %d", opens)
	}
	if _, err = os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("mutated before authoritative readiness")
	}
}

func TestCompleteExecutionDoesNotRelaxUnrecordedOrUnknownProfiles(t *testing.T) {
	for _, profiles := range [][2]string{{"", "ubuntu-26.04-sury"}, {"ubuntu-26.04-sury", ""}, {"", ""}, {"unknown-custom", "unknown-custom"}} {
		t.Run(profiles[0]+"->"+profiles[1], func(t *testing.T) {
			source, err := decodeExecutionPlatform(t, map[string]any{"execution_php_versions": []string{"8.3"}, "execution_php_inventory_complete": true})
			if err != nil {
				t.Fatal(err)
			}
			source.Profile = profiles[0]
			target := platformFixture("26.04")
			target.Profile = profiles[1]
			target.HostingPHPVersions = []string{"8.3", "8.4", "8.5"}
			if err = CheckRestoreCompatibility(Manifest{Platform: &source}, target, RestoreSamePlatform); err == nil {
				t.Fatalf("unknown profile relaxed historical offers: %v", err)
			}
		})
	}
}

func TestExecutionRelaxationRequiresFullRecordedProfileContract(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*PlatformProvenance, *PlatformProvenance)
	}{
		{"missing source codename", func(s, t *PlatformProvenance) { s.Codename = "" }},
		{"wrong source codename", func(s, t *PlatformProvenance) { s.Codename = "noble" }},
		{"missing source internal PHP", func(s, t *PlatformProvenance) { s.InternalPHPVersion = "" }},
		{"wrong source internal PHP", func(s, t *PlatformProvenance) { s.InternalPHPVersion = "8.3" }},
		{"missing target codename", func(s, t *PlatformProvenance) { t.Codename = "" }},
		{"wrong target codename", func(s, t *PlatformProvenance) { t.Codename = "noble" }},
		{"missing target internal PHP", func(s, t *PlatformProvenance) { t.InternalPHPVersion = "" }},
		{"wrong target internal PHP", func(s, t *PlatformProvenance) { t.InternalPHPVersion = "8.3" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := decodeExecutionPlatform(t, map[string]any{"execution_php_versions": []string{"8.3"}, "execution_php_inventory_complete": true})
			if err != nil {
				t.Fatal(err)
			}
			target := platformFixture("26.04")
			target.HostingPHPVersions = []string{"8.3", "8.4", "8.5"}
			tc.mutate(&source, &target)
			if err = CheckRestoreCompatibility(Manifest{Platform: &source}, target, RestoreSamePlatform); err == nil {
				t.Fatalf("incomplete/inconsistent known profile relaxed offers: %v", err)
			}
		})
	}
}
