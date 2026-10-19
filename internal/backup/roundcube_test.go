package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundcubeSQLiteEncryptedRoundTripRestoresContactsPreferences(t *testing.T) {
	binary, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 not installed")
	}
	dir := t.TempDir()
	snapshot, destination := filepath.Join(dir, "snapshot.sqlite"), filepath.Join(dir, "installed.sqlite")
	if out, err := exec.Command(binary, snapshot, `CREATE TABLE users(user_id INTEGER PRIMARY KEY, preferences TEXT); CREATE TABLE contacts(user_id INT,email TEXT); INSERT INTO users VALUES(1,'serialized-preference-canary'); INSERT INTO contacts VALUES(1,'contact-canary@example.test');`).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %s %v", out, err)
	}
	if out, err := exec.Command(binary, destination, `CREATE TABLE stale(value TEXT);`).CombinedOutput(); err != nil {
		t.Fatalf("installed fixture: %s %v", out, err)
	}
	if err := os.Chmod(destination, 0660); err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	var encrypted bytes.Buffer
	w, err := NewArchiveWriter(&encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, _ := json.Marshal(Manifest{FormatVersion: 2, RoundcubeSQLitePath: NativeRoundcubeSQLitePath})
	if err = w.AddBytes(ManifestName, manifestJSON, 0600); err != nil {
		t.Fatal(err)
	}
	if err = w.AddFileFrom(RoundcubeSQLiteDumpName, snapshot); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes(), []byte("serialized-preference-canary")) || bytes.Contains(encrypted.Bytes(), []byte("contact-canary")) {
		t.Fatal("SQLite contents escaped archive encryption")
	}
	manifest, err := ReadManifest(bytes.NewReader(encrypted.Bytes()), key)
	if err != nil || manifest.RoundcubeSQLitePath != NativeRoundcubeSQLitePath {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	reader, err := NewArchiveReader(bytes.NewReader(encrypted.Bytes()), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	header, err := reader.Next()
	if err != nil || header.Name != RoundcubeSQLiteDumpName {
		t.Fatalf("header=%+v err=%v", header, err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, payload, 0600); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.WriteFile(destination+suffix, []byte("obsolete target journal"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := restoreRoundcubeSQLite(context.Background(), snapshot, destination); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(destination + suffix); !os.IsNotExist(err) {
			t.Fatalf("stale %s survived", suffix)
		}
	}
	out, err := exec.Command(binary, "-readonly", destination, `SELECT preferences||'|'||email FROM users JOIN contacts USING(user_id);`).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "serialized-preference-canary|contact-canary@example.test") {
		t.Fatalf("restored canaries: %s %v", out, err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0660 {
		t.Fatalf("native SQLite permissions changed: %v %v", info, err)
	}
}
func TestRoundcubeSQLiteDestinationRejectsArbitraryPaths(t *testing.T) {
	for _, path := range []string{"/etc/shadow", "/tmp/roundcube.sqlite", "/var/lib/roundcube/../other.sqlite"} {
		if _, err := RoundcubeSQLiteDestination(path, RestoreSamePlatform); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	got, err := RoundcubeSQLiteDestination("/var/lib/roundcube/db/roundcube", RestoreForwardMigration)
	if err != nil || got != NativeRoundcubeSQLitePath {
		t.Fatalf("got=%s err=%v", got, err)
	}
}

func TestForwardRoundcubeRestoreRequiresEncryptedSQLiteSnapshotMetadata(t *testing.T) {
	for _, source := range []Manifest{{FormatVersion: 1}, {FormatVersion: 2}, {FormatVersion: 1, RoundcubeSQLitePath: NativeRoundcubeSQLitePath}, {FormatVersion: 2, RoundcubeSQLitePath: "/tmp/foreign.sqlite"}} {
		err := CheckRoundcubeRestoreTarget(source, PlatformProvenance{}, RestoreForwardMigration)
		if err == nil || !strings.Contains(err.Error(), "forward-migration requires") {
			t.Fatalf("source=%+v err=%v", source, err)
		}
	}
	// Existing same-platform format-1 recovery remains available.
	if err := CheckRoundcubeRestoreTarget(Manifest{FormatVersion: 1}, PlatformProvenance{}, RestoreSamePlatform); err != nil {
		t.Fatal(err)
	}
}

func TestArchivePreflightRequiresUsableAdvertisedRoundcubeSnapshot(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 unavailable")
	}
	path := filepath.Join(t.TempDir(), "roundcube.sqlite")
	if out, err := exec.Command(sqlite, path, "CREATE TABLE contacts(email TEXT); INSERT INTO contacts VALUES('archive-canary@example.test');").CombinedOutput(); err != nil {
		t.Fatalf("sqlite fixture: %s %v", out, err)
	}
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		entries [][]byte
		want    string
	}{
		{"missing", nil, "missing"}, {"invalid", [][]byte{[]byte("not a SQLite database")}, "integrity"},
		{"empty", [][]byte{nil}, "integrity"},
		{"duplicate", [][]byte{valid, valid}, "duplicate"}, {"valid", [][]byte{valid}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey(t)
			var archive bytes.Buffer
			w, err := NewArchiveWriter(&archive, key)
			if err != nil {
				t.Fatal(err)
			}
			m, _ := json.Marshal(Manifest{FormatVersion: 2, RoundcubeSQLitePath: NativeRoundcubeSQLitePath})
			if err := w.AddBytes(ManifestName, m, 0600); err != nil {
				t.Fatal(err)
			}
			for _, data := range tc.entries {
				if err := w.AddBytes(RoundcubeSQLiteDumpName, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			err = CheckArchiveIntegrity(bytes.NewReader(archive.Bytes()), key)
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
