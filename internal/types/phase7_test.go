package types

import (
	"encoding/json"
	"testing"
)

func TestPhase7RestoreTypesRoundTrip(t *testing.T) {
	if OpRestoreBackup != "restore_backup" {
		t.Fatalf("OpRestoreBackup = %q, want restore_backup", OpRestoreBackup)
	}
	req := RestoreBackupReq{
		Domain:      "example.test",
		Username:    "npdemo",
		Docroot:     "/home/npdemo/public_html",
		ArchivePath: "/var/lib/nakpanel/backups/example.tar.gz",
		Databases:   []string{"np_demo"},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	var decoded RestoreBackupReq
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if decoded.Domain != req.Domain || decoded.ArchivePath != req.ArchivePath || len(decoded.Databases) != 1 {
		t.Fatalf("decoded = %#v, want %#v", decoded, req)
	}

	result := RestoreBackupResult{Domain: "example.test", RestoredFiles: 2, RestoredDatabases: []string{"np_demo"}}
	raw, err = json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal result returned error: %v", err)
	}
	if string(raw) == "{}" {
		t.Fatal("RestoreBackupResult encoded as empty object")
	}
}
