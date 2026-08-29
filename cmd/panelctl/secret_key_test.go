package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

func TestRunSecretKeyInitializesStrictKeyringOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret-keys.json")
	var stdout bytes.Buffer
	if err := runSecretKey([]string{"init", "--path", path}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runSecretKey returned error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	keyring, err := serveradmin.LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring returned error: %v", err)
	}
	if keyring.ActiveVersion() != 1 {
		t.Fatalf("active version = %d", keyring.ActiveVersion())
	}
	if err := runSecretKey([]string{"init", "--path", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("second initialization replaced an existing key")
	}
}
