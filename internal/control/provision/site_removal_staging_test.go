package provision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemovalStagingRejectsUnconfinedOrPublicFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "custom-outside.json")
	public := filepath.Join(root, "custom-public.json")
	link := filepath.Join(root, "custom-link.json")
	for _, path := range []string{outside, public} {
		if err := os.WriteFile(path, []byte("private-fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(public, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{outside, public, link} {
		if err := removePrivateCertificateStaging(root, path); err == nil {
			t.Fatalf("unsafe staging accepted: %s", path)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("unsafe file changed", err)
		}
	}
}
