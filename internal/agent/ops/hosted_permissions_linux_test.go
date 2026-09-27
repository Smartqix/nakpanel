//go:build linux

package ops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecureHostedDocumentTreeKeepsWordPressConfigPrivate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to exercise hosted file ownership")
	}
	root := t.TempDir()
	config := filepath.Join(root, "wp-config.php")
	index := filepath.Join(root, "index.php")
	if err := os.WriteFile(config, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := secureHostedDocumentTree(root); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		path string
		want os.FileMode
	}{{config, 0o600}, {index, 0o640}} {
		info, err := os.Stat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != item.want {
			t.Errorf("%s mode = %04o, want %04o", filepath.Base(item.path), got, item.want)
		}
	}
}
