//go:build linux

package ops

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestFileManagerRootDropsFilesystemIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to verify Linux FSUID confinement")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("nobody account is unavailable: %v", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "root-secret")
	if err := os.WriteFile(secret, []byte("root only"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore, err := assumeFileSystemIdentity(siteIdentity{uid: uid, gid: gid})
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := os.ReadFile(secret)
	restore()
	if readErr == nil {
		t.Fatal("tenant filesystem identity retained root access to a root-only file")
	}
	if _, err := os.ReadFile(secret); err != nil {
		t.Fatalf("root filesystem identity was not restored: %v", err)
	}
}
