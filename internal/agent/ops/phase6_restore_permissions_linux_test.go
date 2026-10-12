//go:build linux

package ops

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestRestorePreparesHostedPermissionsBeforeDatabaseImport(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to exercise hosted file ownership")
	}
	group, err := user.LookupGroup("www-data")
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		t.Fatal(err)
	}
	homeRoot, req := restoreReliabilityFixture(t, []string{"np_demo"})
	var staging string
	check := func(root string) {
		t.Helper()
		for _, item := range []struct {
			name string
			mode os.FileMode
		}{{"index.php", 0o640}, {"wp-config.php", 0o600}} {
			info, err := os.Stat(filepath.Join(root, item.name))
			if err != nil {
				t.Fatal(err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if info.Mode().Perm() != item.mode || int(stat.Gid) != gid {
				t.Errorf("%s mode=%04o group=%d, want mode=%04o www-data=%d", item.name, info.Mode().Perm(), stat.Gid, item.mode, gid)
			}
		}
		info, err := os.Stat(root)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSetgid == 0 {
			t.Errorf("document root mode=%v, want setgid 0750", info.Mode())
		}
	}
	p := NewRestoreProvisioner(RestoreProvisionerOptions{
		HomeRoot: homeRoot,
		OwnershipManager: reliabilityOwnership(func(_ context.Context, root, _ string) error {
			staging = root
			return filepath.Walk(root, func(name string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				return os.Chown(name, os.Geteuid(), 0)
			})
		}),
		DatabaseRestorer: reliabilityRestorer(func(context.Context, string, []byte) error {
			assertOriginalRestoreFiles(t, req)
			check(staging)
			return nil
		}),
	})
	if _, err := p.RestoreBackup(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	check(req.Docroot)
}
