package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type reliabilityRestorer func(context.Context, string, []byte) error

func (r reliabilityRestorer) RestoreDatabase(ctx context.Context, name string, dump []byte) error {
	return r(ctx, name, dump)
}

type reliabilityOwnership func(context.Context, string, string) error

func (o reliabilityOwnership) ChownRecursive(ctx context.Context, path, username string) error {
	return o(ctx, path, username)
}

func restoreReliabilityFixture(t *testing.T, databases []string) (string, types.RestoreBackupReq) {
	t.Helper()
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	docroot := filepath.Join(homeRoot, "npdemo", "public_html")
	source := filepath.Join(homeRoot, "npdemo", "source")
	for _, dir := range []string{docroot, filepath.Join(source, "empty", "nested")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{filepath.Join(docroot, "index.php"): "original", filepath.Join(source, "index.php"): "restored", filepath.Join(source, "wp-config.php"): "private"} {
		if err := os.WriteFile(name, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	backup, err := NewBackupProvisioner(BackupProvisionerOptions{HomeRoot: homeRoot, OutputDir: filepath.Join(root, "backups"), DatabaseDumper: &fakeDatabaseDumper{}}).CreateBackup(context.Background(), types.CreateBackupReq{Domain: "example.test", Username: "npdemo", Docroot: source, Databases: databases})
	if err != nil {
		t.Fatal(err)
	}
	return homeRoot, types.RestoreBackupReq{Domain: "example.test", Username: "npdemo", Docroot: docroot, ArchivePath: backup.ArchivePath, Databases: databases}
}

func assertOriginalRestoreFiles(t *testing.T, req types.RestoreBackupReq) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(req.Docroot, "index.php"))
	if err != nil || string(data) != "original" {
		t.Fatalf("live index = %q, err = %v; want original", data, err)
	}
}

func TestRestoreDatabaseFailureKeepsOriginalFilesLive(t *testing.T) {
	homeRoot, req := restoreReliabilityFixture(t, []string{"np_demo", "np_second"})
	restorer := reliabilityRestorer(func(_ context.Context, name string, _ []byte) error {
		assertOriginalRestoreFiles(t, req)
		if name == "np_demo" {
			return nil
		}
		return errors.New("database import failed")
	})
	_, err := NewRestoreProvisioner(RestoreProvisionerOptions{HomeRoot: homeRoot, DatabaseRestorer: restorer}).RestoreBackup(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "database import failed") || !strings.Contains(err.Error(), "may have partially committed") {
		t.Fatalf("restore error = %v", err)
	}
	assertOriginalRestoreFiles(t, req)
}

func TestRestorePublishFailureRestoresOriginalDirectory(t *testing.T) {
	homeRoot, req := restoreReliabilityFixture(t, []string{"np_demo"})
	var staging string
	p := NewRestoreProvisioner(RestoreProvisionerOptions{
		HomeRoot: homeRoot,
		OwnershipManager: reliabilityOwnership(func(_ context.Context, root, _ string) error {
			staging = root
			return nil
		}),
		DatabaseRestorer: reliabilityRestorer(func(context.Context, string, []byte) error {
			// Simulate staging storage disappearing after preparation but before publish.
			return os.RemoveAll(staging)
		}),
	})
	_, err := p.RestoreBackup(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "publish restored docroot") {
		t.Fatalf("restore error = %v", err)
	}
	assertOriginalRestoreFiles(t, req)
}

func TestRestoreMissingRestorerKeepsOriginalFilesLive(t *testing.T) {
	homeRoot, req := restoreReliabilityFixture(t, []string{"np_demo"})
	_, err := NewRestoreProvisioner(RestoreProvisionerOptions{HomeRoot: homeRoot}).RestoreBackup(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "restorer is not configured") {
		t.Fatalf("restore error = %v", err)
	}
	assertOriginalRestoreFiles(t, req)
}

func TestRestoreOwnershipFailureKeepsOriginalFilesAndSkipsImports(t *testing.T) {
	homeRoot, req := restoreReliabilityFixture(t, []string{"np_demo"})
	calls := 0
	p := NewRestoreProvisioner(RestoreProvisionerOptions{
		HomeRoot: homeRoot,
		DatabaseRestorer: reliabilityRestorer(func(context.Context, string, []byte) error {
			calls++
			return nil
		}),
		OwnershipManager: reliabilityOwnership(func(_ context.Context, staging, _ string) error {
			assertOriginalRestoreFiles(t, req)
			if staging == req.Docroot {
				t.Fatal("ownership changed live files before restore completed")
			}
			return errors.New("chown failed")
		}),
	})
	_, err := p.RestoreBackup(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "chown failed") {
		t.Fatalf("restore error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("database imports = %d, want none", calls)
	}
	assertOriginalRestoreFiles(t, req)
}

func TestRestoreRejectsMissingRequestedDumpBeforeImports(t *testing.T) {
	homeRoot, req := restoreReliabilityFixture(t, []string{"np_demo"})
	req.Databases = []string{"np_demo", "np_missing"}
	calls := 0
	restorer := reliabilityRestorer(func(context.Context, string, []byte) error { calls++; return nil })
	_, err := NewRestoreProvisioner(RestoreProvisionerOptions{HomeRoot: homeRoot, DatabaseRestorer: restorer}).RestoreBackup(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "np_missing") {
		t.Fatalf("restore error = %v, want missing requested database", err)
	}
	if calls != 0 {
		t.Fatalf("database imports = %d, want none", calls)
	}
	assertOriginalRestoreFiles(t, req)
}

func TestBackupRestorePreservesEmptyDirectories(t *testing.T) {
	homeRoot, req := restoreReliabilityFixture(t, nil)
	if _, err := NewRestoreProvisioner(RestoreProvisionerOptions{HomeRoot: homeRoot}).RestoreBackup(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(req.Docroot, "empty", "nested"))
	if err != nil || !info.IsDir() {
		t.Fatalf("restored empty directory missing: %v", err)
	}
}

func TestRestoreSameTimestampPreservesEachRecoveryTree(t *testing.T) {
	homeRoot, req := restoreReliabilityFixture(t, nil)
	p := NewRestoreProvisioner(RestoreProvisionerOptions{HomeRoot: homeRoot, Now: func() time.Time { return time.Unix(1234, 0) }})
	first, err := p.RestoreBackup(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.RestoreBackup(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.PreviousDocroot == second.PreviousDocroot {
		t.Fatal("restore retries reused the same recovery path")
	}
	data, err := os.ReadFile(filepath.Join(first.PreviousDocroot, "index.php"))
	if err != nil || string(data) != "original" {
		t.Fatalf("first recovery index = %q, error = %v", data, err)
	}
}
