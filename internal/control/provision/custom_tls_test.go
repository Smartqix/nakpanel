package provision

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type failingCustomCertificateAgent struct{}

func (failingCustomCertificateAgent) InstallCustomCert(context.Context, types.InstallCustomCertReq) (types.Response, error) {
	return types.Response{}, errors.New("agent unavailable")
}

func TestInstallCustomCertArgsNeverContainPEM(t *testing.T) {
	t.Parallel()
	args := InstallCustomCertArgs{SiteID: 7, StagingPath: "/var/lib/nakpanel/tls-staging/custom-secret.json", Domain: "example.test", Username: "npdemo", PHPVersion: "8.3"}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(string(encoded), "CERTIFICATE") {
		t.Fatalf("River arguments contain PEM material: %s", encoded)
	}
}

func TestInstallCustomCertArgsUseBoundedRetries(t *testing.T) {
	opts := (InstallCustomCertArgs{}).InsertOpts()
	if opts.MaxAttempts != 3 {
		t.Fatalf("MaxAttempts = %d, want 3", opts.MaxAttempts)
	}
}

func TestInstallCustomCertWorkerDeletesSecretAndMarksTerminalFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-terminal.json")
	if err := os.WriteFile(path, []byte(`{"certificate_pem":"cert","private_key_pem":"key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	status := &recordingTLSStatusStore{}
	worker := NewInstallCustomCertWorker(failingCustomCertificateAgent{}, status, dir)
	err := worker.Work(context.Background(), &river.Job[InstallCustomCertArgs]{
		JobRow: &rivertype.JobRow{Attempt: 3, MaxAttempts: 3},
		Args:   InstallCustomCertArgs{SiteID: 7, StagingPath: path, Domain: "example.test"},
	})
	if err == nil || !strings.Contains(err.Error(), "agent unavailable") {
		t.Fatalf("Work error = %v, want agent failure", err)
	}
	if status.failedID != 7 || !strings.Contains(status.lastError, "agent unavailable") {
		t.Fatalf("failure status = id %d error %q", status.failedID, status.lastError)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("terminal staging secret still exists: %v", statErr)
	}
}

func TestInstallCustomCertWorkerPreservesSecretAndPendingStateForRetry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-retry.json")
	if err := os.WriteFile(path, []byte(`{"certificate_pem":"cert","private_key_pem":"key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	status := &recordingTLSStatusStore{}
	worker := NewInstallCustomCertWorker(failingCustomCertificateAgent{}, status, dir)
	err := worker.Work(context.Background(), &river.Job[InstallCustomCertArgs]{
		JobRow: &rivertype.JobRow{Attempt: 1, MaxAttempts: 3},
		Args:   InstallCustomCertArgs{SiteID: 7, StagingPath: path, Domain: "example.test"},
	})
	if err == nil || !strings.Contains(err.Error(), "agent unavailable") {
		t.Fatalf("Work error = %v, want agent failure", err)
	}
	if status.failedID != 0 || status.lastError != "" {
		t.Fatalf("retryable attempt changed TLS status: id %d error %q", status.failedID, status.lastError)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("retryable attempt removed staging secret: %v", statErr)
	}
}

func TestSweepCustomTLSStagingPreservesActiveJobFiles(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "custom-active.json")
	stale := filepath.Join(dir, "custom-stale.json")
	for _, path := range []string{protected, stale} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-25 * time.Hour)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT args->>'staging_path'\nFROM river_job\nWHERE kind = 'install_custom_cert'\n  AND state IN ('available', 'pending', 'retryable', 'running', 'scheduled')")).
		WillReturnRows(sqlmock.NewRows([]string{"staging_path"}).AddRow(protected))
	if err := SweepCustomTLSStagingForJobs(context.Background(), db, dir, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("active staging file was removed: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("abandoned staging file still exists: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReadStagedCustomCertificateRequiresPrivateRegularFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-test.json")
	if err := os.WriteFile(path, []byte(`{"certificate_pem":"cert","private_key_pem":"key"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readStagedCustomCertificate(path); err == nil || !strings.Contains(err.Error(), "private regular file") {
		t.Fatalf("error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStagedCustomCertificate(path); err != nil {
		t.Fatalf("read private staging file: %v", err)
	}
}

func TestStagingFileInheritsDirectoryOwner(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-owner.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setStagingFileOwner(dir, path); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	dirOwner := reflect.ValueOf(dirInfo.Sys()).Elem().FieldByName("Uid")
	fileOwner := reflect.ValueOf(fileInfo.Sys()).Elem().FieldByName("Uid")
	if dirOwner.IsValid() && fileOwner.IsValid() && dirOwner.Uint() != fileOwner.Uint() {
		t.Fatalf("staging owner uid=%d, directory uid=%d", fileOwner.Uint(), dirOwner.Uint())
	}
}
