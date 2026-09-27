package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeWordPressDatabaseRemover struct {
	state       WordPressDatabaseState
	removeCalls int
	err         error
}

func (f *fakeWordPressDatabaseRemover) Inspect(context.Context, int64, string, string) (WordPressDatabaseState, error) {
	return f.state, f.err
}

func (f *fakeWordPressDatabaseRemover) Remove(context.Context, int64, string, string) (WordPressDatabaseState, error) {
	f.removeCalls++
	if f.err != nil {
		return f.state, f.err
	}
	f.state = WordPressDatabaseState{}
	return f.state, nil
}

type wordpressRemovalFixture struct {
	provisioner  *WordPressProvisioner
	documentRoot string
	spec         types.WordPressSiteSpec
	owned        map[string][2]int
}

func newWordPressRemovalFixture(t *testing.T) wordpressRemovalFixture {
	t.Helper()
	homeRoot := filepath.Join(t.TempDir(), "home")
	spec := wordpressSpec()
	owned := make(map[string][2]int)
	provisioner := NewWordPressProvisioner(WordPressProvisionerOptions{
		HomeRoot: homeRoot,
		Runner:   &wordpressRunner{},
		LookupUser: func(string) (*user.User, error) {
			return &user.User{Uid: "501", Gid: "20", Username: spec.Username}, nil
		},
		Chown: func(path string, uid, gid int) error {
			owned[path] = [2]int{uid, gid}
			return nil
		},
		DatabaseRemover: &fakeWordPressDatabaseRemover{},
	})
	root, err := provisioner.documentRoot(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "wp-load.php"), []byte("<?php require __DIR__.'/wp-config.php';"), 0o640); err != nil {
		t.Fatal(err)
	}
	config := "<?php\ndefine('DB_NAME', 'wp_s3_deadbeef');\ndefine('ABSPATH', __DIR__ . '/');\nrequire_once ABSPATH . 'wp-settings.php';\n"
	if err = os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return wordpressRemovalFixture{provisioner: provisioner, documentRoot: root, spec: spec, owned: owned}
}

func (f wordpressRemovalFixture) request(deleteDatabase bool) types.WordPressOperationReq {
	return types.WordPressOperationReq{
		OperationID: 17,
		Action:      types.WordPressActionUninstall,
		Site:        f.spec,
		Removal: &types.WordPressRemovalSpec{
			DeleteDatabase: deleteDatabase,
			DatabaseName:   "wp_s3_deadbeef",
			DatabaseUser:   "wp_u3_deadbeef",
		},
	}
}

func assertNakpanelPlaceholder(t *testing.T, root, domain string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if !isNakpanelPlaceholderDocumentRoot(root, domain, entries) {
		t.Fatalf("%s is not a Nakpanel placeholder", root)
	}
}

func TestUninstallWordPressAtomicallyReplacesRecognizedRoot(t *testing.T) {
	fixture := newWordPressRemovalFixture(t)
	_, _, _, candidate := wordpressRemovalPaths(fixture.documentRoot, 17)
	result, err := fixture.provisioner.RunWordPress(context.Background(), fixture.request(false))
	if err != nil {
		t.Fatal(err)
	}
	if result.Removal == nil || !result.Removal.FilesRemoved || !result.Removal.DatabasePreserved {
		t.Fatalf("unexpected removal result: %#v", result.Removal)
	}
	assertNakpanelPlaceholder(t, fixture.documentRoot, fixture.spec.Domain)
	if got := fixture.owned[candidate]; got != [2]int{501, 20} {
		t.Fatalf("placeholder candidate ownership = %v, want subscription account 501:20", got)
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte(fixture.documentRoot)) {
		t.Fatal("agent result exposed a filesystem path")
	}
}

func TestUninstallWordPressRejectsSymlinkRoot(t *testing.T) {
	fixture := newWordPressRemovalFixture(t)
	outside := t.TempDir()
	if err := os.RemoveAll(fixture.documentRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, fixture.documentRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.provisioner.RunWordPress(context.Background(), fixture.request(false)); err == nil {
		t.Fatal("symlinked WordPress root was accepted")
	}
}

func TestUninstallWordPressRejectsArbitraryContent(t *testing.T) {
	fixture := newWordPressRemovalFixture(t)
	if err := os.Remove(filepath.Join(fixture.documentRoot, "wp-config.php")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.documentRoot, "customer.txt"), []byte("keep me"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.provisioner.RunWordPress(context.Background(), fixture.request(false)); err == nil {
		t.Fatal("arbitrary document root was accepted")
	}
	if _, err := os.Stat(filepath.Join(fixture.documentRoot, "customer.txt")); err != nil {
		t.Fatalf("arbitrary content was changed: %v", err)
	}
}

func TestUninstallWordPressRetryUsesMatchingMarker(t *testing.T) {
	fixture := newWordPressRemovalFixture(t)
	request := fixture.request(false)
	if _, err := fixture.provisioner.RunWordPress(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.provisioner.RunWordPress(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Removal == nil || !result.Removal.FilesRemoved {
		t.Fatalf("retry result = %#v", result.Removal)
	}
}

func TestFinalizeWordPressRemovalRejectsWrongRevision(t *testing.T) {
	fixture := newWordPressRemovalFixture(t)
	request := fixture.request(false)
	if _, err := fixture.provisioner.RunWordPress(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Removal.Finalize = true
	request.Site.DesiredRevision++
	if _, err := fixture.provisioner.RunWordPress(context.Background(), request); err == nil {
		t.Fatal("finalization accepted a different desired revision")
	}
}

func TestFinalizeWordPressRemovalIsIdempotent(t *testing.T) {
	fixture := newWordPressRemovalFixture(t)
	request := fixture.request(false)
	if _, err := fixture.provisioner.RunWordPress(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Removal.Finalize = true
	for attempt := 0; attempt < 2; attempt++ {
		result, err := fixture.provisioner.RunWordPress(context.Background(), request)
		if err != nil || result.Removal == nil || !result.Removal.FilesRemoved {
			t.Fatalf("finalize attempt %d = %#v, %v", attempt+1, result, err)
		}
	}
}

func TestMariaDBWordPressRemoverRejectsIdentifierInjection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	remover := NewMariaDBWordPressRemover(db)
	_, err = remover.Remove(context.Background(), 9, "wp_s9_ok`; DROP DATABASE mysql;--", "wp_u9_deadbeef")
	if err == nil {
		t.Fatal("unsafe identifier was accepted")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unsafe identifier reached SQL: %v", err)
	}
}

func TestMariaDBWordPressRemoverStopsAfterDatabaseDropFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT EXISTS.*information_schema.SCHEMATA").WithArgs("wp_s9_deadbeef").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("SELECT EXISTS.*mysql.user").WithArgs("wp_u9_deadbeef").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("DROP DATABASE `wp_s9_deadbeef`").WillReturnError(errors.New("drop failed"))
	remover := NewMariaDBWordPressRemover(db)
	if _, err = remover.Remove(context.Background(), 9, "wp_s9_deadbeef", "wp_u9_deadbeef"); err == nil || !strings.Contains(err.Error(), "drop database") {
		t.Fatalf("Remove error = %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMariaDBWordPressRemoverIsIdempotentWhenDatabaseAndUserAreAbsent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT EXISTS.*information_schema.SCHEMATA").WithArgs("wp_s9_deadbeef").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("SELECT EXISTS.*mysql.user").WithArgs("wp_u9_deadbeef").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	state, err := NewMariaDBWordPressRemover(db).Remove(context.Background(), 9, "wp_s9_deadbeef", "wp_u9_deadbeef")
	if err != nil || state.DatabasePresent || state.UserPresent {
		t.Fatalf("Remove = %#v, %v", state, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMariaDBWordPressRemoverReportsPartialUserDropFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT EXISTS.*information_schema.SCHEMATA").WithArgs("wp_s9_deadbeef").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("SELECT EXISTS.*mysql.user").WithArgs("wp_u9_deadbeef").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectExec("DROP DATABASE `wp_s9_deadbeef`").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DROP USER 'wp_u9_deadbeef'@'localhost'").WillReturnError(errors.New("user drop failed"))
	state, err := NewMariaDBWordPressRemover(db).Remove(context.Background(), 9, "wp_s9_deadbeef", "wp_u9_deadbeef")
	if err == nil || state.DatabasePresent || !state.UserPresent {
		t.Fatalf("Remove = %#v, %v; want database removed and user retained", state, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
