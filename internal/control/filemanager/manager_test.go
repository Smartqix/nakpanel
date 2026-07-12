package filemanager

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeStore struct {
	site   Site
	audits []string
}

func (s *fakeStore) GetSite(context.Context, int64) (Site, error) { return s.site, nil }
func (s *fakeStore) RecordAudit(_ context.Context, _ auth.SessionUser, _ Site, action string, _ any) error {
	s.audits = append(s.audits, action)
	return nil
}

type fakeAccess struct{ allow bool }

func (a fakeAccess) CanManageDomain(context.Context, auth.SessionUser, string) (bool, error) {
	return a.allow, nil
}

type fakeAgent struct {
	username string
	writeErr error
	exported types.FileTransferResult
}

func (a *fakeAgent) ListFiles(_ context.Context, req types.FileListReq) (types.FileListResult, error) {
	a.username = req.Username
	return types.FileListResult{Total: 1}, nil
}
func (a *fakeAgent) SearchFiles(context.Context, types.FileSearchReq) (types.FileSearchResult, error) {
	return types.FileSearchResult{}, nil
}
func (a *fakeAgent) ReadFile(context.Context, types.FileReadReq) (types.FileReadResult, error) {
	return types.FileReadResult{}, nil
}
func (a *fakeAgent) WriteFile(_ context.Context, req types.FileWriteReq) (types.FileMutationResult, error) {
	a.username = req.Username
	return types.FileMutationResult{Paths: []string{req.Path}}, a.writeErr
}
func (a *fakeAgent) CreateFileEntry(context.Context, types.FileCreateReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) CopyFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) MoveFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) DeleteFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) ArchiveFiles(context.Context, types.FileArchiveReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) ExtractArchive(context.Context, types.FileExtractReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) SetFileMode(context.Context, types.FileModeReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) ImportFileTransfer(context.Context, types.FileTransferImportReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (a *fakeAgent) ExportFileTransfer(context.Context, types.FileTransferExportReq) (types.FileTransferResult, error) {
	return a.exported, nil
}

func TestManagerScopesSiteAndInjectsSystemUsername(t *testing.T) {
	store := &fakeStore{site: Site{ID: 7, Username: "npdemo", Domain: "example.test"}}
	agent := &fakeAgent{}
	manager := NewManager(ManagerOptions{Store: store, Access: fakeAccess{allow: true}, Agent: agent})
	_, result, err := manager.List(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, types.FileListReq{})
	if err != nil || result.Total != 1 || agent.username != "npdemo" {
		t.Fatalf("result=%#v username=%q err=%v", result, agent.username, err)
	}

	manager.access = fakeAccess{allow: false}
	if _, _, err := manager.List(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, 7, types.FileListReq{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign site error = %v", err)
	}
}

func TestManagerAuditsSuccessfulMutationAndClassifiesConflict(t *testing.T) {
	store := &fakeStore{site: Site{ID: 7, Username: "npdemo", Domain: "example.test"}}
	agent := &fakeAgent{}
	manager := NewManager(ManagerOptions{Store: store, Access: fakeAccess{allow: true}, Agent: agent})
	if _, err := manager.Write(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 7, types.FileWriteReq{Path: "index.php", Content: "ok"}); err != nil {
		t.Fatal(err)
	}
	if len(store.audits) != 1 || store.audits[0] != "file.edit" {
		t.Fatalf("audits=%v", store.audits)
	}
	agent.writeErr = errors.New("file conflict: changed since it was opened")
	if _, err := manager.Write(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 7, types.FileWriteReq{Path: "index.php"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict error=%v", err)
	}
	if len(store.audits) != 1 {
		t.Fatalf("failed mutation was audited: %v", store.audits)
	}
}

func TestManagerStagesUploadsWithinConfiguredLimit(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(ManagerOptions{TransferDir: dir, UploadMaxBytes: 4})
	token, size, err := manager.StageUpload(context.Background(), bytes.NewBufferString("four"))
	if err != nil || size != 4 || !uploadTokenRE.MatchString(token) {
		t.Fatalf("token=%q size=%d err=%v", token, size, err)
	}
	manager.CleanupTransfer(token)
	if _, err := os.Stat(dir + "/" + token); !os.IsNotExist(err) {
		t.Fatalf("cleanup stat=%v", err)
	}
	if _, _, err := manager.StageUpload(context.Background(), bytes.NewBufferString("five!")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("large upload error=%v", err)
	}
}

func TestManagerRejectsUntrustedDownloadToken(t *testing.T) {
	store := &fakeStore{site: Site{ID: 7, Username: "npdemo", Domain: "example.test"}}
	agent := &fakeAgent{exported: types.FileTransferResult{TransferToken: "download-../../secret"}}
	manager := NewManager(ManagerOptions{Store: store, Access: fakeAccess{allow: true}, Agent: agent, TransferDir: t.TempDir()})
	if _, _, _, err := manager.Download(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 7, "index.php"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("download error=%v", err)
	}
}

func TestManagerMutationMethodsReturnUnavailableWithoutAgent(t *testing.T) {
	manager := NewManager(ManagerOptions{Store: &fakeStore{site: Site{ID: 7, Username: "npdemo", Domain: "example.test"}}})
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	if _, err := manager.Write(context.Background(), actor, 7, types.FileWriteReq{Path: "index.php"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("write error=%v", err)
	}
	if _, err := manager.Archive(context.Background(), actor, 7, types.FileArchiveReq{Paths: []string{"index.php"}, Destination: "site.zip"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("archive error=%v", err)
	}
	if _, err := manager.Import(context.Background(), actor, 7, "upload-0123456789abcdef0123456789abcdef", "index.php", false, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("import error=%v", err)
	}
	if _, _, _, err := manager.Download(context.Background(), actor, 7, "index.php"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("download error=%v", err)
	}
}

func TestClassifyAgentErrorMapsMissingAndEditorLimit(t *testing.T) {
	if err := classifyAgentError(errors.New("open file: no such file or directory")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	if err := classifyAgentError(errors.New("file exceeds the 524288 byte editor limit")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("editor limit error=%v", err)
	}
}
