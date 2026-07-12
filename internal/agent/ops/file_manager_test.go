package ops

import (
	"archive/zip"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func testFileManager(t *testing.T) (*FileManager, string, string) {
	t.Helper()
	account, err := user.Current()
	if err != nil || !fileManagerUsernameRE.MatchString(account.Username) {
		t.Skip("current user is not compatible with file manager username validation")
	}
	home := t.TempDir()
	root := filepath.Join(home, account.Username, "public_html")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	transfer := filepath.Join(t.TempDir(), "transfers")
	if err := os.MkdirAll(transfer, 0o700); err != nil {
		t.Fatal(err)
	}
	return NewFileManager(FileManagerOptions{HomeRoot: home, TransferDir: transfer, PanelUser: account.Username}), account.Username, root
}

func TestFileManagerListsAndSearchesDocumentRoot(t *testing.T) {
	manager, username, root := testFileManager(t)
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'ok';"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".htaccess"), []byte("deny from all"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := manager.ListFiles(context.Background(), types.FileListReq{Username: username})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 || len(result.Entries) != 3 || result.Entries[0].Kind != types.FileKindDirectory {
		t.Fatalf("unexpected listing: %#v", result)
	}
	search, err := manager.SearchFiles(context.Background(), types.FileSearchReq{Username: username, Query: "index"})
	if err != nil || len(search.Entries) != 1 || search.Entries[0].Name != "index.php" {
		t.Fatalf("unexpected search: %#v err=%v", search, err)
	}
}

func TestFileManagerRejectsTraversalAndExternalSymlink(t *testing.T) {
	manager, username, root := testFileManager(t)
	if _, err := manager.ListFiles(context.Background(), types.FileListReq{Username: username, Path: "../"}); err == nil {
		t.Fatal("traversal path was accepted")
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ReadFile(context.Background(), types.FileReadReq{Username: username, Path: "outside"}); err == nil || !strings.Contains(err.Error(), "escapes document root") {
		t.Fatalf("external symlink error = %v", err)
	}
}

func TestFileManagerEditorUsesOptimisticHashAndAtomicWrite(t *testing.T) {
	manager, username, root := testFileManager(t)
	file := filepath.Join(root, "index.php")
	if err := os.WriteFile(file, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	read, err := manager.ReadFile(context.Background(), types.FileReadReq{Username: username, Path: "index.php"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.WriteFile(context.Background(), types.FileWriteReq{Username: username, Path: "index.php", Content: "new", ExpectedSHA256: "bad"}); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Fatalf("stale write error = %v", err)
	}
	if _, err := manager.WriteFile(context.Background(), types.FileWriteReq{Username: username, Path: "index.php", Content: "new", ExpectedSHA256: read.SHA256}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(file)
	if string(data) != "new" {
		t.Fatalf("file = %q", data)
	}
}

func TestFileManagerCreatesRenamesAndDeletesEntries(t *testing.T) {
	manager, username, root := testFileManager(t)
	if _, err := manager.CreateEntry(context.Background(), types.FileCreateReq{Username: username, Path: "notes.txt", Kind: types.FileKindFile}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.MoveFiles(context.Background(), types.FileBatchReq{Username: username, Paths: []string{"notes.txt"}, Destination: "", NewName: "readme.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "readme.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.DeleteFiles(context.Background(), types.FileBatchReq{Username: username, Paths: []string{"readme.txt"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "readme.txt")); !os.IsNotExist(err) {
		t.Fatalf("deleted file stat = %v", err)
	}
	if _, err := manager.SetFileMode(context.Background(), types.FileModeReq{Username: username, Path: "", Mode: 0o777}); err == nil {
		t.Fatal("document root chmod was accepted")
	}
}

func TestFileManagerTransfersAndArchives(t *testing.T) {
	manager, username, root := testFileManager(t)
	token := "upload-0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(manager.transferDir, token), []byte("uploaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ImportTransfer(context.Background(), types.FileTransferImportReq{Username: username, TransferToken: token, Destination: "upload.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ArchiveFiles(context.Background(), types.FileArchiveReq{Username: username, Paths: []string{"upload.txt"}, Destination: "site.zip"}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ExtractArchive(context.Background(), types.FileExtractReq{Username: username, Path: "site.zip", Destination: "extracted"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "extracted", "upload.txt")); err != nil || string(data) != "uploaded" {
		t.Fatalf("extracted data=%q err=%v", data, err)
	}
	exported, err := manager.ExportTransfer(context.Background(), types.FileTransferExportReq{Username: username, Path: "upload.txt"})
	if err != nil || !transferTokenRE.MatchString(exported.TransferToken) {
		t.Fatalf("export=%#v err=%v", exported, err)
	}
}

func TestExtractZIPRejectsTraversal(t *testing.T) {
	manager, username, root := testFileManager(t)
	archive, err := os.Create(filepath.Join(root, "bad.zip"))
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	item, err := writer.Create("../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = item.Write([]byte("bad"))
	_ = writer.Close()
	_ = archive.Close()
	if _, err := manager.ExtractArchive(context.Background(), types.FileExtractReq{Username: username, Path: "bad.zip", Destination: ""}); err == nil {
		t.Fatal("zip traversal was accepted")
	}
}

func TestMoveOverwriteSamePathPreservesSource(t *testing.T) {
	manager, username, root := testFileManager(t)
	file := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(file, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := manager.MoveFiles(context.Background(), types.FileBatchReq{Username: username, Paths: []string{"keep.txt"}, Destination: "", Overwrite: true})
	if err == nil || !strings.Contains(err.Error(), "same") {
		t.Fatalf("same-path move error = %v", err)
	}
	if data, readErr := os.ReadFile(file); readErr != nil || string(data) != "keep" {
		t.Fatalf("source was damaged: data=%q err=%v", data, readErr)
	}
}

func TestCopyRejectsDestinationInsideSource(t *testing.T) {
	manager, username, root := testFileManager(t)
	if err := os.MkdirAll(filepath.Join(root, "tree", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tree", "index.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := manager.CopyFiles(context.Background(), types.FileBatchReq{Username: username, Paths: []string{"tree"}, Destination: "tree/nested"})
	if err == nil || !strings.Contains(err.Error(), "inside") {
		t.Fatalf("descendant copy error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "tree", "nested", "tree")); !os.IsNotExist(statErr) {
		t.Fatalf("recursive destination was created: %v", statErr)
	}
}

func TestFileManagerRejectsSymlinkMutation(t *testing.T) {
	manager, username, root := testFileManager(t)
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.MoveFiles(context.Background(), types.FileBatchReq{Username: username, Paths: []string{"link.txt"}, Destination: "", NewName: "renamed.txt"}); err == nil {
		t.Fatal("symlink move was accepted")
	}
	if _, err := manager.SetFileMode(context.Background(), types.FileModeReq{Username: username, Path: "link.txt", Mode: 0o600}); err == nil {
		t.Fatal("symlink chmod was accepted")
	}
	if _, err := os.Lstat(filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("symlink was changed: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "target.txt")); err != nil || string(data) != "target" {
		t.Fatalf("target was changed: data=%q err=%v", data, err)
	}
}

func TestExtractConflictDoesNotPublishPartialArchive(t *testing.T) {
	manager, username, root := testFileManager(t)
	archive, err := os.Create(filepath.Join(root, "partial.zip"))
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	for _, name := range []string{"new.txt", "existing.txt"} {
		item, createErr := writer.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, _ = item.Write([]byte(name))
	}
	_ = writer.Close()
	_ = archive.Close()
	if err := os.Mkdir(filepath.Join(root, "destination"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "destination", "existing.txt"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = manager.ExtractArchive(context.Background(), types.FileExtractReq{Username: username, Path: "partial.zip", Destination: "destination"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("extract conflict error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "destination", "new.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("archive was partially published: %v", statErr)
	}
	if data, readErr := os.ReadFile(filepath.Join(root, "destination", "existing.txt")); readErr != nil || string(data) != "original" {
		t.Fatalf("existing file changed: data=%q err=%v", data, readErr)
	}
}
