package ops

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestRetainedBackupDownloadIsBoundedAndConfined(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "removed.test-fixture.tar.gz")
	data := []byte("archive-fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p := NewBackupDownloadReader(root)
	req := types.ReadBackupChunkReq{BackupID: 1, SubscriptionID: 2, Domain: "removed.test", ArchivePath: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Limit: 4}
	result, err := p.ReadBackupChunk(context.Background(), req)
	if err != nil || string(result.Data) != "arch" || result.Size != int64(len(data)) {
		t.Fatal(result, err)
	}
	for _, mutate := range []func(*types.ReadBackupChunkReq){func(r *types.ReadBackupChunkReq) { r.ArchivePath = filepath.Join(root, "../outside.tar.gz") }, func(r *types.ReadBackupChunkReq) { r.Domain = "other.test" }, func(r *types.ReadBackupChunkReq) { r.Limit = 2 << 20 }, func(r *types.ReadBackupChunkReq) { r.Offset = -1 }, func(r *types.ReadBackupChunkReq) { r.SHA256 = fmt.Sprintf("%064d", 0) }} {
		bad := req
		mutate(&bad)
		if _, err = p.ReadBackupChunk(context.Background(), bad); err == nil {
			t.Fatal("unsafe backup read accepted", bad)
		}
	}
	link := filepath.Join(root, "removed.test-link.tar.gz")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	req.ArchivePath = link
	if _, err = p.ReadBackupChunk(context.Background(), req); err == nil {
		t.Fatal("symlink archive accepted")
	}
}
