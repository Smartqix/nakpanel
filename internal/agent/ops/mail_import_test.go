package ops

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestMaildirStagingRoundTripAndSubscriptionIsolation(t *testing.T) {
	uploads := t.TempDir()
	p := NewMailImportProvisioner(uploads, t.TempDir())
	id := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	body := []byte("Subject: imported\r\n\r\nmessage\r\n")
	_ = tw.WriteHeader(&tar.Header{Name: "new/1", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	if err := os.WriteFile(filepath.Join(uploads, id+".tar"), archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	staged, err := p.StageMaildir(context.Background(), types.StageMaildirReq{SubscriptionID: 1, UploadID: id})
	if err != nil {
		t.Fatal(err)
	}
	page, err := p.InspectMaildir(context.Background(), types.InspectMaildirReq{SubscriptionID: 1, StagingID: staged.StagingID, ManifestSHA256: staged.ManifestSHA256, Limit: 100})
	if err != nil || page.Total != 1 {
		t.Fatalf("%+v %v", page, err)
	}
	chunk, err := p.ReadMaildirMessage(context.Background(), types.ReadMaildirMessageReq{SubscriptionID: 1, StagingID: staged.StagingID, ManifestSHA256: staged.ManifestSHA256, Key: page.Messages[0].Key, Limit: 128 << 10})
	if err != nil || !chunk.EOF || !bytes.Equal(chunk.Data, body) {
		t.Fatalf("chunk %+v %v", chunk, err)
	}
	_, err = p.InspectMaildir(context.Background(), types.InspectMaildirReq{SubscriptionID: 2, StagingID: staged.StagingID, ManifestSHA256: staged.ManifestSHA256, Limit: 100})
	if err == nil {
		t.Fatal("cross-subscription staging was readable")
	}
	if err = p.RemoveMaildirStage(context.Background(), types.RemoveMaildirStageReq{SubscriptionID: 1, StagingID: staged.StagingID, ManifestSHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("cleanup accepted an unverified manifest")
	}
	if err = p.RemoveMaildirStage(context.Background(), types.RemoveMaildirStageReq{SubscriptionID: 1, StagingID: staged.StagingID, ManifestSHA256: staged.ManifestSHA256}); err != nil {
		t.Fatal(err)
	}
	if _, err = p.InspectMaildir(context.Background(), types.InspectMaildirReq{SubscriptionID: 1, StagingID: staged.StagingID, ManifestSHA256: staged.ManifestSHA256, Limit: 100}); err == nil {
		t.Fatal("temporary stage was not removed")
	}
}

func TestMaildirRPCRejectsPathsAndInvalidBounds(t *testing.T) {
	p := NewMailImportProvisioner(t.TempDir(), t.TempDir())
	for _, id := range []string{"../etc/passwd", "/tmp/mail", "", "abc"} {
		if _, err := p.InspectMaildir(context.Background(), types.InspectMaildirReq{SubscriptionID: 1, StagingID: id, Limit: 100}); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	if _, err := p.ReadMaildirMessage(context.Background(), types.ReadMaildirMessageReq{SubscriptionID: 1, StagingID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Limit: 1 << 20}); err == nil {
		t.Fatal("accepted excessive read")
	}
}
func TestMaildirStageRejectsSymlinkUpload(t *testing.T) {
	uploads := t.TempDir()
	p := NewMailImportProvisioner(uploads, t.TempDir())
	id := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	if err := os.Symlink("/etc/passwd", filepath.Join(uploads, id+".tar")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.StageMaildir(context.Background(), types.StageMaildirReq{SubscriptionID: 1, UploadID: id}); err == nil {
		t.Fatal("followed upload symlink")
	}
}
