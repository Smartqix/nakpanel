package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSiteLogEmptyAndNeverCreatedSourcesReturnEmptyArray(t *testing.T) {
	root := t.TempDir()
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{NginxLogRoot: root})
	req := types.SiteLogRequest{SiteID: 7, Username: "siteusr", Domain: "example.test", Source: types.SiteLogNginxError, LineLimit: 20, ByteLimit: 4096}
	for _, exists := range []bool{false, true} {
		if exists {
			if err := os.WriteFile(filepath.Join(root, "siteusr-example-test.error.log"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		result, err := p.ReadSiteLog(context.Background(), req)
		if err != nil || result.Lines == nil || len(result.Lines) != 0 || result.Source != req.Source || result.NextCursor != 0 {
			t.Fatalf("empty=%v result=%#v err=%v", exists, result, err)
		}
	}
}

func TestSiteLogPermissionErrorsRemainErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	path := filepath.Join(root, "siteusr-example-test.error.log")
	if err := os.WriteFile(path, []byte("private"), 0o000); err != nil {
		t.Fatal(err)
	}
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{NginxLogRoot: root})
	_, err := p.ReadSiteLog(context.Background(), types.SiteLogRequest{SiteID: 7, Username: "siteusr", Domain: "example.test", Source: types.SiteLogNginxError})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("permission error swallowed: %v", err)
	}
}

func TestSiteLogOtherIOErrorsRemainErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "siteusr-example-test.error.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{NginxLogRoot: root})
	if _, err := p.ReadSiteLog(context.Background(), types.SiteLogRequest{SiteID: 7, Username: "siteusr", Domain: "example.test", Source: types.SiteLogNginxError}); err == nil {
		t.Fatal("non-file IO failure was converted to an empty log")
	}
}

func TestSiteLogLineLimitDoesNotAdvancePastBufferedUnreadLines(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "siteusr-example-test.error.log"), []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{NginxLogRoot: root})
	req := types.SiteLogRequest{SiteID: 7, Username: "siteusr", Domain: "example.test", Source: types.SiteLogNginxError, LineLimit: 1, ByteLimit: 4096}
	result, err := p.ReadSiteLog(context.Background(), req)
	if err != nil || result.NextCursor != 6 || len(result.Lines) != 1 || result.Lines[0] != "first" || !result.Truncated {
		t.Fatalf("first page %#v err=%v", result, err)
	}
	req.Cursor = result.NextCursor
	result, err = p.ReadSiteLog(context.Background(), req)
	if err != nil || len(result.Lines) != 1 || result.Lines[0] != "second" {
		t.Fatalf("second page %#v err=%v", result, err)
	}
}
