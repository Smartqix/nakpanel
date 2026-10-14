package ops

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"testing"
)

func TestRemovalKeepsSiblingMailAndPrimaryAccess(t *testing.T) {
	f := newSiteTeardownFixture(t)
	f.opts.Mail = NewMailProvisioner(MailProvisionerOptions{DKIMDir: filepath.Join(f.opts.Paths.HomeRoot, "../dkim")})
	f.request.Snapshot.Resources = []types.SiteRemovalResource{{Kind: "mail_domain", ID: 10, SiteID: 2, Name: "addon.test"}, {Kind: "webmail", ID: 11, SiteID: 2, Name: "webmail.addon.test"}}
	for _, path := range []string{filepath.Join(f.opts.Mail.dkimDir, "addon.test", "nak1.key"), filepath.Join(f.opts.Paths.NginxAvailableDir, "webmail.addon.test.conf")} {
		writeRemovalFixture(t, path)
	}
	kept := filepath.Join(f.opts.Mail.dkimDir, "primary.test", "nak1.key")
	writeRemovalFixture(t, kept)
	p := NewSiteTeardownProvisioner(f.opts)
	for _, stage := range []types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting, types.RemovalShared} {
		f.request.Stage = stage
		if _, err := p.TeardownSite(context.Background(), f.request); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.opts.Mail.dkimDir, "addon.test", "nak1.key")); !os.IsNotExist(err) {
		t.Fatal("removed signing key survives")
	}
	if _, err := os.Stat(filepath.Join(f.opts.Paths.NginxAvailableDir, "webmail.addon.test.conf")); !os.IsNotExist(err) {
		t.Fatal("removed webmail config survives")
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatal("sibling mail changed", err)
	}
}

func TestRemovalSharedRequiresHostingFirst(t *testing.T) {
	f := newSiteTeardownFixture(t)
	f.request.Stage = types.RemovalShared
	if _, err := NewSiteTeardownProvisioner(f.opts).TeardownSite(context.Background(), f.request); err == nil {
		t.Fatal("shared cleanup ran before hosting stage")
	}
	if len(f.runner.calls) != 0 {
		t.Fatal("out-of-order side effect")
	}
}

func TestRemovalExternalDNSIsNotModified(t *testing.T) {
	f := newSiteTeardownFixture(t)
	f.request.Snapshot.Resources = []types.SiteRemovalResource{{Kind: "dns_zone", ID: 10, SiteID: 2, Name: "addon.test", Mode: "disabled"}}
	p := NewSiteTeardownProvisioner(f.opts)
	for _, stage := range []types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting, types.RemovalShared} {
		f.request.Stage = stage
		if _, err := p.TeardownSite(context.Background(), f.request); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range f.runner.calls {
		if call[0] == "named-checkconf" || call[0] == "named-checkzone" {
			t.Fatal("external DNS modified")
		}
	}
}

func TestRemovalSharedConfigFailureRollsBack(t *testing.T) {
	f := newSiteTeardownFixture(t)
	f.request.Snapshot.Resources = []types.SiteRemovalResource{{Kind: "webmail", ID: 11, SiteID: 2, Name: "webmail.addon.test"}}
	config := filepath.Join(f.opts.Paths.NginxAvailableDir, "webmail.addon.test.conf")
	writeRemovalFixture(t, config)
	p := NewSiteTeardownProvisioner(f.opts)
	for _, stage := range []types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting} {
		f.request.Stage = stage
		if _, err := p.TeardownSite(context.Background(), f.request); err != nil {
			t.Fatal(err)
		}
	}
	f.runner.failName = "nginx"
	f.request.Stage = types.RemovalShared
	if _, err := p.TeardownSite(context.Background(), f.request); err == nil {
		t.Fatal("shared validation failure ignored")
	}
	if data, err := os.ReadFile(config); err != nil || string(data) != "fixture-original" {
		t.Fatal("webmail candidate did not roll back", err)
	}
	if _, err := os.Stat(f.target.Docroot); !os.IsNotExist(err) {
		t.Fatal("configuration rollback restored removed content")
	}
	f.runner.failName = ""
	if _, err := NewSiteTeardownProvisioner(f.opts).TeardownSite(context.Background(), f.request); err != nil {
		t.Fatal("shared retry", err)
	}
}
