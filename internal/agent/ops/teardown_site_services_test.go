package ops

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/types"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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

func TestSiteRemovalCompletionReplayKeepsReplacement(t *testing.T) {
	f := newSiteTeardownFixture(t)
	p := NewSiteTeardownProvisioner(f.opts)
	for _, stage := range []types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting, types.RemovalShared, types.RemovalFinalize} {
		f.request.Stage = stage
		if _, err := p.TeardownSite(context.Background(), f.request); err != nil {
			t.Fatal(err)
		}
	}
	newIdentity := types.SiteIdentity{SiteID: 99, SubscriptionID: 2, Username: "nps2", Domain: "addon.test"}
	if err := f.opts.IdentityRegistry.WithCreation(context.Background(), []types.SiteIdentity{newIdentity}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(f.target.Docroot, "new-index.php")
	writeRemovalFixture(t, file)
	f.request.Stage = types.RemovalHosting
	if _, err := NewSiteTeardownProvisioner(f.opts).TeardownSite(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("old cleanup deleted replacement", err)
	}
}

func TestSubdomainMailReviewedRemovalKeepsParentAndSibling(t *testing.T) {
	f := newSiteTeardownFixture(t)
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/principal/box@addon.test" {
			t.Errorf("unapproved principal %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		if r.Method == http.MethodDelete {
			deleted = true
			w.Write([]byte(`{"data":null}`))
			return
		}
		if deleted {
			w.Write([]byte(`{"error":"notFound"}`))
			return
		}
		w.Write([]byte(`{"data":{"name":"box@addon.test","type":"individual"}}`))
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "admin-secret")
	writeRemovalFixture(t, secret)
	f.runner.outputs["stalwart-mail"] = []byte("0.11.8")
	f.opts.Mail = NewMailProvisioner(MailProvisionerOptions{DKIMDir: filepath.Join(f.opts.Paths.HomeRoot, "../dkim"), AdminSecretPath: secret, ManagementURL: server.URL, Runner: f.runner})
	f.request.Snapshot.Resources = []types.SiteRemovalResource{{Kind: "mail_domain", ID: 10, SiteID: 2, Name: "addon.test"}, {Kind: "mailbox", ID: 11, SiteID: 2, ParentID: 10, Name: "box@addon.test"}, {Kind: "webmail", ID: 12, SiteID: 2, Name: "webmail.addon.test"}}
	childKey := filepath.Join(f.opts.Mail.dkimDir, "addon.test", "nak1.key")
	parentKey := filepath.Join(f.opts.Mail.dkimDir, "primary.test", "nak1.key")
	config := filepath.Join(f.opts.Paths.NginxAvailableDir, "webmail.addon.test.conf")
	enabled := filepath.Join(f.opts.Paths.NginxEnabledDir, "webmail.addon.test.conf")
	for _, path := range []string{childKey, parentKey, config} {
		writeRemovalFixture(t, path)
	}
	if err := os.Symlink(config, enabled); err != nil {
		t.Fatal(err)
	}
	p := NewSiteTeardownProvisioner(f.opts)
	for _, stage := range []types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting, types.RemovalShared, types.RemovalFinalize} {
		f.request.Stage = stage
		result, err := p.TeardownSite(context.Background(), f.request)
		if err != nil || !slices.Contains(result.Checkpoints, string(stage)) {
			t.Fatalf("%s: result=%+v error=%v", stage, result, err)
		}
	}
	if !deleted {
		t.Fatal("approved mailbox was not removed")
	}
	for _, path := range append(f.kept, parentKey) {
		if raw, err := os.ReadFile(path); err != nil || string(raw) != "fixture-original" {
			t.Fatalf("parent/sibling resource changed: %s %v", path, err)
		}
	}
	for _, path := range []string{childKey, config, enabled} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("selected child artifact remains: %s %v", path, err)
		}
	}
}
