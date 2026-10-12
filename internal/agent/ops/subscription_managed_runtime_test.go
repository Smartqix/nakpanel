package ops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func managedAccountFixture(t *testing.T) (*SubscriptionAccountProvisioner, types.EnsureSubscriptionAccountReq, SitePlan, *recordingOwnershipManager, map[string]string) {
	t.Helper()
	p, req, _, plan := convergenceRuntimeFixture(t)
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"hosting_mode":"managed","active_deployment_id":91}`), &req.Domains[0]); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{plan.NginxConfig: "# managed nginx\nroot /managed/releases/91/public;\n", plan.PHPFPMConfig: "# managed pool\nenv[DEPLOYMENT_ENV] = protected\n", plan.PHPServiceUnit: "# managed unit\nEnvironmentFile=/etc/nakpanel/protected.env\n"}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	domainRoot := filepath.Dir(req.Domains[0].DocumentRoot)
	for _, dir := range []string{filepath.Join(domainRoot, ".nakpanel", "releases", "91"), filepath.Join(domainRoot, ".nakpanel", "shared", "storage"), filepath.Join(req.HomePath, ".security")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	ownership := &recordingOwnershipManager{}
	p.ownership, p.sites.ownership = ownership, ownership
	return p, req, plan, ownership, files
}

func TestAccountConvergencePreservesManagedRuntimeAndConvergesClassicSibling(t *testing.T) {
	p, req, _, ownership, files := managedAccountFixture(t)
	classic := req.Domains[0]
	if err := json.Unmarshal([]byte(`{"hosting_mode":"classic","active_deployment_id":0}`), &classic); err != nil {
		t.Fatal(err)
	}
	classic.SiteID, classic.Domain, classic.DocumentRoot = 8, "classic.test", filepath.Join(req.HomePath, "domains", "classic.test", "public_html")
	req.Domains = append(req.Domains, classic)
	for pass := 0; pass < 2; pass++ {
		if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		for path, previous := range files {
			current, err := os.ReadFile(path)
			if err != nil || string(current) != previous {
				t.Fatalf("managed runtime clobbered: %s: %s (%v)", path, current, err)
			}
		}
	}
	config, err := os.ReadFile(filepath.Join(p.sites.paths.NginxAvailableDir, "classic.test.conf"))
	if err != nil || !strings.Contains(string(config), classic.DocumentRoot) {
		t.Fatalf("classic sibling did not converge: %s, %v", config, err)
	}
	foundClassic := false
	for _, path := range ownership.paths {
		if path == classic.DocumentRoot {
			foundClassic = true
		}
		if path == req.HomePath || path == req.Domains[0].DocumentRoot {
			t.Fatalf("classic sibling caused unsafe recursive ownership: %s", path)
		}
	}
	if !foundClassic {
		t.Fatal("classic writable docroot ownership was not maintained")
	}
}

func TestManagedAccountOwnershipRejectsSymlinkedSharedRoot(t *testing.T) {
	p, req, _, ownership, files := managedAccountFixture(t)
	shared := filepath.Join(filepath.Dir(req.Domains[0].DocumentRoot), ".nakpanel", "shared")
	if err := os.RemoveAll(shared); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, shared); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err == nil {
		t.Fatal("symlinked shared ownership accepted")
	}
	for _, path := range ownership.paths {
		if path == shared || path == outside || path == req.HomePath {
			t.Fatalf("unsafe shared tree was chowned: %s", path)
		}
	}
	for path, previous := range files {
		current, err := os.ReadFile(path)
		if err != nil || string(current) != previous {
			t.Fatalf("validation failure clobbered managed runtime: %s, %v", path, err)
		}
	}
}

func TestAccountConvergenceOnlyChownsTenantWritableBoundaries(t *testing.T) {
	p, req, _, ownership, _ := managedAccountFixture(t)
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(filepath.Dir(req.Domains[0].DocumentRoot), ".nakpanel", "shared")
	foundShared := false
	for _, path := range ownership.paths {
		if path == shared {
			foundShared = true
			continue
		}
		if path == req.HomePath || path == req.Domains[0].DocumentRoot || strings.Contains(path, "releases") || strings.Contains(path, ".security") || path == filepath.Dir(shared) {
			t.Fatalf("ownership escaped writable boundary: %s", path)
		}
	}
	if !foundShared {
		t.Fatal("managed writable shared tree was not maintained")
	}
}

func TestManagedSuspensionPreservesPoolAndEnvironmentUnit(t *testing.T) {
	p, req, plan, _, files := managedAccountFixture(t)
	req.State = "suspended"
	if _, err := p.EnsureSubscriptionAccount(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plan.PHPFPMConfig, plan.PHPServiceUnit} {
		current, err := os.ReadFile(path)
		if err != nil || string(current) != files[path] {
			t.Fatalf("suspension clobbered managed runtime: %s, %v", current, err)
		}
	}
	config, err := os.ReadFile(plan.NginxConfig)
	if err != nil || !strings.Contains(string(config), "return 503;") || !strings.Contains(string(config), "listen 443 ssl;") {
		t.Fatalf("managed suspension did not publish TLS503: %s, %v", config, err)
	}
}
