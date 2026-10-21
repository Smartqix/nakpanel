package ops

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

// Only the systemd process boundary is substituted. Renderers, restored files,
// drift detection and the real system reconciler run together.
type restoredClassicSystemd struct {
	state         string
	starts, stops int
}

func (s *restoredClassicSystemd) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "systemctl" || !slices.Equal(args, []string{"show", "--property=ActiveState", "--value", "nakpanel-php-fpm@7.service"}) {
		return nil, fmt.Errorf("unexpected process: %s %q", name, args)
	}
	return []byte(s.state + "\n"), nil
}

func (s *restoredClassicSystemd) ReloadService(_ context.Context, name string) error {
	if name == "nakpanel-php-fpm@7.service" {
		s.state = "active"
		s.starts++
	}
	return nil
}

func (s *restoredClassicSystemd) StopService(_ context.Context, name string) error {
	if name != "nakpanel-php-fpm@7.service" {
		return fmt.Errorf("unexpected stop: %s", name)
	}
	s.state = "inactive"
	s.stops++
	return nil
}

func TestSystemReconciliationRestoresClassicPHPServiceFromIntent(t *testing.T) {
	for _, minor := range []string{"8.3", "8.4", "8.5"} {
		for _, intent := range []string{"active", "suspended"} {
			t.Run(minor+"/"+intent, func(t *testing.T) {
				root := t.TempDir()
				paths := SitePathConfig{HomeRoot: filepath.Join(root, "home"), NginxAvailableDir: filepath.Join(root, "available"),
					NginxEnabledDir: filepath.Join(root, "enabled"), NginxLogDir: filepath.Join(root, "logs"),
					PHPFPMPoolDir: filepath.Join(root, "php"), PHPFPMLogDir: filepath.Join(root, "php-logs"),
					PHPRunDir: filepath.Join(root, "run"), NginxSnippet: "snippets/fastcgi-php.conf", WWWGroup: "www-data", PHPTmpDir: filepath.Join(root, "tmp")}
				systemd := &restoredClassicSystemd{state: "inactive"}
				sites := NewSiteProvisioner(SiteProvisionerOptions{Paths: paths, Reloader: systemd, Runner: systemd})
				req := types.ApplySiteRuntimeReq{SiteID: 7, Username: "nprestore", Domain: "restore.test", SharedAccount: true,
					CurrentPHPVersion: minor, DesiredPHPVersion: minor, State: intent}
				if err := sites.ApplySiteRuntime(context.Background(), req); err != nil {
					t.Fatal(err)
				}
				// Restore retains exact configuration bytes but defers PHP startup to
				// reconciliation. Suspension must also repair a wrongly running unit.
				systemd.state = "inactive"
				if intent == "suspended" {
					systemd.state = "active"
				}
				systemd.starts, systemd.stops = 0, 0
				reconciler := NewReconciliationProvisioner(sites, nil, nil, sites)
				input := types.ReconcileSystemReq{Sites: []types.ReconcileSiteReq{{SiteID: 7, Username: req.Username, Domain: req.Domain,
					SharedAccount: true, PHPVersion: minor, DesiredPHPVersion: minor, State: intent}}}
				result, err := reconciler.ReconcileSystem(context.Background(), input)
				if err != nil || result.Failed != 0 || len(result.Resources) != 1 || result.Resources[0].Outcome != "repaired" {
					t.Fatalf("matching restored files concealed service drift: result=%#v error=%v", result, err)
				}
				if intent == "active" && (systemd.state != "active" || systemd.starts != 1 || systemd.stops != 0) {
					t.Fatalf("active intent did not recover PHP: %#v", systemd)
				}
				if intent == "suspended" && (systemd.state != "inactive" || systemd.starts != 0 || systemd.stops == 0) {
					t.Fatalf("suspended intent activated PHP: %#v", systemd)
				}
				starts, stops := systemd.starts, systemd.stops
				result, err = reconciler.ReconcileSystem(context.Background(), input)
				if err != nil || result.Failed != 0 || result.Resources[0].Outcome != "unchanged" {
					t.Fatalf("healthy runtime did not remain unchanged: %#v %v", result, err)
				}
				if systemd.starts != starts || systemd.stops != stops {
					t.Fatalf("unchanged runtime caused service mutations: %#v", systemd)
				}
			})
		}
	}
}
