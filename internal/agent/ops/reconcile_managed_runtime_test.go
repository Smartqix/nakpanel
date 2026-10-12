package ops

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type managedSystemRuntime struct {
	creates, driftChecks, applies, suspends int
	suspended                               types.CreateSiteReq
	cert, key                               string
	suspendErr                              error
}

func (p *managedSystemRuntime) CreateSite(context.Context, types.CreateSiteReq) error {
	p.creates++
	return nil
}
func (p *managedSystemRuntime) SiteRuntimeDrift(context.Context, types.ApplySiteRuntimeReq) (bool, error) {
	p.driftChecks++
	return true, nil
}
func (p *managedSystemRuntime) ApplySiteRuntime(context.Context, types.ApplySiteRuntimeReq) error {
	p.applies++
	return nil
}
func (p *managedSystemRuntime) suspendExistingSiteRuntime(_ context.Context, req types.CreateSiteReq, cert, key string) error {
	p.suspends++
	p.suspended, p.cert, p.key = req, cert, key
	return p.suspendErr
}

func TestSystemReconciliationPreservesActiveManagedRuntime(t *testing.T) {
	for _, withRuntime := range []bool{false, true} {
		runtime := &managedSystemRuntime{}
		p := NewReconciliationProvisioner(runtime, nil, nil)
		if withRuntime {
			p = NewReconciliationProvisioner(runtime, nil, nil, runtime)
		}
		result, err := p.ReconcileSystem(context.Background(), types.ReconcileSystemReq{Sites: []types.ReconcileSiteReq{
			{SiteID: 7, Username: "nps4", Domain: "managed.test", PHPVersion: "8.4", State: "active", HostingMode: types.PHPHostingModeManaged, ActiveDeploymentID: 11},
			{SiteID: 8, Username: "nps4", Domain: "classic.test", PHPVersion: "8.4", State: "active"},
		}})
		if err != nil || result.Failed != 0 || result.SitesOK != 2 {
			t.Fatalf("reconciliation failed: %#v %v", result, err)
		}
		if withRuntime && (runtime.driftChecks != 1 || runtime.applies != 1 || runtime.creates != 0) {
			t.Fatalf("managed runtime reached classic renderer: %#v", runtime)
		}
		if !withRuntime && runtime.creates != 1 {
			t.Fatalf("managed site reached fallback CreateSite: %#v", runtime)
		}
	}
}

func TestSystemReconciliationSuspendsManagedWithoutClassicWrites(t *testing.T) {
	for _, fail := range []bool{false, true} {
		runtime := &managedSystemRuntime{}
		if fail {
			runtime.suspendErr = errors.New("stop failed")
		}
		p := NewReconciliationProvisioner(runtime, nil, nil, runtime)
		result, err := p.ReconcileSystem(context.Background(), types.ReconcileSystemReq{Sites: []types.ReconcileSiteReq{{
			SiteID: 7, SubscriptionID: 4, Username: "nps4", Domain: "managed.test", PHPVersion: "8.4", DesiredPHPVersion: "8.5", State: "suspended",
			HostingMode: types.PHPHostingModeManaged, ActiveDeploymentID: 11, SharedAccount: true, TLSCertPath: "/certs/fullchain.pem", TLSKeyPath: "/certs/privkey.pem",
		}}})
		if err != nil {
			t.Fatal(err)
		}
		if runtime.suspends != 1 || runtime.applies != 0 || runtime.creates != 0 || runtime.driftChecks != 0 {
			t.Fatalf("managed suspension used generic renderer: %#v", runtime)
		}
		if runtime.suspended.SiteID != 7 || runtime.suspended.PHPVersion != "8.4" || !runtime.suspended.SharedAccount || runtime.cert != "/certs/fullchain.pem" || runtime.key != "/certs/privkey.pem" {
			t.Fatalf("managed shutdown lost authoritative identity/TLS: %#v", runtime)
		}
		if (result.Failed > 0) != fail {
			t.Fatalf("suspension failure not acknowledged: %#v", result)
		}
	}
}
