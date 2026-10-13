package provision

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type sslQuotaStore struct {
	*fakeQuotaStore
	policy types.HostingPolicy
}

func (s *sslQuotaStore) EffectiveSubscriptionPolicy(context.Context, int64) (types.HostingPolicy, error) {
	return s.policy, nil
}

func TestCreationSSLChecksEntitlementAndCapabilitiesBeforeWritingIntent(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		tls, acme, requested, allowed bool
	}{
		{"TLS forbidden", false, true, true, false}, {"ACME unavailable", true, false, true, false}, {"secure creation", true, true, true, true}, {"legacy plain creation", false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeSiteRepository{}
			policy := types.HostingPolicy{Permissions: types.HostingPermissionPolicy{TLS: tc.tls}, Resources: types.HostingResourcePolicy{DiskMB: 512}, PHP: types.HostingPHPPolicy{FPMMaxChildren: 3, MemoryLimitMB: 128}}
			quotas := &sslQuotaStore{fakeQuotaStore: &fakeQuotaStore{hasLimits: true, limits: controlquota.Limits{MaxSites: -1, SiteDiskQuotaMB: 512, PHPFPMMaxChildren: 3, PHPMemoryMB: 128, PHPAllowlist: "8.4", DefaultPHPVersion: "8.4"}}, policy: policy}
			var req types.CreateSiteReq
			if err := json.Unmarshal([]byte(`{"subscription_id":20,"domain":"example.test","secure_with_ssl":`+map[bool]string{true: "true", false: "false"}[tc.requested]+`}`), &req); err != nil {
				t.Fatal(err)
			}
			var capabilities types.RuntimeCapabilities
			if err := json.Unmarshal([]byte(`{"php_versions":["8.4"],"acme_available":`+map[bool]string{true: "true", false: "false"}[tc.acme]+`}`), &capabilities); err != nil {
				t.Fatal(err)
			}
			manager := NewManager(repo, WithQuotaStore(quotas), WithRuntimeCapabilities(fakeRuntimeCapabilities{result: capabilities}))
			_, err := manager.CreateSiteForSubscription(context.Background(), auth.SessionUser{ID: 9, Role: auth.RoleAdmin}, 20, req)
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
				body, _ := json.Marshal(repo.req)
				var saved map[string]any
				_ = json.Unmarshal(body, &saved)
				if tc.requested && saved["secure_with_ssl"] != true {
					t.Fatalf("SSL intent lost: %s", body)
				}
			} else if err == nil || repo.req.Domain != "" {
				t.Fatalf("denied request wrote intent: %#v error=%v", repo.req, err)
			}
		})
	}
}
