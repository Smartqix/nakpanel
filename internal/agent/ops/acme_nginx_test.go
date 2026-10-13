package ops

import (
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPublicNginxRenderersAllowACMEWithoutOpeningHiddenFiles(t *testing.T) {
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: 30, Username: "npdemo", Domain: "example.test", PHPVersion: "8.4", SharedAccount: true}, SitePathConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]string{
		"plain":     RenderNginxVHost(plan),
		"tls":       RenderNginxTLSVHost(plan, "/cert.pem", "/key.pem"),
		"redirect":  RenderNginxRuntimeVHost(plan, "/cert.pem", "/key.pem", true),
		"suspended": RenderSuspendedNginxVHost(plan),
	} {
		t.Run(name, func(t *testing.T) {
			want := 1
			if name == "tls" || name == "redirect" {
				want = 2
			}
			if got := strings.Count(config, "location ^~ /.well-known/acme-challenge/"); got != want {
				t.Fatalf("ACME exceptions = %d, want %d public listeners:\n%s", got, want, config)
			}
			if !strings.Contains(config, "limit_except GET") || !strings.Contains(config, "disable_symlinks on;") {
				t.Fatal("challenge endpoint must allow only read operations and reject symlinks")
			}
			if name != "suspended" && !strings.Contains(config, "deny all;") {
				t.Fatal("hidden-file protection was removed")
			}
		})
	}
}
