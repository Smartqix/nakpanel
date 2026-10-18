package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

// This opt-in, loopback-only fixture renders production components without
// connecting a panel worker to a live database.
func TestDomainWorkspaceBrowserPreview(t *testing.T) {
	if os.Getenv("NAKPANEL_DOMAIN_UI_PREVIEW") != "1" {
		t.Skip("set NAKPANEL_DOMAIN_UI_PREVIEW=1 for browser QA")
	}
	data, actions := domainDesignFixture()
	actions.CanCreateDatabase, actions.CanIssueCertificate = true, true
	expiry := dashboard.NullableTime{Time: time.Now().Add(90 * 24 * time.Hour), Valid: true}
	data.Sites[0].TLSExpiresAt, data.Sites[0].TLSAutoRenew = expiry, true
	data.Sites[0].Username, data.Sites[0].DocumentRoot = "nps3", "/home/nps3/domains/example.test/public_html"
	data.Sites[1].TLSLastError = "HTTP-01 validation returned HTTP 403. Check challenge routing and permissions."
	data.Sites = append(data.Sites, dashboard.Site{ID: 9, Domain: "example.net", SubscriptionID: 20, Status: "active", DesiredStatus: "active", PHPVersion: "8.5", TLSStatus: "active", TLSExpiresAt: expiry})
	data.Subscriptions[0].DiskMB, data.Subscriptions[0].DomainsUsed = 8192, 2
	data.Subscriptions[0].AllowBackups = true
	data.SubscriptionUsage = []types.SubscriptionUsage{{SubscriptionID: 20, DiskBytes: 1932735283, Complete: true, CollectedAt: time.Now()}}
	data.Phase6.DNSZones = []dashboard.DNSZone{{ID: 1, SiteID: 1, Domain: "example.test", Mode: "primary", Status: "active", Address: "192.0.2.1"}}
	data.Phase6.DNSRecords = []types.DNSRecord{{ZoneID: 1, Host: "blog", Type: "A", Value: "192.0.2.1"}}
	data.Sites[1].DNSZoneMode = "parent"
	stopped := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets", StaticHandler()))
	mux.HandleFunc("/__stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		once.Do(func() { close(stopped) })
		w.WriteHeader(204)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/removal/preview") {
			p := types.SiteRemovalPreview{SiteID: 9, SubscriptionID: 20, Domain: "example.net", Kind: "website", Allowed: true, RequiresHostnameConfirmation: true, Snapshot: types.SiteRemovalSnapshot{Sites: []types.SiteRemovalSite{{SiteID: 9, Domain: "example.net"}, {SiteID: 10, Domain: "blog.example.net"}}, Databases: []types.SiteRemovalDatabase{{ID: 5, Name: "example_data", DeletionEligible: true}}, Backups: []types.SiteRemovalResource{{ID: 6}}}}
			var html bytes.Buffer
			if err := SiteRemovalPreviewContent(WorkspaceView{CSRFToken: "fixture"}, SiteRemovalView{Preview: &p}).Render(context.Background(), &html); err != nil {
				t.Error(err)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "state": "preview", "html": html.String()})
			return
		}
		view := WorkspaceView{Route: "sites", CSRFToken: "fixture", Tab: r.URL.Query().Get("tab")}
		if view.Tab == "" {
			view.Tab = "overview"
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 2 && parts[0] == "sites" {
			view.DetailID, _ = strconv.ParseInt(parts[1], 10, 64)
			view.Route = "site-detail"
			if len(parts) > 2 {
				view.Tab = parts[2]
			}
		}
		if err := RoutedDashboardPage("Domains", auth.SessionUser{Email: "admin@example.test", Role: auth.RoleAdmin}, data, actions, view).Render(r.Context(), w); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Println("DOMAIN_PREVIEW_URL=" + server.URL)
	select {
	case <-stopped:
	case <-time.After(30 * time.Minute):
		t.Fatal("preview timeout")
	}
}
