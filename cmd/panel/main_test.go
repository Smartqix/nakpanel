package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/maintenance"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/riverqueue/river"
)

func TestDashboardSiteAdapterPreservesSubdomainMetadata(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := sqlmock.NewRows([]string{"id", "owner", "username", "domain", "php", "status", "error", "created", "updated", "tls_status", "issuer", "cert", "key", "expires", "tls_error", "subscription", "customer", "desired_status", "desired_php", "redirect", "desired_redirect", "settings_status", "settings_error", "renew", "account", "root", "parent", "dns_mode", "removal_state"}).AddRow(
		31, 1, "nps3", "sap.example.test", "8.4", "active", "", time.Now(), time.Now(), "active", "acme", "", "", nil, "", 3, 4, "active", "8.4", false, false, "in_sync", "", true, 3, "/home/nps3/domains/sap.example.test/public_html", 1, "parent", "removing",
	)
	mock.ExpectQuery("SELECT id, owner_user_id").WillReturnRows(rows)
	sites, err := (dashboardQuerier{queries: store.New(db)}).ListSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || !sites[0].ParentSiteID.Valid || sites[0].ParentSiteID.Int64 != 1 || sites[0].DnsZoneMode != "parent" || sites[0].RemovalState != "removing" {
		t.Fatalf("lost parent/DNS identity: %#v", sites)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestNewHTTPServerUsesPanelPortAndTLS12Minimum(t *testing.T) {
	server := newHTTPServer(config.PanelRuntimeConfig{
		HTTPSAddr: ":7443",
	}, http.NotFoundHandler())

	if server.Addr != ":7443" {
		t.Fatalf("Addr = %q, want :7443", server.Addr)
	}
	if server.TLSConfig == nil {
		t.Fatal("TLSConfig is nil")
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", server.TLSConfig.MinVersion)
	}
}

func TestPanelQueuesIsolateHostMutations(t *testing.T) {
	queues := panelQueueConfig()
	if queues[serveradmin.SystemQueue].MaxWorkers != 1 {
		t.Fatalf("system workers = %d, want 1", queues[serveradmin.SystemQueue].MaxWorkers)
	}
	if queues[river.QueueDefault].MaxWorkers != 4 || queues[maintenance.Queue].MaxWorkers != 2 {
		t.Fatalf("provisioning or maintenance queues changed: %#v", queues)
	}
}
