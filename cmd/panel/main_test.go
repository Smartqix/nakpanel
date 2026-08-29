package main

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/maintenance"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/riverqueue/river"
)

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
