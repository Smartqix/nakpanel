package main

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/nakroteck/nakpanel/internal/config"
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
