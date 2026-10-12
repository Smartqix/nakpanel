package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

func TestPanelHostnameContext(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"Panel.Example:7443", "panel.example"},
		{"panel.example", "panel.example"},
		{"[::1]:7443", "::1"},
		{"[::1]", "::1"},
		{"", "Control panel"},
	} {
		if got := panelHostname(WithPanelHostname(context.Background(), tc.host)); got != tc.want {
			t.Errorf("host %q = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestDashboardComponentHostnameFallback(t *testing.T) {
	var body bytes.Buffer
	err := DashboardPage("Dashboard", auth.SessionUser{Role: auth.RoleAdmin}, dashboard.Data{}, DashboardActions{}).Render(context.Background(), &body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.String(), "<small>Control panel</small>") || strings.Contains(body.String(), "ns1.nakroteck.com") {
		t.Fatal("component render did not use neutral hostname fallback")
	}
}
