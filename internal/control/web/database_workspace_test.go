package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestDomainDatabaseWorkspaceActions(t *testing.T) {
	var out bytes.Buffer
	err := domainDatabases(dashboard.Site{ID: 58, SubscriptionID: 39, Domain: "example.test"}, types.SubscriptionSummary{MaxDatabases: -1}, []dashboard.Database{{ID: 30, Name: "app_db", Status: "active"}}, DashboardActions{CanCreateDatabase: true}, WorkspaceView{}).Render(context.Background(), &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Open phpMyAdmin", "Connection details", "Reset password", `name="password"`, `data-np-domain-db-form`, `data-np-db-status-url`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
