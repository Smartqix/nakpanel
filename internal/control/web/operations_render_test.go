package web

import (
	"bytes"
	"context"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"strings"
	"testing"
	"time"
)

func TestOperationsCenterSeparatesReadAcknowledgementAndRecovery(t *testing.T) {
	v := WorkspaceView{Route: "activity", OperationsTab: "issues", Operations: operations.Page{Counts: operations.Counts{OpenIssues: 2, ActiveTasks: 1, Unread: 3}, Issues: []operations.Issue{{ID: 9, Kind: "backup", Title: "Backup is overdue", Target: "studio.example", State: "acknowledged", Severity: "critical", ObservedAt: time.Now()}}}}
	var b bytes.Buffer
	if err := operationsCenter(auth.SessionUser{Role: auth.RoleAdmin}, v).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Issues", "Tasks", "History", "Notifications", "Backup is overdue", "studio.example", "Acknowledging an issue does not resolve it", "data-np-operations"} {
		if !strings.Contains(b.String(), want) {
			t.Fatal("missing", want)
		}
	}
	v.OperationsError = "Current status is unavailable"
	b.Reset()
	_ = operationsSummary(v).Render(context.Background(), &b)
	if strings.Contains(b.String(), "Nothing needs attention") {
		t.Fatal("query failure fabricated healthy state")
	}
}
