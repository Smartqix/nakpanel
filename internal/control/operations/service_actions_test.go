package operations_test

import (
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"testing"
)

type serviceActionArgs struct {
	OperationID string `json:"operation_id"`
	ServiceID   string `json:"service_id"`
	Action      string `json:"action"`
}

func (serviceActionArgs) Kind() string { return "system_control_service" }

func TestServiceTasksNameTheActionAndKeepIndependentFailures(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`CREATE TABLE server_operations(operation_id text PRIMARY KEY,status text);`); err != nil {
		t.Fatal(err)
	}
	q := recorderQueue(t, db)
	for _, service := range []string{"web", "dns"} {
		job, err := q.Insert(ctx, serviceActionArgs{"op_" + service, service, "restart"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE river_job SET state='discarded',attempt=1,finalized_at=now() WHERE id=$1`, job.Job.ID); err != nil {
			t.Fatal(err)
		}
	}
	s := operations.NewStore(db)
	page, err := s.Page(ctx, admin, "tasks", operations.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Tasks) != 2 || page.Tasks[0].Title != "Restart BIND" || page.Tasks[1].Title != "Restart nginx" {
		t.Fatalf("service tasks need readable names: %#v", page.Tasks)
	}
	issues, err := s.Page(ctx, admin, "issues", operations.Filter{})
	if err != nil || len(issues.Issues) != 2 {
		t.Fatalf("independent services merged: %#v %v", issues.Issues, err)
	}
}

func TestQuickTasksRetainRecentManualServiceCompletions(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	for _, tc := range []struct{ key, kind, trigger, age string }{
		{"recent-service", "system_control_service", "manual", "1 minute"},
		{"old-service", "system_control_service", "manual", "11 minutes"},
		{"automatic-service", "system_control_service", "scheduled", "1 minute"},
		{"routine-mail", "configure_mail", "manual", "1 minute"},
	} {
		o, err := s.CreateOperation(ctx, operations.NewOperation{Key: tc.key, Kind: tc.kind, Title: tc.key, Trigger: tc.trigger, Resource: operations.Resource{Kind: operations.ResourceServer}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`UPDATE operations SET state='succeeded',updated_at=now()-$2::interval WHERE id=$1`, o.ID, tc.age); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Page(ctx, admin, "tasks", operations.Filter{ActiveFirst: true, Limit: 8})
	if err != nil || len(page.Tasks) != 1 || page.Tasks[0].Title != "recent-service" || page.Counts.ActiveTasks != 0 {
		t.Fatalf("quick completion result: %#v %v", page, err)
	}
	foreign, err := s.Page(ctx, client, "tasks", operations.Filter{ActiveFirst: true, Limit: 8})
	if err != nil || len(foreign.Tasks) != 0 {
		t.Fatalf("server service disclosed to tenant: %#v %v", foreign, err)
	}
}
