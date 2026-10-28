package operations_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type serviceActionAgent struct{ fail, stopped bool }

func (a serviceActionAgent) InspectServer(context.Context) (types.ServerInventory, error) {
	return types.ServerInventory{}, nil
}
func (a serviceActionAgent) ControlManagedService(context.Context, types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	if a.fail {
		return types.ControlManagedServiceResult{}, errors.New("private-agent-error-sentinel")
	}
	return types.ControlManagedServiceResult{Changed: true, DurationMS: 12}, nil
}
func (a serviceActionAgent) InspectManagedServices(_ context.Context, ids []string) ([]types.ManagedService, error) {
	state := "active"
	if a.stopped {
		state = "inactive"
	}
	return []types.ManagedService{{ID: ids[0], Available: true, ActiveState: state}}, nil
}

func TestServiceActionLinksOneDurableTaskAndSerializesItsService(t *testing.T) {
	db := isolatedDB(t)
	files, err := filepath.Glob("../../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(data), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	q := recorderQueue(t, db)
	m := serveradmin.NewManager(serveradmin.NewStore(db, nil), q, serviceActionAgent{})
	req := types.ControlManagedServiceReq{OperationID: "op_services_test_1234567890", ServiceID: "web", Action: "restart", ActorUserID: 1}
	result, err := m.ControlManagedService(ctx, req)
	if err != nil || result.TaskID <= 0 {
		t.Fatalf("accepted task missing: %#v %v", result, err)
	}
	conflict := req
	conflict.OperationID = "op_services_other_1234567890"
	conflict.Action = "stop"
	if _, err = m.ControlManagedService(ctx, conflict); !errors.Is(err, serveradmin.ErrOperationInProgress) {
		t.Fatalf("conflicting service action accepted: %v", err)
	}
	items, err := m.ServiceOperations(ctx)
	if err != nil || len(items) != 1 || items[0].TaskID != result.TaskID || items[0].Status != serveradmin.OperationPending {
		t.Fatalf("progress identity mismatch: %#v %v", items, err)
	}
	worker := serveradmin.NewControlServiceWorker(m)
	job := &river.Job[serveradmin.ControlServiceArgs]{Args: serveradmin.ControlServiceArgs{OperationID: req.OperationID}}
	if err = worker.Work(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE river_job SET state='completed',attempt=1,finalized_at=now() WHERE args->>'operation_id'=$1`, req.OperationID); err != nil {
		t.Fatal(err)
	}
	detail, err := operations.NewStore(db).Operation(ctx, admin, result.TaskID)
	if err != nil || detail.Operation.State != operations.StateSucceeded || detail.Operation.Title != "Restart nginx" {
		t.Fatalf("task result mismatch: %#v %v", detail, err)
	}
	items, err = m.ServiceOperations(ctx)
	if err != nil || len(items) != 1 || items[0].Status != serveradmin.OperationSucceeded || items[0].DurationMS != 12 {
		t.Fatalf("service result mismatch: %#v %v", items, err)
	}
	// Recovering a persisted terminal failure must not turn it into success.
	failed := serveradmin.NewManager(serveradmin.NewStore(db, nil), q, serviceActionAgent{fail: true})
	req.OperationID = "op_services_failure_1234567890"
	req.ServiceID = "dns"
	failedResult, err := failed.ControlManagedService(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err = serveradmin.NewControlServiceWorker(failed).Work(ctx, &river.Job[serveradmin.ControlServiceArgs]{Args: serveradmin.ControlServiceArgs{OperationID: req.OperationID}}); err == nil {
		t.Fatal("agent failure was ignored")
	}
	if _, err = db.Exec(`UPDATE river_job SET state='completed',attempt=1,finalized_at=now() WHERE args->>'operation_id'=$1`, req.OperationID); err != nil {
		t.Fatal(err)
	}
	detail, err = operations.NewStore(db).Operation(ctx, admin, failedResult.TaskID)
	if err != nil || detail.Operation.State != operations.StateFailed {
		t.Fatalf("terminal command failure became successful: %#v %v", detail, err)
	}
	items, err = failed.ServiceOperations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if strings.Contains(item.Error, "private-agent-error-sentinel") {
			t.Fatal("raw agent output leaked into progress")
		}
	}
}

func TestServiceQueueTerminalStateReleasesBusyOperationWithoutReplay(t *testing.T) {
	db := isolatedDB(t)
	files, err := filepath.Glob("../../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(data), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	q := recorderQueue(t, db)
	m := serveradmin.NewManager(serveradmin.NewStore(db, nil), q, serviceActionAgent{})
	for n, tc := range []struct{ name, persisted, queued, expected string }{
		{"cancel before execution", "pending", "cancelled", "cancelled"},
		{"cancel after execution started", "running", "cancelled", "failed"},
		{"discard before execution", "pending", "discarded", "failed"},
		{"interrupted execution exhausted", "running", "discarded", "failed"},
		{"unrecorded outcome", "running", "completed", "failed"},
		{"proven success before lost queue acknowledgement", "succeeded", "discarded", "succeeded"},
		{"persisted failure before cancellation", "failed", "cancelled", "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("op_service_recheck_%020d", n)
			t.Cleanup(func() {
				_, _ = db.Exec(`UPDATE server_operations SET status='failed' WHERE operation_id=$1 AND status IN ('pending','running','awaiting_confirmation')`, id)
			})
			result, err := m.ControlManagedService(ctx, types.ControlManagedServiceReq{OperationID: id, ServiceID: "web", Action: "restart", ActorUserID: 1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE server_operations SET status=$2,result='{"stage":"verifying"}'::jsonb,completed_at=CASE WHEN $2 IN ('succeeded','failed') THEN now() ELSE NULL END WHERE operation_id=$1`, id, tc.persisted); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE river_job SET state=$2::river_job_state,attempt=1,finalized_at=now() WHERE args->>'operation_id'=$1`, id, tc.queued); err != nil {
				t.Fatal(err)
			}
			items, err := m.ServiceOperations(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, item := range items {
				if item.OperationID == id {
					found = true
					if string(item.Status) != tc.expected || item.CompletedAt == nil || (item.Stage != "" && tc.persisted != "succeeded" && tc.persisted != "failed") {
						t.Errorf("service operation remained busy or lost its result: %#v, expected %s", item, tc.expected)
					}
				}
			}
			if !found {
				t.Fatal("terminal service operation missing")
			}
			detail, err := operations.NewStore(db).Operation(ctx, admin, result.TaskID)
			if err != nil || string(detail.Operation.State) != tc.expected {
				t.Errorf("task disagrees with service outcome: %#v %v, expected %s", detail, err, tc.expected)
			}
			// The next iteration must be able to queue a new action for the same service.
		})
	}
}
