package serveradmin

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type capabilityInvalidator struct{ calls int }

func (c *capabilityInvalidator) Invalidate() { c.calls++ }

type capabilityMutationAgent struct {
	phase26EAgent
	err error
}

func (a capabilityMutationAgent) ControlManagedService(context.Context, types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	return types.ControlManagedServiceResult{}, a.err
}

func (a capabilityMutationAgent) ApplyUpdates(context.Context, types.ApplyUpdatesReq) (types.UpdateState, error) {
	return types.UpdateState{}, a.err
}

func TestWorkersInvalidateCapabilitiesAfterAgentMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		service string
		dryRun  bool
		fail    bool
		want    int
	}{
		{name: "PHP service", service: "php-8.5", want: 1},
		{name: "agent restart", service: "agent", want: 1},
		{name: "failed service action", service: "php-8.5", fail: true, want: 1},
		{name: "package update", want: 1},
		{name: "partial package update", fail: true, want: 1},
		{name: "package dry run", dryRun: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			now := time.Now()
			const operationID = "op_12345678901234567890"
			category, action, target, key := "server_management", "install_updates", "server_updates", "selected_packages"
			var request any = types.ApplyUpdatesReq{OperationID: operationID, DryRun: test.dryRun}
			if test.service != "" {
				category, action, target, key = "services", "restart", "server_service", test.service
				request = types.ControlManagedServiceReq{OperationID: operationID, ServiceID: test.service, Action: action}
			}
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			rows := func(status string) *sqlmock.Rows {
				return operationTestRows(now).AddRow(
					int64(1), operationID, category, action, target, key, payload, []byte(`{}`), status,
					nil, operationID, nil, nil, "", int64(7), nil, nil, now, now,
				)
			}
			mock.ExpectQuery("SELECT .* FROM server_operations").WillReturnRows(rows("pending"))
			mock.ExpectQuery("UPDATE server_operations").WillReturnRows(rows("running"))
			// Invalidation must happen even if persisting the outcome fails.
			persistErr := errors.New("completion unavailable")
			mock.ExpectBegin().WillReturnError(persistErr)
			agent := capabilityMutationAgent{}
			if test.fail {
				agent.err = errors.New("agent mutation partially failed")
			}
			manager := NewManager(NewStore(db, nil), nil, agent)
			invalidator := &capabilityInvalidator{}
			manager.SetCapabilityInvalidator(invalidator)
			if test.service != "" {
				err = NewControlServiceWorker(manager).Work(context.Background(), &river.Job[ControlServiceArgs]{Args: ControlServiceArgs{OperationID: operationID}})
			} else {
				err = NewApplyUpdatesWorker(manager).Work(context.Background(), &river.Job[ApplyUpdatesArgs]{Args: ApplyUpdatesArgs{OperationID: operationID}})
			}
			if err == nil {
				t.Error("worker unexpectedly persisted completion")
			}
			if invalidator.calls != test.want {
				t.Errorf("Invalidate calls = %d, want %d", invalidator.calls, test.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
