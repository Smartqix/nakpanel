package serveradmin

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phase26EAgent struct{}

func (phase26EAgent) InspectServer(context.Context) (types.ServerInventory, error) {
	return types.ServerInventory{}, nil
}

func (phase26EAgent) ControlManagedService(context.Context, types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	return types.ControlManagedServiceResult{}, nil
}

func (phase26EAgent) InspectUpdates(context.Context) (types.UpdateState, error) {
	return types.UpdateState{}, nil
}

func (phase26EAgent) ApplyUpdates(context.Context, types.ApplyUpdatesReq) (types.UpdateState, error) {
	return types.UpdateState{}, nil
}

func (phase26EAgent) ControlHostPower(context.Context, types.HostPowerReq) (types.HostPowerResult, error) {
	return types.HostPowerResult{Accepted: true}, nil
}

func TestPhase26EOperationsUseSingleAttemptSystemQueue(t *testing.T) {
	updateOpts := (ApplyUpdatesArgs{}).InsertOpts()
	if updateOpts.Queue != SystemQueue || updateOpts.MaxAttempts != 1 || !updateOpts.UniqueOpts.ByArgs {
		t.Fatalf("update opts = %#v", updateOpts)
	}
	powerOpts := (HostPowerArgs{}).InsertOpts()
	if powerOpts.Queue != SystemQueue || powerOpts.MaxAttempts != 1 || !powerOpts.UniqueOpts.ByArgs {
		t.Fatalf("power opts = %#v", powerOpts)
	}
}

func TestApplicationCatalogInventoryIsAggregatedWithoutImagesOrSecrets(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	changedAt := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT COALESCE").
		WillReturnRows(sqlmock.NewRows([]string{
			"slug", "runtime", "instances", "running", "stopped", "failed",
			"pending_convergence", "last_changed_at",
		}).AddRow("wordpress", "php", 3, 2, 0, 1, 1, changedAt))

	manager := &Manager{store: NewStore(db, nil)}
	inventory, err := manager.ApplicationCatalogInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 1 || inventory[0].Slug != "wordpress" ||
		inventory[0].Instances != 3 || inventory[0].Failed != 1 ||
		!inventory[0].LastChangedAt.Equal(changedAt) {
		t.Fatalf("inventory = %#v", inventory)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPhase26EManagerRejectsUnattributedOrUnknownHostPower(t *testing.T) {
	manager := &Manager{agent: phase26EAgent{}}
	for _, req := range []types.HostPowerReq{
		{Action: types.HostPowerReboot, OperationID: "op_12345678901234567890"},
		{Action: "shell", OperationID: "op_12345678901234567890", ActorUserID: 7},
	} {
		if err := manager.ControlHostPower(context.Background(), req); err == nil {
			t.Fatalf("host request unexpectedly accepted: %#v", req)
		}
	}
}
