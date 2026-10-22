package provision

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

type backupRemovalAPI interface {
	PreviewBackupRemovalFor(context.Context, auth.SessionUser, int64, []int64) (types.BackupRemovalPreview, error)
	RemoveBackupsFor(context.Context, auth.SessionUser, int64, []int64, string, bool) error
}

func TestBackupRemovalRequiresConfirmationAndOwnershipBeforeIntent(t *testing.T) {
	m := NewManager(nil, WithAccessPolicy(fakeAccessPolicy{allow: false}))
	service, ok := any(m).(backupRemovalAPI)
	if !ok {
		t.Fatal("manual backup removal is unavailable")
	}
	actor := auth.SessionUser{ID: 2, Role: auth.RoleClient}
	if err := service.RemoveBackupsFor(context.Background(), actor, 1, []int64{7}, "preview", false); err == nil {
		t.Fatal("missing confirmation was accepted")
	}
	if _, err := service.PreviewBackupRemovalFor(context.Background(), actor, 1, []int64{7}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign backup preview: %v", err)
	}
	if err := service.RemoveBackupsFor(context.Background(), actor, 1, []int64{7}, "preview", true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign removal reached intent: %v", err)
	}
}
