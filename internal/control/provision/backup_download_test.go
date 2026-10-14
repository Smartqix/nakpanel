package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type backupReaderFixture struct {
	calls   int
	request types.ReadBackupChunkReq
}

func (f *backupReaderFixture) ReadBackupChunk(_ context.Context, req types.ReadBackupChunkReq) (types.ReadBackupChunkResult, error) {
	f.calls++
	f.request = req
	return types.ReadBackupChunkResult{BackupID: req.BackupID, Offset: req.Offset, Size: 4, Data: []byte("test")}, nil
}
func TestSiteRemovalRetainedBackupDownloadRevalidatesOwnership(t *testing.T) {
	s, op := completeRemovalFixture(t)
	if err := s.Finalize(context.Background(), op.ID, op.Revision); err != nil {
		t.Fatal(err)
	}
	agent := &backupReaderFixture{}
	repository := NewSQLPhase6Repository(s.db, s.river)
	denied := NewManager(nil, WithPhase6Repository(repository), WithAccessPolicy(fakeAccessPolicy{allow: false}), WithBackupChunkReader(agent))
	if _, err := denied.ReadBackupFor(context.Background(), auth.SessionUser{ID: 99, Role: auth.RoleClient}, op.Snapshot.Backups[0].ID, 0, 100); !errors.Is(err, ErrForbidden) || agent.calls != 0 {
		t.Fatal(err, agent.calls)
	}
	allowed := NewManager(nil, WithPhase6Repository(repository), WithAccessPolicy(fakeAccessPolicy{allow: true}), WithBackupChunkReader(agent))
	if _, err := allowed.ReadBackupFor(context.Background(), auth.SessionUser{ID: 2, Role: auth.RoleClient}, op.Snapshot.Backups[0].ID, 0, 100); err != nil {
		t.Fatal(err)
	}
	if agent.request.Domain != op.Domain || agent.request.SubscriptionID != op.SubscriptionID || agent.request.SHA256 == "" {
		t.Fatal("download did not derive archive identity from owned intent", agent.request)
	}
}
