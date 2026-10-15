package mailimport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeAccess struct{ allowed bool }

func (a fakeAccess) CanManageSubscription(context.Context, auth.SessionUser, int64) (bool, error) {
	return a.allowed, nil
}

type fakeStore struct {
	active bool
	writes int
}

func (s *fakeStore) Mailbox(context.Context, int64) (Mailbox, error) {
	return Mailbox{ID: 1, SubscriptionID: 3, Active: s.active}, nil
}
func (s *fakeStore) Preview(_ context.Context, _ auth.SessionUser, req types.MailImportRequest) (types.MailImportPreview, error) {
	s.writes++
	return types.MailImportPreview{ID: "preview", Request: req}, nil
}
func (s *fakeStore) Load(context.Context, string) (types.MailImport, error) {
	return types.MailImport{MailboxID: 1}, nil
}
func (s *fakeStore) Start(context.Context, auth.SessionUser, string) (types.MailImport, error) {
	s.writes++
	return types.MailImport{}, nil
}
func TestMailImportRejectsForeignMailbox(t *testing.T) {
	s := &fakeStore{active: true}
	m := NewManager(s, fakeAccess{})
	_, err := m.Preview(context.Background(), auth.SessionUser{Role: auth.RoleReseller}, types.MailImportRequest{MailboxID: 1})
	if !errors.Is(err, ErrNotFound) || s.writes != 0 {
		t.Fatalf("error=%v writes=%d", err, s.writes)
	}
}
func TestMailImportInactiveMailboxCreatesNoIntent(t *testing.T) {
	s := &fakeStore{}
	m := NewManager(s, fakeAccess{true})
	_, err := m.Preview(context.Background(), auth.SessionUser{Role: auth.RoleAdmin}, types.MailImportRequest{MailboxID: 1})
	if !errors.Is(err, ErrInactive) || s.writes != 0 {
		t.Fatalf("error=%v writes=%d", err, s.writes)
	}
}
func TestMailImportCredentialsNeverSerialize(t *testing.T) {
	b, err := json.Marshal(types.MailImportRequest{SourcePassword: "source-secret", TargetPassword: "target-secret"})
	if err != nil || strings.Contains(string(b), "secret") {
		t.Fatalf("serialized credentials: %s %v", b, err)
	}
	b, err = json.Marshal(ImportArgs{ImportID: "imp_test", Revision: 1})
	if err != nil || strings.Contains(string(b), "password") {
		t.Fatalf("invalid job: %s %v", b, err)
	}
}
func TestMailImportClientCannotStart(t *testing.T) {
	s := &fakeStore{active: true}
	m := NewManager(s, fakeAccess{true})
	_, err := m.Start(context.Background(), auth.SessionUser{Role: auth.RoleClient}, "preview")
	if !errors.Is(err, ErrForbidden) || s.writes != 0 {
		t.Fatalf("error=%v writes=%d", err, s.writes)
	}
}
