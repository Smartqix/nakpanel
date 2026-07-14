package provision

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

// fakeMailServiceStore satisfies controlquota.AccountServiceStore and records
// which calls got past the manager's authorization.
type fakeMailServiceStore struct {
	fakeQuotaStore
	mailboxCalls int
	deleteCalls  []string
}

func (s *fakeMailServiceStore) SetSubscriptionPolicy(context.Context, int64, int64, json.RawMessage, bool) error {
	return nil
}
func (s *fakeMailServiceStore) SetSitePolicy(context.Context, int64, int64, json.RawMessage) error {
	return nil
}
func (s *fakeMailServiceStore) UpsertSFTPIdentity(context.Context, int64, int64, types.SFTPIdentityInput) (int64, error) {
	return 1, nil
}
func (s *fakeMailServiceStore) DeleteSFTPIdentity(context.Context, int64, int64) error { return nil }
func (s *fakeMailServiceStore) UpsertScheduledTask(context.Context, int64, int64, types.ScheduledTaskInput) (int64, error) {
	return 1, nil
}
func (s *fakeMailServiceStore) DeleteScheduledTask(context.Context, int64, int64) error { return nil }
func (s *fakeMailServiceStore) UpsertMailDomain(context.Context, int64, int64, types.MailDomainInput) (int64, error) {
	return 1, nil
}
func (s *fakeMailServiceStore) DeleteMailDomain(context.Context, int64, int64) error { return nil }
func (s *fakeMailServiceStore) UpsertMailbox(context.Context, int64, int64, types.MailboxInput) (int64, error) {
	s.mailboxCalls++
	return 7, nil
}
func (s *fakeMailServiceStore) DeleteMailbox(context.Context, int64, int64) error {
	s.deleteCalls = append(s.deleteCalls, "mailbox")
	return nil
}
func (s *fakeMailServiceStore) UpsertMailAlias(context.Context, int64, int64, types.MailAliasInput) (int64, error) {
	s.mailboxCalls++
	return 9, nil
}
func (s *fakeMailServiceStore) DeleteMailAlias(context.Context, int64, int64) error {
	s.deleteCalls = append(s.deleteCalls, "mail_alias")
	return nil
}
func (s *fakeMailServiceStore) UpsertApplication(context.Context, int64, int64, types.ApplicationInput) (int64, error) {
	return 1, nil
}
func (s *fakeMailServiceStore) DeleteApplication(context.Context, int64, int64) error { return nil }

func TestManagerBlocksMailboxAccessForForeignSubscription(t *testing.T) {
	store := &fakeMailServiceStore{}
	manager := NewManager(&fakeSiteRepository{}, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: false}))
	client := auth.SessionUser{ID: 5, Role: auth.RoleClient}
	if _, err := manager.UpsertMailbox(context.Background(), client, 83, types.MailboxInput{MailDomainID: 1, LocalPart: "a", Password: "long-enough-pass"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("UpsertMailbox for a foreign subscription = %v, want ErrForbidden", err)
	}
	if _, err := manager.UpsertMailAlias(context.Background(), client, 83, types.MailAliasInput{MailDomainID: 1, LocalPart: "b", Destinations: []string{"a@x.test"}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("UpsertMailAlias for a foreign subscription = %v, want ErrForbidden", err)
	}
	if err := manager.DeleteSubscriptionService(context.Background(), client, 83, "mailbox", 7); !errors.Is(err, ErrForbidden) {
		t.Fatalf("DeleteSubscriptionService mailbox = %v, want ErrForbidden", err)
	}
	if store.mailboxCalls != 0 || len(store.deleteCalls) != 0 {
		t.Fatalf("store was reached despite denied access: %d %v", store.mailboxCalls, store.deleteCalls)
	}
}

func TestManagerRoutesMailboxAndAliasDeletes(t *testing.T) {
	store := &fakeMailServiceStore{}
	manager := NewManager(&fakeSiteRepository{}, WithQuotaStore(store), WithAccessPolicy(fakeAccessPolicy{allow: true}))
	client := auth.SessionUser{ID: 5, Role: auth.RoleClient}
	if err := manager.DeleteSubscriptionService(context.Background(), client, 83, "mailbox", 7); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteSubscriptionService(context.Background(), client, 83, "mail_alias", 9); err != nil {
		t.Fatal(err)
	}
	if len(store.deleteCalls) != 2 || store.deleteCalls[0] != "mailbox" || store.deleteCalls[1] != "mail_alias" {
		t.Fatalf("delete routing = %v", store.deleteCalls)
	}
}
