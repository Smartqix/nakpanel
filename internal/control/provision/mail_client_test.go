package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type mailClientStore struct {
	*fakeQuotaStore
	hostname string
	reads    int
}

func (s *mailClientStore) MailClientHostname(context.Context) (string, error) {
	s.reads++
	return s.hostname, nil
}

func TestMailClientProfileIsScopedAndUsesVerifiedProtocols(t *testing.T) {
	store := &mailClientStore{fakeQuotaStore: &fakeQuotaStore{}, hostname: "mail.node.test"}
	m := NewManager(nil, WithQuotaStore(store), WithMailAgent(&mailAdminAgent{status: types.MailServerStatus{State: "active", Listeners: []int{993, 465, 587, 995}}}))
	var probed []int
	m.mailClientProbe = func(_ context.Context, host string, port int) error {
		if host != "mail.node.test" {
			t.Fatalf("unexpected host %q", host)
		}
		probed = append(probed, port)
		if port == 587 {
			return errors.New("untrusted certificate with private details")
		}
		return nil
	}
	if _, err := m.MailClientSettings(context.Background(), auth.SessionUser{Role: auth.RoleClient}, 20); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unowned request: %v", err)
	}
	if store.reads != 0 {
		t.Fatal("denied request read server settings")
	}
	p, err := m.MailClientSettings(context.Background(), auth.SessionUser{Role: auth.RoleAdmin}, 20)
	if err != nil || !p.IMAPTLS || !p.SMTPTLS || p.SMTPSTARTTLS || p.Hostname != "mail.node.test" || len(probed) != 3 {
		t.Fatalf("profile=%+v probed=%v err=%v", p, probed, err)
	}
}

func TestMailClientProfileRejectsUnsafeHostnameAndInvalidScope(t *testing.T) {
	for _, host := range []string{"", "https://mail.test", "mail.test:993", "127.0.0.1", "mail.test/path"} {
		m := NewManager(nil, WithQuotaStore(&mailClientStore{fakeQuotaStore: &fakeQuotaStore{}, hostname: host}), WithMailAgent(&mailAdminAgent{}))
		if _, err := m.MailClientSettings(context.Background(), auth.SessionUser{Role: auth.RoleAdmin}, 20); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
	m := NewManager(nil)
	if _, err := m.MailClientSettings(context.Background(), auth.SessionUser{Role: auth.RoleAdmin}, 0); err == nil {
		t.Fatal("accepted missing subscription")
	}
}
