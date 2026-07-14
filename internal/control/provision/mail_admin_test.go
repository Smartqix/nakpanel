package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type mailAdminStore struct {
	*fakeQuotaStore
	settings controlquota.MailSettings
}

func (s *mailAdminStore) MailSettings(context.Context) (controlquota.MailSettings, error) {
	return s.settings, nil
}

func (s *mailAdminStore) UpdateMailSettings(_ context.Context, settings controlquota.MailSettings) error {
	s.settings = settings
	return nil
}

type mailAdminAgent struct {
	service string
	status  types.MailServerStatus
}

func (a *mailAdminAgent) MailStatus(context.Context) (types.MailServerStatus, error) {
	return a.status, nil
}
func (a *mailAdminAgent) ReloadService(_ context.Context, service string) (types.Response, error) {
	a.service = service
	return types.Response{OK: true}, nil
}

func TestMailSettingsPreserveAndClearRelaySecret(t *testing.T) {
	store := &mailAdminStore{fakeQuotaStore: &fakeQuotaStore{}, settings: controlquota.MailSettings{
		MailHostname: "mail.node.test", SmarthostHost: "smtp.node.test", SmarthostPort: 587,
		SmarthostUsername: "relay", SmarthostPassword: "existing-secret", OutboundRateLimit: "200/1h", QueueAlertThreshold: 50,
	}}
	manager := NewManager(nil, WithQuotaStore(store))
	admin := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}

	view, err := manager.UpdateMailSettings(context.Background(), admin, types.MailSettingsUpdate{
		MailHostname: "mail.changed.test", SmarthostHost: "smtp.node.test", SmarthostPort: 465,
		SmarthostUsername: "relay", OutboundRateLimit: "100/1h", QueueAlertThreshold: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.settings.SmarthostPassword != "existing-secret" || !view.SmarthostConfigured {
		t.Fatalf("blank password did not preserve relay credential: settings=%+v view=%+v", store.settings, view)
	}
	if _, err = manager.UpdateMailSettings(context.Background(), admin, types.MailSettingsUpdate{
		MailHostname: "mail.changed.test", ClearSmarthost: true, OutboundRateLimit: "100/1h", QueueAlertThreshold: 25,
	}); err != nil {
		t.Fatal(err)
	}
	if store.settings.SmarthostHost != "" || store.settings.SmarthostPassword != "" {
		t.Fatalf("clear relay retained credentials: %+v", store.settings)
	}
}

func TestMailAdminOperationsAreFixedAndAdminOnly(t *testing.T) {
	store := &mailAdminStore{fakeQuotaStore: &fakeQuotaStore{}, settings: controlquota.MailSettings{MailHostname: "mail.node.test", OutboundRateLimit: "100/1h", QueueAlertThreshold: 25}}
	agent := &mailAdminAgent{status: types.MailServerStatus{State: "active", TotalQueued: 2}}
	manager := NewManager(nil, WithQuotaStore(store), WithMailAgent(agent))
	admin := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	client := auth.SessionUser{ID: 2, Role: auth.RoleClient}

	if err := manager.RestartMail(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	if agent.service != "stalwart-mail.service" {
		t.Fatalf("restart service=%q, want fixed Stalwart service", agent.service)
	}
	if status, err := manager.MailServerStatus(context.Background(), admin); err != nil || status.TotalQueued != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if err := manager.RestartMail(context.Background(), client); !errors.Is(err, ErrForbidden) {
		t.Fatalf("client restart error=%v, want forbidden", err)
	}
}
