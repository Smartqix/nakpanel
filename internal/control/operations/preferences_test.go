package operations_test

import (
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"testing"
)

func TestNotificationPreferencesArePersonalAndMandatoryNoticesRemain(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	p, err := s.Preferences(ctx, client)
	if err != nil || p.EmailMode != "off" || !p.CriticalInApp || !p.SecurityInApp {
		t.Fatal(p, err)
	}
	if err = s.SavePreferences(ctx, client, operations.Preferences{EmailMode: "digest"}); err != nil {
		t.Fatal(err)
	}
	p, err = s.Preferences(ctx, client)
	if err != nil || p.EmailMode != "digest" {
		t.Fatal(p, err)
	}
	if err = s.SavePreferences(ctx, client, operations.Preferences{EmailMode: "everything"}); !errors.Is(err, operations.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = s.Preferences(ctx, auth.SessionUser{ID: 11, Role: auth.RoleAdmin}); !errors.Is(err, operations.ErrNotFound) {
		t.Fatal("forged role accepted", err)
	}
	if err = s.SaveDeliveryPolicy(ctx, client, operations.DeliveryPolicy{Enabled: true}); !errors.Is(err, operations.ErrNotFound) {
		t.Fatal("client changed sender policy", err)
	}
}
