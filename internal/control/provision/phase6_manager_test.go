package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakePhase6Repository struct {
	backupOwnerID    int64
	backupReq        types.CreateBackupReq
	webmailOwnerID   int64
	webmailDomain    string
	dnsOwnerID       int64
	dnsDomain        string
	dnsAddress       string
	reconcileOwnerID int64
	adminerOwnerID   int64
	restoreOwnerID   int64
	restoreBackupID  int64
}

func (r *fakePhase6Repository) CreateBackup(ctx context.Context, ownerID int64, req types.CreateBackupReq) (int64, error) {
	r.backupOwnerID = ownerID
	r.backupReq = req
	return 101, nil
}

func (r *fakePhase6Repository) ConfigureWebmail(ctx context.Context, ownerID int64, domain string) (int64, error) {
	r.webmailOwnerID = ownerID
	r.webmailDomain = domain
	return 102, nil
}

func (r *fakePhase6Repository) ConfigureDNS(ctx context.Context, ownerID int64, domain string, address string) (int64, error) {
	r.dnsOwnerID = ownerID
	r.dnsDomain = domain
	r.dnsAddress = address
	return 103, nil
}

func (r *fakePhase6Repository) ReconcileSystem(ctx context.Context, ownerID int64) (int64, error) {
	r.reconcileOwnerID = ownerID
	return 104, nil
}

func (r *fakePhase6Repository) CreateAdminerToken(ctx context.Context, ownerID int64) (types.AdminerSSO, error) {
	r.adminerOwnerID = ownerID
	return types.AdminerSSO{Token: "adminer-token", ExpiresAtUnix: 1770000000}, nil
}

func (r *fakePhase6Repository) RestoreBackup(ctx context.Context, ownerID int64, backupID int64) (int64, error) {
	r.restoreOwnerID = ownerID
	r.restoreBackupID = backupID
	return 105, nil
}

func TestManagerPhase6ActionsRequireAdmin(t *testing.T) {
	repo := &fakePhase6Repository{}
	manager := NewManager(nil, WithPhase6Repository(repo))
	client := auth.SessionUser{ID: 2, Role: auth.RoleClient}

	if _, err := manager.CreateBackup(context.Background(), client, types.CreateBackupReq{Domain: "example.test"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateBackup error = %v, want ErrForbidden", err)
	}
	if _, err := manager.ConfigureWebmail(context.Background(), client, "example.test"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ConfigureWebmail error = %v, want ErrForbidden", err)
	}
	if _, err := manager.ConfigureDNS(context.Background(), client, "example.test", "192.0.2.10"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ConfigureDNS error = %v, want ErrForbidden", err)
	}
	if _, err := manager.ReconcileSystem(context.Background(), client); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ReconcileSystem error = %v, want ErrForbidden", err)
	}
	if _, err := manager.CreateAdminerToken(context.Background(), client); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateAdminerToken error = %v, want ErrForbidden", err)
	}
	if _, err := manager.RestoreBackup(context.Background(), client, 7); !errors.Is(err, ErrForbidden) {
		t.Fatalf("RestoreBackup error = %v, want ErrForbidden", err)
	}
	if repo.backupReq.Domain != "" || repo.webmailDomain != "" || repo.dnsDomain != "" || repo.reconcileOwnerID != 0 || repo.adminerOwnerID != 0 || repo.restoreOwnerID != 0 {
		t.Fatalf("non-admin invoked repository: %#v", repo)
	}
}

func TestManagerPhase6ActionsNormalizeAndForwardAdminRequests(t *testing.T) {
	repo := &fakePhase6Repository{}
	manager := NewManager(nil, WithPhase6Repository(repo))
	admin := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}

	if id, err := manager.CreateBackup(context.Background(), admin, types.CreateBackupReq{Domain: " EXAMPLE.TEST. "}); err != nil || id != 101 {
		t.Fatalf("CreateBackup id=%d err=%v, want 101 nil", id, err)
	}
	if id, err := manager.ConfigureWebmail(context.Background(), admin, " EXAMPLE.TEST. "); err != nil || id != 102 {
		t.Fatalf("ConfigureWebmail id=%d err=%v, want 102 nil", id, err)
	}
	if id, err := manager.ConfigureDNS(context.Background(), admin, " EXAMPLE.TEST. ", "192.0.2.10"); err != nil || id != 103 {
		t.Fatalf("ConfigureDNS id=%d err=%v, want 103 nil", id, err)
	}
	if id, err := manager.ReconcileSystem(context.Background(), admin); err != nil || id != 104 {
		t.Fatalf("ReconcileSystem id=%d err=%v, want 104 nil", id, err)
	}
	token, err := manager.CreateAdminerToken(context.Background(), admin)
	if err != nil || token.Token != "adminer-token" {
		t.Fatalf("CreateAdminerToken token=%#v err=%v, want adminer-token nil", token, err)
	}
	if id, err := manager.RestoreBackup(context.Background(), admin, 7); err != nil || id != 105 {
		t.Fatalf("RestoreBackup id=%d err=%v, want 105 nil", id, err)
	}

	if repo.backupReq.Domain != "example.test" || repo.webmailDomain != "example.test" || repo.dnsDomain != "example.test" || repo.dnsAddress != "192.0.2.10" {
		t.Fatalf("repository requests not normalized: %#v", repo)
	}
	if repo.backupOwnerID != 1 || repo.webmailOwnerID != 1 || repo.dnsOwnerID != 1 || repo.reconcileOwnerID != 1 || repo.adminerOwnerID != 1 || repo.restoreOwnerID != 1 || repo.restoreBackupID != 7 {
		t.Fatalf("repository owner IDs = %#v, want all 1", repo)
	}
}
