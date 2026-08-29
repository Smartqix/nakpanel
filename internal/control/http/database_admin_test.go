package panelhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/databaseadmin"
	"github.com/nakroteck/nakpanel/internal/control/platformadmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeDatabaseAdminService struct {
	actorID     int64
	databaseID  int64
	password    string
	role        platformadmin.DatabaseRole
	rotateCalls int
	roleCalls   int
}

func (*fakeDatabaseAdminService) Snapshot(context.Context) (databaseadmin.Snapshot, error) {
	return databaseadmin.Snapshot{}, nil
}

func (f *fakeDatabaseAdminService) RotatePassword(_ context.Context, actorID, databaseID int64, password string) (types.ManageDatabaseAdminResult, error) {
	f.actorID, f.databaseID, f.password = actorID, databaseID, password
	f.rotateCalls++
	return types.ManageDatabaseAdminResult{
		OperationID: "op_123456789012345678901234", DatabaseID: databaseID,
		Action: types.DatabaseAdminRotatePassword, Status: "queued",
	}, nil
}

func (f *fakeDatabaseAdminService) SetRole(_ context.Context, actorID, databaseID int64, role platformadmin.DatabaseRole) (types.ManageDatabaseAdminResult, error) {
	f.actorID, f.databaseID, f.role = actorID, databaseID, role
	f.roleCalls++
	return types.ManageDatabaseAdminResult{
		OperationID: "op_123456789012345678901234", DatabaseID: databaseID,
		Action: types.DatabaseAdminSetRole, Role: types.DatabaseAdminRole(role), Status: "queued",
	}, nil
}

func (*fakeDatabaseAdminService) Check(context.Context, int64) (types.ManageDatabaseAdminResult, error) {
	return types.ManageDatabaseAdminResult{}, nil
}

func TestDatabaseAdminInputRejectsUnknownFields(t *testing.T) {
	for _, request := range []*http.Request{
		func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/databases/1/role",
				strings.NewReader(`{"role":"read-only","sql":"DROP DATABASE mysql"}`))
			req.Header.Set("Content-Type", "application/json")
			return req
		}(),
		func() *http.Request {
			form := url.Values{"role": {"read-only"}, "path": {"/tmp/import.sql"}}
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/databases/1/role",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req
		}(),
	} {
		var input struct {
			Role string `json:"role"`
		}
		if err := decodeDatabaseAdminInput(request, &input, "role"); err == nil {
			t.Fatal("expected unknown database administration field to be rejected")
		}
	}
}

func TestDatabaseAdminCheckAcceptsOnlyEmptyObject(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/databases/1/check",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if err := decodeDatabaseAdminInput(req, &struct{}{}); err != nil {
		t.Fatalf("empty check request rejected: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/databases/1/check",
		strings.NewReader(`{"repair":true}`))
	req.Header.Set("Content-Type", "application/json")
	if err := decodeDatabaseAdminInput(req, &struct{}{}); err == nil {
		t.Fatal("repair field must not be accepted by integrity check")
	}
}

func TestDatabasePasswordRotationRequiresRecentAdminAuthAndReturnsQueued(t *testing.T) {
	service := &fakeDatabaseAdminService{}
	handler, sessions := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DatabaseAdmin: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	form := url.Values{"password": {"new_rotation_password_2026"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/databases/42/password",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || service.rotateCalls != 1 ||
		service.actorID != 1 || service.databaseID != 42 {
		t.Fatalf("queued rotation = status %d calls %d actor %d database %d body=%s",
			rec.Code, service.rotateCalls, service.actorID, service.databaseID, rec.Body.String())
	}

	sessions.user.AuthenticatedAt = time.Date(2026, 7, 7, 11, 49, 0, 0, time.UTC)
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/databases/42/password",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired || service.rotateCalls != 1 {
		t.Fatalf("stale-auth rotation = status %d calls %d", rec.Code, service.rotateCalls)
	}
}

func TestDatabaseRoleMutationIsAdminOnly(t *testing.T) {
	service := &fakeDatabaseAdminService{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{DatabaseAdmin: service})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	form := url.Values{"role": {"read-only"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/databases/42/role",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || service.roleCalls != 0 {
		t.Fatalf("client role mutation = status %d calls %d", rec.Code, service.roleCalls)
	}
}
