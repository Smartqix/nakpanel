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
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phase26EHTTPFake struct {
	inventory   types.ServerInventory
	updates     types.UpdateState
	updateReq   types.ApplyUpdatesReq
	updateUser  int64
	updateCalls int
	powerReq    types.HostPowerReq
	powerCalls  int
}

type phase26EOperationStatusFake struct {
	*phase26EHTTPFake
	operation serveradmin.Operation
	err       error
}

func (f *phase26EOperationStatusFake) OperationStatus(context.Context, string) (serveradmin.Operation, error) {
	return f.operation, f.err
}

func (f *phase26EHTTPFake) InspectServer(context.Context) (types.ServerInventory, error) {
	return f.inventory, nil
}

func (*phase26EHTTPFake) ControlManagedService(context.Context, types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	return types.ControlManagedServiceResult{}, nil
}

func (f *phase26EHTTPFake) InspectUpdates(context.Context) (types.UpdateState, error) {
	return f.updates, nil
}

func (f *phase26EHTTPFake) ApplyUpdates(_ context.Context, req types.ApplyUpdatesReq, userID int64) error {
	f.updateCalls++
	f.updateReq = req
	f.updateUser = userID
	return nil
}

func (f *phase26EHTTPFake) ControlHostPower(_ context.Context, req types.HostPowerReq) error {
	f.powerCalls++
	f.powerReq = req
	return nil
}

func (*phase26EHTTPFake) ApplicationCatalogInventory(context.Context) ([]types.ApplicationCatalogInventory, error) {
	return nil, nil
}

func TestPhase26EOperationDecodersRejectUnknownFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tools-settings/operations/power",
		strings.NewReader(`{"action":"reboot","confirmation":"REBOOT","out_of_band_acknowledged":true,"command":"id"}`))
	req.Header.Set("Content-Type", "application/json")
	if _, err := decodePhase26HostPowerInput(req); err == nil {
		t.Fatal("unknown host power field was accepted")
	}

	req = httptest.NewRequest(http.MethodPost, "/tools-settings/operations/updates",
		strings.NewReader(`{"package_names":["nginx"],"dry_run":true,"path":"/tmp"}`))
	req.Header.Set("Content-Type", "application/json")
	if _, err := decodePhase26UpdateInput(req); err == nil {
		t.Fatal("unknown managed update field was accepted")
	}
}

func TestPhase26EOperationDecodersCanonicalizeRegistryValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tools-settings/operations/power",
		strings.NewReader("action=%20REBOOT%20&confirmation=%20REBOOT%20"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	input, err := decodePhase26HostPowerInput(req)
	if err != nil {
		t.Fatal(err)
	}
	if input.Action != "reboot" || input.Confirmation != "REBOOT" {
		t.Fatalf("host input = %#v", input)
	}
}

func TestPhase26EUpdateInstallRequiresReauthenticationAndTypedConfirmation(t *testing.T) {
	admin := &phase26EHTTPFake{updates: types.UpdateState{Packages: []types.UpdatePackage{{
		Name: "nginx", Current: "1.24.0", Candidate: "1.24.1", Origin: "Ubuntu:noble-updates",
	}}}}
	handler, sessions := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	sessions.user.AuthenticatedAt = time.Date(2026, 7, 7, 11, 49, 0, 0, time.UTC)

	form := url.Values{
		"package_names": {"nginx"},
		"confirmation":  {"INSTALL UPDATES"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/operations/updates", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired || admin.updateCalls != 0 {
		t.Fatalf("stale update request = %d, calls=%d", rec.Code, admin.updateCalls)
	}

	sessions.user.AuthenticatedAt = time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	form.Set("confirmation", "install updates")
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/operations/updates", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || admin.updateCalls != 0 {
		t.Fatalf("unconfirmed update request = %d, calls=%d", rec.Code, admin.updateCalls)
	}

	form.Set("confirmation", "INSTALL UPDATES")
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/operations/updates", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || admin.updateCalls != 1 ||
		len(admin.updateReq.PackageNames) != 1 || admin.updateReq.PackageNames[0] != "nginx" ||
		len(admin.updateReq.Packages) != 1 || admin.updateReq.Packages[0].Candidate != "1.24.1" ||
		admin.updateUser <= 0 || !strings.HasPrefix(admin.updateReq.OperationID, "op_") {
		t.Fatalf("confirmed update = %d req=%#v user=%d calls=%d; body=%s",
			rec.Code, admin.updateReq, admin.updateUser, admin.updateCalls, rec.Body.String())
	}
}

func TestPhase26EShutdownRequiresCurrentHostnameConfirmation(t *testing.T) {
	admin := &phase26EHTTPFake{inventory: types.ServerInventory{Hostname: "panel-01"}}
	handler, sessions := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	sessions.user.AuthenticatedAt = time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)

	for _, confirmation := range []string{"SHUTDOWN", "panel-02"} {
		form := url.Values{"action": {"shutdown"}, "confirmation": {confirmation}, "out_of_band_acknowledged": {"true"}}
		req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/operations/power", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || admin.powerCalls != 0 {
			t.Fatalf("shutdown confirmation %q = %d, calls=%d", confirmation, rec.Code, admin.powerCalls)
		}
	}

	form := url.Values{"action": {"shutdown"}, "confirmation": {"panel-01"}, "out_of_band_acknowledged": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/operations/power", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || admin.powerCalls != 1 ||
		admin.powerReq.Action != types.HostPowerShutdown || admin.powerReq.ActorUserID <= 0 {
		t.Fatalf("confirmed shutdown = %d req=%#v calls=%d; body=%s",
			rec.Code, admin.powerReq, admin.powerCalls, rec.Body.String())
	}
}

func TestPhase26EOperationStatusIsAdminOnlyAndRedactsInternalFailure(t *testing.T) {
	const operationID = "op_12345678901234567890"
	admin := &phase26EOperationStatusFake{
		phase26EHTTPFake: &phase26EHTTPFake{},
		operation: serveradmin.Operation{
			OperationID: operationID,
			Action:      "install_updates",
			TargetType:  "server_updates",
			TargetKey:   "selected_packages",
			Status:      serveradmin.OperationFailed,
			LastError:   "repository password=do-not-render",
		},
	}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/operations/"+operationID, nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "do-not-render") ||
		!strings.Contains(rec.Body.String(), `"status":"failed"`) {
		t.Fatalf("operation status = %d; body=%s", rec.Code, rec.Body.String())
	}

	clientHandler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{ServerAdmin: admin})
	clientCookie := login(t, clientHandler, "client@nakpanel.test", "NakpanelClient!2026")
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/operations/"+operationID, nil)
	addAuthenticatedCookie(req, clientCookie)
	rec = httptest.NewRecorder()
	clientHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("client operation status = %d, want 403", rec.Code)
	}
}
