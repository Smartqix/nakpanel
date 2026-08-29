package panelhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phase26CoreServerAdminFake struct {
	phase26ServerAdminFake
	journalReq    types.ReadJournalReq
	journalResult types.ReadJournalResult
	journalCalls  int
	updateState   types.UpdateState
	updateCalls   int
	dryRunID      string
	dryRunCalls   int
	dryRunReq     types.ApplyUpdatesReq
	dryRunActorID int64
}

func (f *phase26CoreServerAdminFake) ReadJournal(_ context.Context, req types.ReadJournalReq) (types.ReadJournalResult, error) {
	f.journalCalls++
	f.journalReq = req
	return f.journalResult, nil
}

func (f *phase26CoreServerAdminFake) InspectUpdates(context.Context) (types.UpdateState, error) {
	f.updateCalls++
	return f.updateState, nil
}

func (f *phase26CoreServerAdminFake) ApplyUpdates(_ context.Context, req types.ApplyUpdatesReq, actorID int64) error {
	f.dryRunCalls++
	f.dryRunID = req.OperationID
	f.dryRunReq = req
	f.dryRunActorID = actorID
	return nil
}

func TestServerJournalUsesOnlyRegisteredBoundedQueries(t *testing.T) {
	admin := &phase26CoreServerAdminFake{journalResult: types.ReadJournalResult{
		Entries: []types.JournalEntry{{SourceID: "web", Message: "ready"}},
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/journal?source=web&hours=6&limit=100", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("journal = %d; body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || !response.OK {
		t.Fatalf("journal response = %q, err=%v", rec.Body.String(), err)
	}
	if admin.journalCalls != 1 || len(admin.journalReq.SourceIDs) != 1 || admin.journalReq.SourceIDs[0] != "web" ||
		admin.journalReq.Limit != 100 {
		t.Fatalf("journal request = %#v, calls=%d", admin.journalReq, admin.journalCalls)
	}

	for _, query := range []string{
		"source=../../etc/shadow", "source=web&limit=999", "source=web&hours=2", "source=web&command=id",
	} {
		req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/journal?"+query, nil)
		addAuthenticatedCookie(req, cookie)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unsafe journal query %q = %d; body=%s", query, rec.Code, rec.Body.String())
		}
	}
	if admin.journalCalls != 1 {
		t.Fatalf("unsafe journal queries reached agent: calls=%d", admin.journalCalls)
	}
}

func TestUpdateInventoryAndDryRunCannotAcceptPackageNames(t *testing.T) {
	admin := &phase26CoreServerAdminFake{updateState: types.UpdateState{
		Packages:      []types.UpdatePackage{{Name: "openssl", Security: true}},
		SecurityCount: 1,
	}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/updates/inventory", nil)
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || admin.updateCalls != 1 {
		t.Fatalf("update inventory = %d calls=%d; body=%s", rec.Code, admin.updateCalls, rec.Body.String())
	}

	form := url.Values{"package_name": {"../../bin/sh"}}
	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/updates/dry-run", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || admin.dryRunCalls != 0 {
		t.Fatalf("unsafe update dry-run = %d calls=%d; body=%s", rec.Code, admin.dryRunCalls, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "https://panel.test/tools-settings/updates/dry-run", nil)
	addAuthenticatedCookie(req, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || admin.updateCalls != 2 || admin.dryRunCalls != 1 ||
		!strings.HasPrefix(admin.dryRunID, "op_") || !admin.dryRunReq.DryRun ||
		len(admin.dryRunReq.Packages) != 1 || admin.dryRunActorID <= 0 {
		t.Fatalf("update dry-run = %d calls=%d id=%q; body=%s", rec.Code, admin.dryRunCalls, admin.dryRunID, rec.Body.String())
	}
}

func TestServerCoreReadsRemainAdminOnly(t *testing.T) {
	admin := &phase26CoreServerAdminFake{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleReseller, ServerOptions{ServerAdmin: admin})
	cookie := login(t, handler, "reseller@nakpanel.test", "NakpanelReseller!2026")
	for _, path := range []string{"/tools-settings/journal", "/tools-settings/updates/inventory"} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("reseller GET %s = %d", path, rec.Code)
		}
	}
	if admin.journalCalls != 0 || admin.updateCalls != 0 {
		t.Fatalf("reseller reached server core reads: journal=%d updates=%d", admin.journalCalls, admin.updateCalls)
	}
}
