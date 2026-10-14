package panelhttp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeRemovalService struct {
	preview   types.SiteRemovalPreview
	operation types.SiteRemovalOperation
	err       error
	removeErr error
	calls     int
	request   types.RemoveSiteReq
}

func (f *fakeRemovalService) PreviewSiteRemoval(context.Context, auth.SessionUser, int64) (types.SiteRemovalPreview, error) {
	return f.preview, f.err
}
func (f *fakeRemovalService) RemoveSiteFor(_ context.Context, _ auth.SessionUser, req types.RemoveSiteReq) (types.SiteRemovalOperation, error) {
	f.calls++
	f.request = req
	if req.ConfirmDomain != f.preview.Domain || !req.AcknowledgePermanent {
		return types.SiteRemovalOperation{}, errors.New("confirm the exact domain and permanent removal")
	}
	if f.removeErr != nil {
		return f.operation, f.removeErr
	}
	return f.operation, f.err
}
func (f *fakeRemovalService) SiteRemovalFor(context.Context, auth.SessionUser, int64) (types.SiteRemovalOperation, error) {
	return f.operation, f.err
}
func (f *fakeRemovalService) SiteRemovalByRequestFor(context.Context, auth.SessionUser, string) (types.SiteRemovalOperation, error) {
	return f.operation, f.err
}
func (f *fakeRemovalService) RetrySiteRemovalFor(context.Context, auth.SessionUser, int64) (types.SiteRemovalOperation, error) {
	f.calls++
	return f.operation, f.err
}

func removalHTTPFixture(t *testing.T) (http.Handler, *http.Cookie, *fakeRemovalService) {
	t.Helper()
	f := &fakeRemovalService{preview: types.SiteRemovalPreview{SiteID: 7, SubscriptionID: 20, CustomerID: 88, Domain: "addon.example.test", Kind: "website", Allowed: true, RequiresHostnameConfirmation: true, Digest: strings.Repeat("a", 64), Snapshot: types.SiteRemovalSnapshot{Sites: []types.SiteRemovalSite{{SiteID: 7, Domain: "addon.example.test"}}, Databases: []types.SiteRemovalDatabase{{ID: 9, Name: "app_db", DeletionEligible: true}}}}, operation: types.SiteRemovalOperation{ID: 42, SiteID: 7, SubscriptionID: 20, CustomerID: 88, Domain: "addon.example.test", State: "queued", Stage: types.RemovalWaiting, Revision: 1}}
	h, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{SiteRemoval: f, DashboardReader: &fakeDashboardReader{data: dashboard.Data{Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Fixture"}}}}})
	return h, login(t, h, "admin@nakpanel.test", "NakpanelAdmin!2026"), f
}
func removalPreviewHTTP(t *testing.T, h http.Handler, cookie *http.Cookie, path string) map[string]any {
	t.Helper()
	r := httptest.NewRequest("GET", "https://panel.test"+path, nil)
	r.AddCookie(cookie)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("preview status=%d cache=%s", w.Code, w.Header().Get("Cache-Control"))
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}
func TestSiteRemovalPreviewAndDefaultRetention(t *testing.T) {
	h, c, f := removalHTTPFixture(t)
	p := removalPreviewHTTP(t, h, c, "/sites/7/removal/preview")
	if f.calls != 0 || p["approval"] == "" || p["request_id"] == "" {
		t.Fatal("preview mutated or unsigned", p)
	}
	html, _ := p["html"].(string)
	if !strings.Contains(html, "Databases and backups are kept by default") || !strings.Contains(html, "addon.example.test") || strings.Contains(html, "delete_database_ids\" value=\"9\" checked") {
		t.Fatal("unsafe defaults", html)
	}
}
func TestSiteRemovalJSONAndHTMLProgress(t *testing.T) {
	for _, enhanced := range []bool{true, false} {
		t.Run(string(rune('0'+boolInt(enhanced))), func(t *testing.T) {
			h, c, f := removalHTTPFixture(t)
			p := removalPreviewHTTP(t, h, c, "/sites/7/removal/preview")
			form := url.Values{"approval": {p["approval"].(string)}, "request_id": {p["request_id"].(string)}, "confirm_domain": {"addon.example.test"}, "acknowledge_permanent": {"true"}}
			r := httptest.NewRequest("POST", "https://panel.test/sites/7/remove", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if enhanced {
				r.Header.Set("X-Nakpanel-SPA", "true")
			}
			addAuthenticatedCookie(r, c)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 303
			if enhanced {
				want = 202
			}
			if w.Code != want || f.calls != 1 {
				t.Fatalf("accepted=%d calls=%d %s", w.Code, f.calls, w.Body.String())
			}
			if enhanced && !strings.Contains(w.Body.String(), `"status_url":"/site-removals/42/status"`) {
				t.Fatal(w.Body.String())
			}
			if !enhanced && w.Header().Get("Location") != "/site-removals/42" {
				t.Fatal(w.Header())
			}
		})
	}
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func TestSiteRemovalCSRFAndSupportScope(t *testing.T) {
	h, c, f := removalHTTPFixture(t)
	for _, path := range []string{"/support/customers/99/sites/7/removal/preview", "/support/customers/99/site-removals/42/status"} {
		r := httptest.NewRequest("GET", "https://panel.test"+path, nil)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "https://panel.test/sites/7/remove", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || f.calls != 0 {
		t.Fatal(w.Code, f.calls)
	}
	f.err = provision.ErrForbidden
	r = httptest.NewRequest("GET", "https://panel.test/sites/7/removal/preview", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestSiteRemovalHistoricalCompletionHasSafeDestination(t *testing.T) {
	h, c, f := removalHTTPFixture(t)
	f.operation.State = "completed"
	r := httptest.NewRequest("GET", "https://panel.test/site-removals/42/status", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"redirect":"/subscriptions/20?tab=websites`) || strings.Contains(w.Body.String(), `"redirect":"/sites/7`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestSiteRemovalApprovalIsSessionScopeAndTimeBound(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	p := types.SiteRemovalPreview{SiteID: 7, SubscriptionID: 20, CustomerID: 88, Digest: strings.Repeat("a", 64)}
	now := time.Now()
	token, requestID, err := signSiteRemovalApproval(key, "session-a", p, 88, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		session       string
		site, support int64
		now           time.Time
		valid         bool
	}{{"session-a", 7, 88, now, true}, {"session-b", 7, 88, now, false}, {"session-a", 8, 88, now, false}, {"session-a", 7, 99, now, false}, {"session-a", 7, 88, now.Add(11 * time.Minute), false}} {
		_, err = verifySiteRemovalApproval(key, tc.session, token, requestID, tc.site, tc.support, tc.now)
		if (err == nil) != tc.valid {
			t.Fatal("approval binding", tc, err)
		}
	}
}

func TestSiteRemovalWrongHostnameAndExpiredApprovalPreserveConfirmation(t *testing.T) {
	h, c, f := removalHTTPFixture(t)
	p := removalPreviewHTTP(t, h, c, "/sites/7/removal/preview")
	for _, enhanced := range []bool{true, false} {
		form := url.Values{"approval": {p["approval"].(string)}, "request_id": {p["request_id"].(string)}, "confirm_domain": {"wrong.test"}, "acknowledge_permanent": {"true"}}
		r := httptest.NewRequest("POST", "https://panel.test/sites/7/remove", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if enhanced {
			r.Header.Set("X-Nakpanel-SPA", "true")
		}
		addAuthenticatedCookie(r, c)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
		if !enhanced && (!strings.Contains(w.Body.String(), `value="wrong.test"`) || !strings.Contains(w.Body.String(), "Review removal")) {
			t.Fatal("confirmation values were lost")
		}
	}
	before := f.calls
	r := httptest.NewRequest("POST", "https://panel.test/sites/7/remove", strings.NewReader("approval=invalid&request_id=invalid"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Nakpanel-SPA", "true")
	addAuthenticatedCookie(r, c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || f.calls != before {
		t.Fatal("invalid approval reached removal", w.Code, f.calls)
	}
}
func TestSiteRemovalSupportPrefixAndAnonymousStatus(t *testing.T) {
	h, c, f := removalHTTPFixture(t)
	p := removalPreviewHTTP(t, h, c, "/support/customers/88/sites/7/removal/preview")
	if !strings.Contains(p["html"].(string), `action="/support/customers/88/sites/7/remove"`) {
		t.Fatal("support action lost context")
	}
	r := httptest.NewRequest("GET", "https://panel.test/site-removals/42/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	f.err = provision.ErrForbidden
	r = httptest.NewRequest("GET", "https://panel.test/site-removals/999/status", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestSiteRemovalStaticAssetDoesNotListDirectories(t *testing.T) {
	h, _, _ := removalHTTPFixture(t)
	for _, tc := range []struct {
		path   string
		status int
	}{{"/assets/site-removal.js", 200}, {"/assets/", 404}, {"/assets/static/site-removal.js", 404}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "https://panel.test"+tc.path, nil))
		if w.Code != tc.status {
			t.Fatal(tc.path, w.Code)
		}
	}
}

type retainedBackupHTTPService struct {
	*fakePhase6Manager
	target          int64
	downloadCalls   int
	downloadErr     error
	downloadCorrupt bool
}

func (f *retainedBackupHTTPService) RestoreBackupToSiteFor(_ context.Context, _ auth.SessionUser, backup, target int64) (int64, error) {
	f.target = target
	f.restoreBackup = backup
	return 19, nil
}
func (f *retainedBackupHTTPService) ReadBackupFor(_ context.Context, _ auth.SessionUser, id, offset int64, _ int) (types.ReadBackupChunkResult, error) {
	f.downloadCalls++
	if f.downloadErr != nil {
		return types.ReadBackupChunkResult{}, f.downloadErr
	}
	data := []byte("backup fixture")
	checksum := fmt.Sprintf("%x", sha256.Sum256(data))
	if f.downloadCorrupt {
		data[0] = 'x'
	}
	return types.ReadBackupChunkResult{SHA256: checksum, BackupID: id, Offset: offset, Size: int64(len(data)), Data: data[offset:]}, nil
}
func TestSiteRemovalRetainedBackupHTTPUsesExplicitTargetAndScopedDownload(t *testing.T) {
	f := &retainedBackupHTTPService{fakePhase6Manager: &fakePhase6Manager{}}
	h, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Phase6Manager: f, Workspace: &fakeWorkspaceService{}})
	c := login(t, h, "admin@nakpanel.test", "NakpanelAdmin!2026")
	r := httptest.NewRequest("POST", "https://panel.test/restores", strings.NewReader("backup_id=9&target_site_id=8"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addAuthenticatedCookie(r, c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || f.target != 8 || f.restoreBackup != 9 {
		t.Fatal(w.Code, f.target, f.restoreBackup)
	}
	r = httptest.NewRequest("GET", "https://panel.test/backups/9/download", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "backup fixture" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal(w.Code, w.Header())
	}
	r = httptest.NewRequest("GET", "https://panel.test/support/customers/99/backups/9/download", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 || f.downloadCalls != 1 {
		t.Fatal(w.Code, f.downloadCalls)
	}
}

func TestSiteRemovalBackupDownloadWithholdsCorruptedFinalChunk(t *testing.T) {
	f := &retainedBackupHTTPService{fakePhase6Manager: &fakePhase6Manager{}, downloadCorrupt: true}
	h, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Phase6Manager: f})
	c := login(t, h, "admin@nakpanel.test", "NakpanelAdmin!2026")
	r := httptest.NewRequest("GET", "https://panel.test/backups/9/download", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.Len() == len("backup fixture") {
		t.Fatal("corrupt stream was reported as a complete archive")
	}
}

func TestSiteRemovalChangedImpactRequiresFreshConsent(t *testing.T) {
	h, c, f := removalHTTPFixture(t)
	p := removalPreviewHTTP(t, h, c, "/sites/7/removal/preview")
	f.removeErr = provision.ErrRemovalPreviewChanged
	form := url.Values{"approval": {p["approval"].(string)}, "request_id": {p["request_id"].(string)}, "confirm_domain": {"addon.example.test"}, "acknowledge_permanent": {"true"}, "include_children": {"true"}}
	for _, enhanced := range []bool{true, false} {
		r := httptest.NewRequest("POST", "https://panel.test/sites/7/remove", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if enhanced {
			r.Header.Set("X-Nakpanel-SPA", "true")
		}
		addAuthenticatedCookie(r, c)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
		if enhanced {
			if !strings.Contains(w.Body.String(), `"refresh_preview":true`) {
				t.Fatal("stale approval can be resubmitted without reviewing new impact")
			}
		} else if strings.Contains(w.Body.String(), `name="acknowledge_permanent" value="true" required checked`) {
			t.Fatal("old consent copied into changed removal scope")
		}
	}
}
