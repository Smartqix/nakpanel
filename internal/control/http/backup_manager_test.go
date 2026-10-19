package panelhttp

import (
	"context"
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type backupManagerHTTPFixture struct {
	fakePhase6Manager
	calls  int
	denied bool
}

func (f *backupManagerHTTPFixture) PreviewBackupRemovalFor(_ context.Context, _ auth.SessionUser, sub int64, ids []int64) (types.BackupRemovalPreview, error) {
	if f.denied || sub != 3 || len(ids) != 1 || ids[0] != 7 {
		return types.BackupRemovalPreview{}, provision.ErrForbidden
	}
	return types.BackupRemovalPreview{SubscriptionID: 3, CustomerID: 88, Digest: strings.Repeat("a", 64), SizeBytes: 123, Items: []types.BackupRemovalItem{{ID: 7, Domain: "removed.test", SizeBytes: 123, Retained: true, Status: "active"}}}, nil
}
func (f *backupManagerHTTPFixture) RemoveBackupsFor(_ context.Context, _ auth.SessionUser, sub int64, ids []int64, digest string, confirmed bool) error {
	if !confirmed || f.denied {
		return provision.ErrForbidden
	}
	f.calls++
	return nil
}
func (f *backupManagerHTTPFixture) BackupStatusFor(context.Context, auth.SessionUser, int64) (map[int64]string, error) {
	return map[int64]string{7: "active"}, nil
}

func TestBackupRemovalPreviewConfirmationCSRFAndFallback(t *testing.T) {
	for _, enhanced := range []bool{true, false} {
		t.Run(map[bool]string{true: "JSON", false: "HTML"}[enhanced], func(t *testing.T) {
			f := &backupManagerHTTPFixture{}
			h, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Phase6Manager: f, Workspace: &fakeWorkspaceService{}, DashboardReader: &fakeDashboardReader{data: dashboard.Data{Subscriptions: []types.SubscriptionSummary{{ID: 3, CustomerID: 88}}}}})
			cookie := login(t, h, "admin@nakpanel.test", "NakpanelAdmin!2026")
			r := httptest.NewRequest("GET", "https://panel.test/subscriptions/3/backups/remove?backup_id=7", nil)
			r.AddCookie(cookie)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("preview %d %s", w.Code, w.Body.String())
			}
			var p struct {
				Approval string `json:"approval"`
				HTML     string `json:"html"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if f.calls != 0 || p.Approval == "" || !strings.Contains(p.HTML, "removed.test") || !strings.Contains(p.HTML, "acknowledge_permanent") {
				t.Fatal("unsafe preview", p)
			}
			for _, confirmation := range []string{"", "true"} {
				form := url.Values{"backup_id": {"7"}, "approval": {p.Approval}, "acknowledge_permanent": {confirmation}}
				r = httptest.NewRequest("POST", "https://panel.test/subscriptions/3/backups/remove", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				addAuthenticatedCookie(r, cookie)
				if enhanced {
					r.Header.Set("X-Nakpanel-SPA", "true")
				}
				w = httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if confirmation == "" {
					if f.calls != 0 {
						t.Fatal("missing confirmation accepted")
					}
					continue
				}
				want := 303
				if enhanced {
					want = 202
				}
				if w.Code != want || f.calls != 1 {
					t.Fatalf("accepted=%d calls=%d %s", w.Code, f.calls, w.Body.String())
				}
				if !enhanced && w.Header().Get("Location") != "/subscriptions/3?tab=backups&notice=backups-removing" {
					t.Fatal(w.Header())
				}
			}
		})
	}
}

func TestBackupRemovalRejectsCSRFChangedSelectionAndProof(t *testing.T) {
	f := &backupManagerHTTPFixture{}
	h, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{Phase6Manager: f, Workspace: &fakeWorkspaceService{}})
	cookie := login(t, h, "admin@nakpanel.test", "NakpanelAdmin!2026")
	r := httptest.NewRequest("GET", "https://panel.test/subscriptions/3/backups/remove?backup_id=7", nil)
	r.AddCookie(cookie)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var p struct {
		Approval string `json:"approval"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &p); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"csrf", "selection", "proof", "empty"} {
		t.Run(kind, func(t *testing.T) {
			form := url.Values{"backup_id": {"7"}, "approval": {p.Approval}, "acknowledge_permanent": {"true"}}
			if kind == "selection" {
				form.Set("backup_id", "8")
			}
			if kind == "proof" {
				form.Set("approval", "x"+p.Approval)
			}
			if kind == "empty" {
				form.Del("backup_id")
			}
			r := httptest.NewRequest("POST", "https://panel.test/subscriptions/3/backups/remove", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("X-Nakpanel-SPA", "true")
			if kind == "csrf" {
				r.AddCookie(cookie)
			} else {
				addAuthenticatedCookie(r, cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || f.calls != 0 {
				t.Fatalf("unsafe %s: %d calls %d", kind, w.Code, f.calls)
			}
		})
	}
	for _, path := range []string{"/subscriptions/99/backups/remove?backup_id=7", "/subscriptions/3/backups/remove?backup_id=99", "/support/customers/99/subscriptions/3/backups/remove?backup_id=7"} {
		r := httptest.NewRequest("GET", "https://panel.test"+path, nil)
		r.AddCookie(cookie)
		r.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("scope %s: %d", path, w.Code)
		}
	}
}
