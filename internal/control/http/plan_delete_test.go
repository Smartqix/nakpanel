package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

type deletePlanFixture struct {
	fakeQuotaManager
	deleted int64
	err     error
}

func TestDeletePlanFailuresDoNotReportSuccess(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{controlquota.ErrPlanInUse, http.StatusConflict},
		{provision.ErrForbidden, http.StatusNotFound},
		{errors.New("private database error"), http.StatusInternalServerError},
	} {
		fixture := &deletePlanFixture{err: tc.err}
		workspace := &fakeWorkspaceService{}
		handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: fixture, Workspace: workspace})
		cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
		req := httptest.NewRequest(http.MethodPost, "https://panel.test/plans/42/delete", nil)
		req.Header.Set("Origin", "https://panel.test")
		req.AddCookie(cookie)
		req.Header.Set("X-Nakpanel-CSRF", csrfToken(req))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status || fixture.deleted != 0 || len(workspace.audits) != 0 {
			t.Fatalf("failed deletion status=%d deleted=%d audits=%v", rec.Code, fixture.deleted, workspace.audits)
		}
		if tc.status == http.StatusConflict && !strings.Contains(rec.Body.String(), "subscriptions") {
			t.Fatal("missing explanation that subscriptions block deletion")
		}
		if strings.Contains(rec.Body.String(), "private database error") {
			t.Fatal("backend error leaked")
		}
	}
}

func (f *deletePlanFixture) DeletePlan(_ context.Context, _ auth.SessionUser, id int64) error {
	if f.err == nil {
		f.deleted = id
	}
	return f.err
}

func TestDeletePlanRouteRequiresProviderAndCSRF(t *testing.T) {
	for _, tc := range []struct {
		name string
		role auth.Role
		csrf bool
		id   string
		want int
	}{
		{"admin", auth.RoleAdmin, true, "42", http.StatusSeeOther},
		{"reseller", auth.RoleReseller, true, "42", http.StatusSeeOther},
		{"client", auth.RoleClient, true, "42", http.StatusForbidden},
		{"csrf", auth.RoleAdmin, false, "42", http.StatusForbidden},
		{"invalid", auth.RoleAdmin, true, "0", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &deletePlanFixture{}
			workspace := &fakeWorkspaceService{}
			handler, _ := newTestHandlerWithOptions(t, tc.role, ServerOptions{QuotaManager: fixture, Workspace: workspace})
			email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
			if tc.role == auth.RoleReseller {
				email, password = "reseller@nakpanel.test", "NakpanelReseller!2026"
			}
			if tc.role == auth.RoleClient {
				email, password = "client@nakpanel.test", "NakpanelClient!2026"
			}
			cookie := login(t, handler, email, password)
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/plans/"+tc.id+"/delete", strings.NewReader(""))
			req.Header.Set("Origin", "https://panel.test")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			if tc.csrf {
				req.Header.Set("X-Nakpanel-CSRF", csrfToken(req))
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusSeeOther {
				if fixture.deleted != 42 || rec.Header().Get("Location") != "/service-plans?type=hosting&notice=plan-deleted" {
					t.Fatalf("deletion/redirect missing: %d %s", fixture.deleted, rec.Header().Get("Location"))
				}
				if len(workspace.audits) != 1 || workspace.audits[0].Action != "plan.deleted" {
					t.Fatalf("missing deletion audit: %+v", workspace.audits)
				}
			} else if fixture.deleted != 0 || len(workspace.audits) != 0 {
				t.Fatal("rejected request mutated plan or recorded success")
			}
		})
	}
}
