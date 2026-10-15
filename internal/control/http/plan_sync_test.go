package panelhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestPlanSyncStatusRouteHasProviderBoundary(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleClient} {
		handler, _ := newTestHandlerWithOptions(t, role, ServerOptions{QuotaManager: &fakeQuotaManager{}})
		email, password := "admin@nakpanel.test", "NakpanelAdmin!2026"
		if role == auth.RoleClient {
			email, password = "client@nakpanel.test", "NakpanelClient!2026"
		}
		cookie := login(t, handler, email, password)
		req := httptest.NewRequest(http.MethodGet, "https://panel.test/plans/5/sync-status", nil)
		req.AddCookie(cookie)
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		want := http.StatusServiceUnavailable
		if role == auth.RoleClient {
			want = http.StatusForbidden
		}
		if result.Code != want {
			t.Fatalf("role %s: got %d, want %d", role, result.Code, want)
		}
	}
}

type planSyncFixture struct {
	fakeQuotaManager
	err error
}

func (f *planSyncFixture) PlanSynchronization(context.Context, auth.SessionUser, int64) (types.PlanSynchronization, error) {
	return types.PlanSynchronization{PlanID: 5, Revision: 3, State: "pending", Pending: 1}, f.err
}

func TestPlanSyncStatusReturnsScopedUncachedState(t *testing.T) {
	for _, fixture := range []struct {
		err    error
		status int
	}{
		{nil, http.StatusOK}, {provision.ErrForbidden, http.StatusNotFound}, {errors.New("private backend detail"), http.StatusServiceUnavailable},
	} {
		handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: &planSyncFixture{err: fixture.err}})
		cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
		req := httptest.NewRequest(http.MethodGet, "https://panel.test/plans/5/sync-status", nil)
		req.AddCookie(cookie)
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		if result.Code != fixture.status {
			t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
		}
		if !strings.Contains(result.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("plan status may be cached: %v", result.Header())
		}
		if fixture.err == nil {
			var payload struct {
				Synchronization types.PlanSynchronization `json:"synchronization"`
			}
			if err := json.Unmarshal(result.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Synchronization.Revision != 3 || payload.Synchronization.Pending != 1 {
				t.Fatalf("%+v", payload)
			}
		}
	}
}
