package panelhttp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type planPHPHTTPFixture struct {
	fakeQuotaManager
	input                     controlquota.PlanPHPVersionsInput
	actor                     auth.SessionUser
	previewCalls, updateCalls int
	narrowErr                 error
}

func (m *planPHPHTTPFixture) PreviewPlanPHPVersions(_ context.Context, actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsPreview, error) {
	m.previewCalls++
	m.input = input
	m.actor = actor
	return controlquota.PlanPHPVersionsPreview{PlanID: id, Revision: 3, Preview: types.PlanPreview{Allowed: true}}, m.narrowErr
}
func (m *planPHPHTTPFixture) UpdatePlanPHPVersions(_ context.Context, actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsResult, error) {
	m.updateCalls++
	m.input = input
	m.actor = actor
	return controlquota.PlanPHPVersionsResult{PlanID: id, Revision: 4, Changed: true, SyncState: "pending"}, m.narrowErr
}

func TestPlanPHPHTTPStrictFieldsAndPreview(t *testing.T) {
	for _, tt := range []struct {
		name, extra, query, media string
		csrf                      bool
		want                      int
	}{
		{"valid", "", "", "application/x-www-form-urlencoded", true, 200},
		{"extra full form", "&disk_mb=999", "", "application/x-www-form-urlencoded", true, 400},
		{"duplicate revision", "&expected_revision=3", "", "application/x-www-form-urlencoded", true, 400},
		{"query override", "", "?default_php_version=8.3", "application/x-www-form-urlencoded", true, 400},
		{"JSON rejected", "", "", "application/json", true, 400},
		{"CSRF required", "", "", "application/x-www-form-urlencoded", false, 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager := &planPHPHTTPFixture{}
			handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
			cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
			form := url.Values{"expected_revision": {"3"}, "php_versions": {"8.5", "8.3"}, "default_php_version": {"8.5"}, "change_reason": {"Explicit PHP maintenance"}}
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/plans/5/php-versions/preview"+tt.query, strings.NewReader(form.Encode()+tt.extra))
			req.Header.Set("Content-Type", tt.media)
			addAuthenticatedCookie(req, cookie)
			if !tt.csrf {
				req.Header.Del("X-Nakpanel-CSRF")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status %d want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == 200 {
				var raw map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
					t.Fatal(err)
				}
				if blockers, ok := raw["blockers"].([]any); !ok || len(blockers) != 0 {
					t.Fatal("successful blockers must be an empty array")
				}
				var response struct {
					OK       bool `json:"ok"`
					Revision int  `json:"revision"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || !response.OK || response.Revision != 3 {
					t.Fatalf("preview envelope %s %v", rec.Body.String(), err)
				}
				if manager.previewCalls != 1 || manager.updateCalls != 0 || manager.input.PHPVersions[0] != "8.3" || manager.actor.ID != 1 {
					t.Fatal("preview did not use strict narrow authenticated command")
				}
			} else if manager.previewCalls+manager.updateCalls != 0 {
				t.Fatal("invalid request reached manager")
			}
		})
	}
}

func TestPlanPHPHTTPApplyConflictAndRole(t *testing.T) {
	manager := &planPHPHTTPFixture{narrowErr: &controlquota.PlanPHPConflictError{Code: "stale_revision", ExpectedRevision: 3, CurrentRevision: 4}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://panel.test/plans/5/php-versions", strings.NewReader("expected_revision=3&php_versions=8.5&default_php_version=8.5&change_reason=Explicit"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addAuthenticatedCookie(req, cookie)
		return req
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, request())
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"code":"stale_revision"`) {
		t.Fatalf("conflict %d %s", rec.Code, rec.Body.String())
	}
	manager.narrowErr = nil
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, request())
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"sync_state":"pending"`) {
		t.Fatalf("apply %d %s", rec.Code, rec.Body.String())
	}
	clientHandler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{QuotaManager: manager})
	clientCookie := login(t, clientHandler, "client@nakpanel.test", "NakpanelClient!2026")
	req := request()
	req.Header.Del("Cookie")
	addAuthenticatedCookie(req, clientCookie)
	rec = httptest.NewRecorder()
	clientHandler.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("client scope %d", rec.Code)
	}
}

func TestPlanPHPHTTPMalformedFormCannotHideBehindBodyCSRF(t *testing.T) {
	for _, headerToken := range []bool{false, true} {
		for _, malformed := range []bool{false, true} {
			manager := &planPHPHTTPFixture{}
			handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
			cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
			tokenRequest := httptest.NewRequest(http.MethodPost, "https://panel.test/plans/5/php-versions/preview", nil)
			addAuthenticatedCookie(tokenRequest, cookie)
			body := "expected_revision=3&php_versions=8.5&default_php_version=8.5&change_reason=Explicit&csrf_token=" + csrfToken(tokenRequest)
			if malformed {
				body += "&unknown=%zz"
			}
			req := httptest.NewRequest(http.MethodPost, tokenRequest.URL.String(), strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			addAuthenticatedCookie(req, cookie)
			if !headerToken {
				req.Header.Del("X-Nakpanel-CSRF")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			want, calls := 200, 1
			if malformed {
				want, calls = 400, 0
			}
			if rec.Code != want || manager.previewCalls != calls {
				t.Fatalf("header=%t malformed=%t status=%d manager calls=%d", headerToken, malformed, rec.Code, manager.previewCalls)
			}
		}
	}
}

type planPHPUnavailableConnector struct{ calls *atomic.Int32 }

func (c planPHPUnavailableConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c.calls.Add(1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return nil, errors.New("private transport diagnostic")
	}
}
func (c planPHPUnavailableConnector) Driver() driver.Driver { return planPHPUnavailableDriver{} }

type planPHPUnavailableDriver struct{}

func (planPHPUnavailableDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("unreachable driver fallback")
}

func TestPlanPHPHTTPUnavailableStoreIsSafe503(t *testing.T) {
	for _, closed := range []bool{false, true} {
		for _, route := range []string{"", "/preview"} {
			var calls atomic.Int32
			db := sql.OpenDB(planPHPUnavailableConnector{calls: &calls})
			defer db.Close()
			if closed {
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			manager := provision.NewManager(nil, provision.WithQuotaStore(controlquota.NewSQLStore(db)))
			handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{QuotaManager: manager})
			cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/plans/5/php-versions"+route, strings.NewReader("expected_revision=3&php_versions=8.5&default_php_version=8.5&change_reason=Owned"))
			req = req.WithContext(ctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			addAuthenticatedCookie(req, cookie)
			rec := httptest.NewRecorder()
			started := time.Now()
			handler.ServeHTTP(rec, req)
			cancel()
			if rec.Code != 503 || !strings.Contains(rec.Body.String(), `"code":"unavailable"`) || strings.Contains(rec.Body.String(), "private transport") || strings.Contains(rec.Body.String(), "database is closed") || time.Since(started) >= 500*time.Millisecond {
				t.Fatalf("closed=%t route=%s dependency response=%d %s", closed, route, rec.Code, rec.Body.String())
			}
			want := int32(1)
			if closed {
				want = 0
			}
			if calls.Load() != want {
				t.Fatalf("closed=%t actual connects=%d want%d", closed, calls.Load(), want)
			}
		}
	}
	for _, err := range []error{controlquota.ErrResellerCapacity, controlquota.ErrOversellCap, controlquota.ErrSubscriptionTerminating, &controlquota.PlanPHPRejectedError{Cause: errors.New("known validation refusal")}} {
		rec := httptest.NewRecorder()
		writePlanPHPFailure(rec, err)
		if rec.Code != 400 {
			t.Fatalf("known domain rejection misclassified: %v %d", err, rec.Code)
		}
	}
}

func TestPlanPHPHTTPOnlySafeFailureEnvelopesBypassUIRewrite(t *testing.T) {
	for _, tt := range []struct {
		body, path string
		preserved  bool
	}{
		{`{"code":"unavailable","error":"Plan operation is unavailable","ok":false}`, "/plans/5/php-versions", true},
		{`{"code":"readiness_unavailable","error":"Authoritative PHP readiness is unavailable","ok":false}`, "/plans/5/php-versions/preview", true},
		{`{"code":"plan_timeout","error":"Plan operation exceeded its deadline","ok":false}`, "/plans/5/php-versions", true},
		{`{"code":"unavailable","error":"private transport diagnostic","ok":false}`, "/plans/5/php-versions", false},
		{`{"code":"unavailable","error":"Plan operation is unavailable","ok":false,"private":"diagnostic"}`, "/plans/5/php-versions", false},
		{`{"code":"unavailable","error":"Plan operation is unavailable","ok":false}`, "/plans", false},
		{`{"code":"unavailable","error":"private diagnostic","error":"Plan operation is unavailable","ok":false}`, "/plans/5/php-versions", false},
	} {
		handler := userFacingErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
			_, _ = w.Write([]byte(tt.body))
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://panel.test"+tt.path, nil))
		if strings.Contains(rec.Body.String(), `"code":`) != tt.preserved || strings.Contains(rec.Body.String(), "private") || strings.Contains(rec.Body.String(), "diagnostic") {
			t.Fatalf("unsafe or lost envelope: %s", rec.Body.String())
		}
	}
	panicHandler := userFacingErrors(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("private panic diagnostic")
	}))
	rec := httptest.NewRecorder()
	panicHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://panel.test/plans/5/php-versions", nil))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "private") || strings.Contains(rec.Body.String(), "diagnostic") {
		t.Fatalf("panic bypassed normal sanitizer: %d %s", rec.Code, rec.Body.String())
	}
}
