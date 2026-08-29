package panelhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/platformadmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phase26DMailFake struct {
	searchCalls  int
	searchFilter platformadmin.MailQueueFilter
	inspectID    string
	logCalls     int
}

func (*phase26DMailFake) MailSettings(context.Context, auth.SessionUser) (types.MailSettingsView, error) {
	return types.MailSettingsView{}, nil
}

func (*phase26DMailFake) UpdateMailSettings(context.Context, auth.SessionUser, types.MailSettingsUpdate) (types.MailSettingsView, error) {
	return types.MailSettingsView{}, nil
}

func (*phase26DMailFake) ReconfigureMail(context.Context, auth.SessionUser) error {
	return nil
}

func (*phase26DMailFake) MailServerStatus(context.Context, auth.SessionUser) (types.MailServerStatus, error) {
	return types.MailServerStatus{}, nil
}

func (*phase26DMailFake) RestartMail(context.Context, auth.SessionUser) error {
	return nil
}

func (f *phase26DMailFake) SearchMailQueue(_ context.Context, _ auth.SessionUser, filter platformadmin.MailQueueFilter) (types.MailQueueQueryResult, error) {
	f.searchCalls++
	f.searchFilter = filter
	return types.MailQueueQueryResult{Messages: []types.MailQueueMessage{{ID: "42"}}, CheckedAt: time.Now()}, nil
}

func (f *phase26DMailFake) InspectQueuedMail(_ context.Context, _ auth.SessionUser, messageID string) (types.MailQueueMessage, error) {
	f.inspectID = messageID
	return types.MailQueueMessage{ID: messageID, ReturnPath: "sender@example.test"}, nil
}

func (f *phase26DMailFake) ReadMailLogs(context.Context, auth.SessionUser, time.Time, string, int) (types.ReadJournalResult, error) {
	f.logCalls++
	return types.ReadJournalResult{Entries: []types.JournalEntry{{SourceID: "mail", Message: "delivery deferred"}}}, nil
}

func TestPhase26DMailReadRoutesAreAdminOnlyAndBounded(t *testing.T) {
	mail := &phase26DMailFake{}
	handler, cookie := newPhase26DMailRouteTestHandler(t, auth.RoleAdmin, mail)

	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/mail/queue?state=deferred&sender_domain=example.test&limit=25", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"42"`) {
		t.Fatalf("queue read = %d; body=%s", rec.Code, rec.Body.String())
	}
	if mail.searchCalls != 1 || mail.searchFilter.Limit != 25 ||
		mail.searchFilter.State != platformadmin.MailQueueStateDeferred {
		t.Fatalf("queue filter = %+v, calls=%d", mail.searchFilter, mail.searchCalls)
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/mail/queue/42", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || mail.inspectID != "42" ||
		!strings.Contains(rec.Body.String(), "sender@example.test") {
		t.Fatalf("queue detail = %d; id=%q body=%s", rec.Code, mail.inspectID, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/mail/logs?since_minutes=60&limit=100", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || mail.logCalls != 1 || !strings.Contains(rec.Body.String(), `"source_id":"mail"`) {
		t.Fatalf("mail logs = %d; calls=%d body=%s", rec.Code, mail.logCalls, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/mail/queue?expression=*", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || mail.searchCalls != 1 {
		t.Fatalf("expression query = %d, calls=%d; body=%s", rec.Code, mail.searchCalls, rec.Body.String())
	}

	resellerMail := &phase26DMailFake{}
	resellerHandler, resellerCookie := newPhase26DMailRouteTestHandler(t, auth.RoleReseller, resellerMail)
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/mail/queue", nil)
	req.AddCookie(resellerCookie)
	rec = httptest.NewRecorder()
	resellerHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || resellerMail.searchCalls != 0 {
		t.Fatalf("reseller queue = %d, calls=%d", rec.Code, resellerMail.searchCalls)
	}
}

func newPhase26DMailRouteTestHandler(t *testing.T, role auth.Role, mail MailManager) (http.Handler, *http.Cookie) {
	t.Helper()
	store := &fakeSessionStore{user: auth.SessionUser{ID: 1, Email: "operator@nakpanel.test", Role: role}}
	sessions := auth.NewSessionManager(store, auth.SessionOptions{
		TTL: time.Hour, TokenBytes: 32, Now: func() time.Time {
			return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
		},
	})
	token, _, err := sessions.Create(context.Background(), 1, auth.SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(fakeUserStore{}, sessions, ServerOptions{MailManager: mail})
	mux := http.NewServeMux()
	server.registerPhase26DMailRoutes(mux)
	handler := securityHeaders(sameOriginPostGuard(limitPostBody(csrfGuard(mux), nil)))
	return handler, &http.Cookie{Name: SessionCookieName, Value: token}
}
