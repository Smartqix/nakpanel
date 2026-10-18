package panelhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlfiles "github.com/nakroteck/nakpanel/internal/control/filemanager"
	"github.com/nakroteck/nakpanel/internal/types"
)

type unreadFragmentBody struct{ reads int }

func (b *unreadFragmentBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("unauthenticated body must not be read")
}

func TestFragmentMultipartUnauthenticatedDoesNotReadBody(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{})
	for _, path := range []string{"/sites/7/mail-imports/preview", "/subscriptions/20/applications"} {
		body := &unreadFragmentBody{}
		req := httptest.NewRequest(http.MethodPost, "https://panel.test"+path, body)
		req.ContentLength = 64 << 20
		if path == "/subscriptions/20/applications" {
			req.ContentLength = -1
		}
		req.Header.Set("Content-Type", "multipart/form-data; boundary=large-upload")
		req.Header.Set("X-Nakpanel-Fragment", "main")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("X-Nakpanel-Location") != "/login" || body.reads != 0 {
			t.Errorf("%s: status=%d location=%q reads=%d", path, rec.Code, rec.Header().Get("X-Nakpanel-Location"), body.reads)
		}
	}
}

func TestFragmentMultipartNormalisationBoundaries(t *testing.T) {
	sessions := auth.NewSessionManager(&fakeSessionStore{user: auth.SessionUser{ID: 1, Role: auth.RoleAdmin}}, auth.SessionOptions{})
	token, _, err := sessions.Create(context.Background(), 1, auth.SessionMeta{})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{sessions: sessions}
	for _, tc := range []struct {
		name, path              string
		file, large, normalised bool
		status                  int
	}{
		{"small fields", "/sites", false, false, true, 204},
		{"file upload", "/sites/7/files/upload", true, false, false, 204},
		{"mail preview", "/sites/7/mail-imports/preview", true, false, false, 204},
		{"support mail preview", "/support/customers/88/sites/7/mail-imports/preview", true, false, false, 204},
		{"custom certificate", "/sites/7/certificates/custom", true, false, false, 204},
		{"oversized fields", "/database-manager/compat", false, true, true, 400},
		{"unexpected file", "/sites", true, false, true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			form := multipart.NewWriter(&body)
			value := "preserved"
			if tc.large {
				value = strings.Repeat("x", maxFormBodyBytes+1)
			}
			if err := form.WriteField("name", value); err != nil {
				t.Fatal(err)
			}
			if tc.file {
				part, err := form.CreateFormFile("upload", "example.txt")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(part, "file contents"); err != nil {
					t.Fatal(err)
				}
			}
			if err := form.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "https://panel.test"+tc.path, &body)
			req.Header.Set("Content-Type", form.FormDataContentType())
			req.Header.Set("X-Nakpanel-Fragment", "main")
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if tc.normalised {
					if err := r.ParseForm(); err != nil || r.PostForm.Get("name") != "preserved" {
						t.Errorf("normalised name length=%d: %v", len(r.PostForm.Get("name")), err)
					}
				} else {
					if r.MultipartForm != nil {
						t.Error("upload was already normalised")
					}
					if err := r.ParseMultipartForm(maxFormBodyBytes); err != nil {
						t.Fatal(err)
					}
					defer r.MultipartForm.RemoveAll()
					if len(r.MultipartForm.File["upload"]) != 1 {
						t.Error("handler lost its upload")
					}
				}
				w.WriteHeader(http.StatusNoContent)
			})
			rec := httptest.NewRecorder()
			limitPostBody(s.fragmentRequests(next), nil).ServeHTTP(rec, req)
			if rec.Code != tc.status || reached != (tc.status == 204) {
				t.Errorf("status=%d reached=%v body=%s", rec.Code, reached, rec.Body.String())
			}
		})
	}
}

func TestWorkspaceRepresentations(t *testing.T) {
	reader := &fakeDashboardReader{data: dashboard.Data{
		Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", Username: "owned", Status: "active", CustomerID: 88, SubscriptionID: 20}},
		Customers:     []types.Customer{{ID: 88, DisplayName: "Owner"}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Owned hosting", Status: "active"}},
	}}
	for _, disabled := range []bool{false, true} {
		handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DashboardReader: reader, DisableInstantNav: disabled, FileManager: &fakeFileManagerService{site: controlfiles.Site{ID: 7, Domain: "owned.test"}}})
		cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
		for _, path := range []string{"/dashboard", "/subscriptions/20", "/subscriptions/20?tab=mail", "/sites/7?tab=dns", "/support/customers/88/dashboard", "/sites/7/files", "/tools-settings/dns"} {
			for _, fragment := range []bool{false, true} {
				req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
				addAuthenticatedCookie(req, cookie)
				if fragment {
					req.Header.Set("X-Nakpanel-Fragment", "main")
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				body := rec.Body.String()
				if rec.Code != 200 {
					t.Fatalf("%s: %d %s", path, rec.Code, body)
				}
				if !strings.Contains(rec.Header().Get("Vary"), "X-Nakpanel-Fragment") {
					t.Errorf("%s missing Vary", path)
				}
				if fragment {
					for _, marker := range []string{`data-np-fragment="main"`, `data-np-shell="meta"`, `data-np-shell="sidebar"`, `data-np-shell="topbar"`, `data-np-shell="support"`} {
						if !strings.Contains(body, marker) {
							t.Errorf("%s missing %s", path, marker)
						}
					}
					for _, marker := range []string{"<html", "routed-layout", "<script"} {
						if strings.Contains(body, marker) {
							t.Errorf("%s fragment contains %s", path, marker)
						}
					}
					if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
						t.Errorf("fragment headers: %v", rec.Header())
					}
				} else if !strings.Contains(body, "<html") || strings.Contains(body, `data-np-nav="on"`) == disabled {
					t.Errorf("%s full-page nav flag (disabled=%v)", path, disabled)
				}
				if path == "/dashboard" && !strings.Contains(rec.Header().Get("Server-Timing"), "render;dur=") {
					t.Errorf("missing timing: %v", rec.Header())
				}
			}
		}
		req := httptest.NewRequest(http.MethodGet, "https://panel.test/sites/7/files/edit?path=index.php", nil)
		addAuthenticatedCookie(req, cookie)
		req.Header.Set("X-Nakpanel-Fragment", "main")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `data-full-document="true"`) || strings.Contains(rec.Body.String(), `data-np-fragment`) {
			t.Fatalf("editor fragment: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestFragmentAuthenticationAndAssets(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{})
	for _, path := range []string{"/dashboard", "/support/customers/88/dashboard", "/sites/7/files"} {
		req := httptest.NewRequest(http.MethodGet, "https://panel.test"+path, nil)
		req.Header.Set("X-Nakpanel-Fragment", "main")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 401 || rec.Header().Get("X-Nakpanel-Location") != "/login" {
			t.Errorf("%s auth: %d %v", path, rec.Code, rec.Header())
		}
	}
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/customers", nil)
	addAuthenticatedCookie(req, cookie)
	req.Header.Set("X-Nakpanel-Fragment", "main")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 403 || strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("forbidden: %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "https://panel.test/assets/navigation.js", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Errorf("asset: %d %v", rec.Code, rec.Header())
	}
}

func TestPrefetchPreservesOneShotFormError(t *testing.T) {
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{})
	session := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	for _, header := range []string{"Sec-Purpose", "Purpose"} {
		request := func(prefetch bool) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
			addAuthenticatedCookie(req, session)
			req.AddCookie(&http.Cookie{Name: FormErrorCookieName, Value: "Keep+this+form+error"})
			req.Header.Set("X-Nakpanel-Fragment", "main")
			if prefetch {
				req.Header.Set(header, "prefetch")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			return rec
		}
		prefetched := request(true)
		if prefetched.Code != 200 || strings.Contains(prefetched.Body.String(), "Keep this form error") {
			t.Fatalf("prefetch consumed error: %d %s", prefetched.Code, prefetched.Body.String())
		}
		for _, cookie := range prefetched.Result().Cookies() {
			if cookie.Name == FormErrorCookieName {
				t.Fatal("prefetch wrote the one-shot cookie")
			}
		}
		real := request(false)
		if !strings.Contains(real.Body.String(), "Keep this form error") {
			t.Fatal("following real navigation lost its error")
		}
		expired := false
		for _, cookie := range real.Result().Cookies() {
			if cookie.Name == FormErrorCookieName && cookie.MaxAge < 0 {
				expired = true
			}
		}
		if !expired {
			t.Fatal("real navigation did not expire the cookie")
		}
	}
}

func TestFragmentPOSTRedirectDestination(t *testing.T) {
	service := &fakeMailDomainServices{}
	data := dashboard.Data{Subscriptions: []types.SubscriptionSummary{{ID: 20, SubscriptionName: "Hosting"}}}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: service, DashboardReader: &fakeDashboardReader{data: data}})
	session := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/20/scheduled-tasks/5/run", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Nakpanel-Fragment", "main")
	addAuthenticatedCookie(req, session)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	// Fetch follows 303 with GET, retaining custom headers on same-origin redirects.
	redirected := httptest.NewRequest(http.MethodGet, "https://panel.test"+rec.Header().Get("Location"), nil)
	redirected.Header.Set("Accept", "text/html")
	redirected.Header.Set("X-Nakpanel-Fragment", "main")
	addAuthenticatedCookie(redirected, session)
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, redirected)
	if result.Code != 200 || !strings.Contains(result.Body.String(), `data-np-fragment="main"`) || strings.Contains(result.Body.String(), "<!doctype") {
		t.Fatalf("redirect GET: %d %s", result.Code, result.Body.String())
	}
}

func TestFragmentMultipartPOSTPreservesFields(t *testing.T) {
	service := &fakeMailDomainServices{}
	handler, _ := newTestHandlerWithOptions(t, auth.RoleAdmin, ServerOptions{DomainManager: service})
	cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for name, value := range map[string]string{"site_id": "7", "name": "submitted-name", "runtime": "container", "return_to": "site-applications"} {
		if err := form.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/subscriptions/20/applications", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Nakpanel-Fragment", "main")
	addAuthenticatedCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 303 || !service.appCalled || service.application.Name != "submitted-name" || service.application.SiteID != 7 || rec.Header().Get("Location") != "/sites/7/containers?notice=service-saved" {
		t.Fatalf("multipart fields lost: status=%d input=%+v location=%s body=%s", rec.Code, service.application, rec.Header().Get("Location"), rec.Body.String())
	}
}
