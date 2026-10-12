package panelhttp

import (
	"bytes"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSiteFormTransport(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		multipart, file, oversized, missing, badCSRF bool
		want                                         int
	}{
		{name: "urlencoded", want: 202}, {name: "multipart", multipart: true, want: 202},
		{name: "file", multipart: true, file: true, want: 400}, {name: "oversized", multipart: true, oversized: true, want: 413},
		{name: "missing selection", missing: true, want: 400}, {name: "csrf", multipart: true, badCSRF: true, want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creator := &fakeSiteCreator{}
			handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleAdmin, creator)
			cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
			var body bytes.Buffer
			contentType := "application/x-www-form-urlencoded"
			if tc.multipart {
				w := multipart.NewWriter(&body)
				_ = w.WriteField("subscription_id", "39")
				_ = w.WriteField("domain", "example.test")
				_ = w.WriteField("php_version", "8.5")
				if tc.file {
					f, _ := w.CreateFormFile("file", "test.txt")
					_, _ = f.Write([]byte("test"))
				}
				if tc.oversized {
					_ = w.WriteField("extra", strings.Repeat("x", 65536))
				}
				_ = w.Close()
				contentType = w.FormDataContentType()
			} else {
				body.WriteString("domain=example.test&php_version=8.5")
				if !tc.missing {
					body.WriteString("&subscription_id=39")
				}
			}
			req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", &body)
			req.Header.Set("Content-Type", contentType)
			req.Header.Set("X-Nakpanel-SPA", "true")
			addAuthenticatedCookie(req, cookie)
			if tc.badCSRF {
				req.Header.Set("X-Nakpanel-CSRF", "invalid")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == 202 {
				if len(creator.requests) != 1 || creator.requests[0].SubscriptionID != 39 || creator.requests[0].PHPVersion != "8.5" {
					t.Fatalf("wrong provisioning input: %+v", creator.requests)
				}
			} else if len(creator.requests) != 0 {
				t.Fatal("invalid form reached provisioning")
			}
		})
	}
}

func TestSiteFormMalformedAndStreamingLimit(t *testing.T) {
	for _, tc := range []struct {
		contentType, body string
		want              int
	}{
		{"multipart/form-data; boundary=absent", "broken", 400},
		{"application/x-www-form-urlencoded", "subscription_id=%xx", 400},
		{"application/x-www-form-urlencoded", "subscription_id=39&extra=" + strings.Repeat("x", 65536), 413},
	} {
		creator := &fakeSiteCreator{}
		handler, _ := newTestHandlerWithSiteCreator(t, auth.RoleAdmin, creator)
		cookie := login(t, handler, "admin@nakpanel.test", "NakpanelAdmin!2026")
		req := httptest.NewRequest("POST", "https://panel.test/sites", strings.NewReader(tc.body))
		req.ContentLength = -1
		req.Header.Set("Content-Type", tc.contentType)
		req.Header.Set("X-Nakpanel-SPA", "true")
		addAuthenticatedCookie(req, cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want || len(creator.requests) != 0 {
			t.Fatalf("status %d requests %d: %s", rec.Code, len(creator.requests), rec.Body.String())
		}
	}
}
