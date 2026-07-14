package provisioningapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCookieOnlyAPIRequestIsUnauthorizedWithoutSessionCookie(t *testing.T) {
	handler := NewHandler(HandlerOptions{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	req.AddCookie(&http.Cookie{Name: "nakpanel_session", Value: "valid-looking-cookie"})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body=%s", res.Code, res.Body.String())
	}
	if got := res.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("API emitted a session cookie: %v", got)
	}
	if !strings.Contains(res.Body.String(), `"code":"unauthorized"`) {
		t.Fatalf("unexpected error envelope: %s", res.Body.String())
	}
	if res.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing request ID")
	}
}

func TestStrictJSONRejectsTrailingAndUnknownFields(t *testing.T) {
	for _, body := range []string{`{"external_ref":"x","unknown":true}`, `{"external_ref":"x"}{}`} {
		var value struct {
			ExternalRef string `json:"external_ref"`
		}
		if err := decodeStrictJSON(strings.NewReader(body), &value); err == nil {
			t.Fatalf("expected strict decoder to reject %s", body)
		}
	}
}
