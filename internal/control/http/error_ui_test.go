package panelhttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerRendersBrandedHTMLForPlainHTTPError(t *testing.T) {
	handler := NewServer(nil, nil).Handler()
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", nil)
	req.Header.Set("Origin", "https://attacker.test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want HTML", contentType)
	}
	body := rec.Body.String()
	for _, marker := range []string{
		`data-np-error-page`,
		`<title>Action not allowed · nakpanel</title>`,
		`You do not have permission to perform this action.`,
		`href="/dashboard"`,
		`data-np-error-back`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("branded error page missing %q:\n%s", marker, body)
		}
	}
	if strings.TrimSpace(body) == "Forbidden" {
		t.Fatal("server returned the raw net/http error body")
	}
}

func TestServerReturnsStructuredJSONForEnhancedError(t *testing.T) {
	handler := NewServer(nil, nil).Handler()
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites", nil)
	req.Header.Set("Origin", "https://attacker.test")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Nakpanel-SPA", "true")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("Content-Type = %q, want JSON", contentType)
	}
	var payload struct {
		OK     bool   `json:"ok"`
		Status int    `json:"status"`
		Title  string `json:"title"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode JSON error: %v\n%s", err, rec.Body.String())
	}
	if payload.OK || payload.Status != http.StatusForbidden || payload.Title != "Action not allowed" || payload.Error != "You do not have permission to perform this action." {
		t.Fatalf("error payload = %#v", payload)
	}
}

func TestUserFacingErrorsRedactsJSONServerErrors(t *testing.T) {
	handler := userFacingErrors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ok":false,"error":"database password=should-never-render"}`))
	}))
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/tools-settings/status", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("Content-Type = %q, want JSON", contentType)
	}
	if strings.Contains(rec.Body.String(), "should-never-render") || !strings.Contains(rec.Body.String(), "Nakpanel could not complete this request") {
		t.Fatalf("JSON server error was not redacted:\n%s", rec.Body.String())
	}
}

func TestUserFacingErrorsStreamsLargeJSONClientErrorsUnchanged(t *testing.T) {
	payload := `{"ok":false,"error":"` + strings.Repeat("x", maxUserFacingErrorBytes*2) + `"}`
	handler := userFacingErrors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(payload))
	}))
	req := httptest.NewRequest(http.MethodPost, "https://panel.test/sites/1/php-settings", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if got := rec.Body.String(); got != payload {
		t.Fatalf("large JSON client error was changed: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestServerRendersGenericNotFoundWithoutObjectDisclosure(t *testing.T) {
	handler := NewServer(nil, nil).Handler()
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/assets/not-a-real-file.css", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Page not found") || strings.Contains(body, "not-a-real-file.css") {
		t.Fatalf("404 page is missing generic copy or discloses the requested object:\n%s", body)
	}
}

func TestServerPreservesSuccessfulPlainTextResponses(t *testing.T) {
	handler := NewServer(nil, nil).Handler()
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "ok\nversion=") {
		t.Fatalf("health response = %d %q", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("health Content-Type = %q, want text/plain", contentType)
	}
}

func TestUserFacingErrorsRecoversPanicWithoutLeakingDetails(t *testing.T) {
	handler := userFacingErrors(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("database password=should-never-render")
	}))
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Something went wrong") || strings.Contains(body, "should-never-render") {
		t.Fatalf("panic response missing safe copy or leaked details:\n%s", body)
	}
}

func TestUserFacingErrorsRecoversPanicAfterJSONHeader(t *testing.T) {
	handler := userFacingErrors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="error.json"`)
		panic("database password=should-never-render")
	}))
	req := httptest.NewRequest(http.MethodGet, "https://panel.test/dashboard", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("panic Content-Type = %q, want HTML", contentType)
	}
	if disposition := rec.Header().Get("Content-Disposition"); disposition != "" {
		t.Fatalf("panic retained download disposition %q", disposition)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Something went wrong") || strings.Contains(body, "should-never-render") {
		t.Fatalf("panic response missing safe copy or leaked details:\n%s", body)
	}
}

func TestCapturedErrorWriterBoundsBufferedErrorBody(t *testing.T) {
	writer := &capturedErrorWriter{target: httptest.NewRecorder()}
	writer.WriteHeader(http.StatusBadRequest)
	chunk := bytes.Repeat([]byte("x"), maxUserFacingErrorBytes)
	for range 3 {
		n, err := writer.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("captured write = (%d, %v), want (%d, nil)", n, err, len(chunk))
		}
	}
	if got, max := writer.body.Len(), maxUserFacingErrorBytes+1; got > max {
		t.Fatalf("captured body length = %d, want at most %d", got, max)
	}

	writer = &capturedErrorWriter{target: httptest.NewRecorder()}
	writer.WriteHeader(http.StatusBadRequest)
	large := bytes.Repeat([]byte("y"), maxUserFacingErrorBytes*3)
	copied, err := writer.ReadFrom(bytes.NewReader(large))
	if err != nil || copied != int64(len(large)) {
		t.Fatalf("captured ReadFrom = (%d, %v), want (%d, nil)", copied, err, len(large))
	}
	if got, max := writer.body.Len(), maxUserFacingErrorBytes+1; got > max {
		t.Fatalf("ReadFrom captured body length = %d, want at most %d", got, max)
	}
}

func TestUserFacingErrorFieldMapsPHPPermissionFailures(t *testing.T) {
	tests := []struct {
		message string
		field   string
	}{
		{"site policy exceeds subscription: PHP URL fopen is not delegated by the subscription", "site_php_url_fopen"},
		{"site policy exceeds subscription: PHP error display is not delegated by the subscription", "site_php_display_errors"},
		{"site policy exceeds subscription: PHP process execution is not delegated by the subscription", "site_php_exec"},
		{"site policy exceeds subscription: OPcache is not delegated by the subscription", "site_php_opcache"},
		{"Could not update PHP settings: PHP 8.5 is not installed on the server", "desired_php_version"},
	}
	for _, test := range tests {
		if got := userFacingErrorField(test.message); got != test.field {
			t.Errorf("userFacingErrorField(%q) = %q, want %q", test.message, got, test.field)
		}
	}
}

func TestUserFacingErrorCopyExplainsUnavailablePHPRuntime(t *testing.T) {
	title, message := userFacingErrorCopy(http.StatusBadRequest, "Could not update PHP settings: PHP 8.5 is not installed on the server")
	if title != "PHP runtime unavailable" || message != "The selected PHP version is not available on this server. Choose one of the listed versions." {
		t.Fatalf("runtime error copy = (%q, %q)", title, message)
	}
}
