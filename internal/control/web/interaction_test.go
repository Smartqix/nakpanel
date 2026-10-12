package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSharedInteractionAsset(t *testing.T) {
	w := httptest.NewRecorder()
	StaticHandler().ServeHTTP(w, httptest.NewRequest("GET", "/interaction.js", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") || !strings.Contains(w.Body.String(), "X-Nakpanel-SPA") {
		t.Fatalf("shared transport unavailable: %d", w.Code)
	}
}
