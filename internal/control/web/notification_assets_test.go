package web

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNotificationsAssetEmbedded(t *testing.T) {
	w := httptest.NewRecorder()
	StaticHandler().ServeHTTP(w, httptest.NewRequest("GET", "/notifications.js", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") || !strings.Contains(w.Body.String(), "createNotificationView") {
		t.Fatal("missing embedded notification module", w.Code)
	}
}

func TestNotificationMobileToolbarAndTouchTargets(t *testing.T) {
	css, err := os.ReadFile("static/operations.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		".nakpanel-js .np-notification-meta>span:first-child{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
		".np-notification-detail-footer{position:sticky;bottom:0;",
		".np-routed .np-notification-detail-footer button{width:auto;flex:0 0 auto;min-height:44px}",
		".np-routed .np-notification-error button{width:auto;flex:0 0 auto}",
		".np-domains .np-routed-top:has([data-np-operations-shell]){display:grid;grid-template-columns:44px minmax(0,1fr);gap:10px}",
		".np-domains .np-routed-top:has([data-np-operations-shell]) .np-global-search{grid-column:1/-1;grid-row:2;width:100%;max-width:none}",
		".np-domains .np-top-secondary:has([data-np-operations-shell]){display:flex;grid-column:2;grid-row:1;justify-self:end}",
		".np-routed .np-notification-preview button,.np-routed .np-notification-inbox button{min-height:44px}",
		".np-notification-toolbar>[data-np-notification-search-submit]{grid-column:2;grid-row:2;min-height:44px}",
		".np-notification-search{grid-column:1;grid-row:2;min-width:0;min-height:44px}",
	} {
		if !strings.Contains(string(css), rule) {
			t.Errorf("missing mobile layout rule %s", rule)
		}
	}
}
