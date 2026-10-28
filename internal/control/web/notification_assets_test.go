package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotificationsAssetEmbedded(t *testing.T) {
	w:=httptest.NewRecorder()
	StaticHandler().ServeHTTP(w,httptest.NewRequest("GET","/notifications.js",nil))
	if w.Code!=200||!strings.Contains(w.Header().Get("Content-Type"),"javascript")||!strings.Contains(w.Body.String(),"createNotificationView") {t.Fatal("missing embedded notification module",w.Code)}
}
