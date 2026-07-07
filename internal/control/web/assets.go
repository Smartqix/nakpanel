package web

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed static/app.css
var staticFiles embed.FS

var appCSS = mustReadStatic("static/app.css")

func StaticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "app.css" && r.URL.Path != "/app.css" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		http.ServeContent(w, r, "app.css", time.Time{}, bytes.NewReader(appCSS))
	})
}

func mustReadStatic(name string) []byte {
	data, err := staticFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return data
}
