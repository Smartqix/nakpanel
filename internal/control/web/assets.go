package web

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed static/app.css static/app.js
var staticFiles embed.FS

var appCSS = mustReadStatic("static/app.css")
var appJS = mustReadStatic("static/app.js")

func StaticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "app.css", "/app.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			http.ServeContent(w, r, "app.css", time.Time{}, bytes.NewReader(appCSS))
		case "app.js", "/app.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "app.js", time.Time{}, bytes.NewReader(appJS))
		default:
			http.NotFound(w, r)
		}
	})
}

func mustReadStatic(name string) []byte {
	data, err := staticFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return data
}
