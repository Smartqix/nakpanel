package web

import (
	"bytes"
	"embed"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed static/app.css static/app.js static/icons.svg static/ace/*
var staticFiles embed.FS

var appCSS = mustReadStatic("static/app.css")
var appJS = mustReadStatic("static/app.js")
var iconsSVG = mustReadStatic("static/icons.svg")

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
		case "icons.svg", "/icons.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			http.ServeContent(w, r, "icons.svg", time.Time{}, bytes.NewReader(iconsSVG))
		default:
			asset := strings.TrimPrefix(r.URL.Path, "/")
			if strings.HasPrefix(asset, "ace/") && path.Clean(asset) == asset {
				data, err := staticFiles.ReadFile("static/" + asset)
				if err == nil {
					w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
					if path.Base(asset) == "LICENSE" {
						w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					}
					http.ServeContent(w, r, path.Base(asset), time.Time{}, bytes.NewReader(data))
					return
				}
			}
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
