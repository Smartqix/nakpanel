package web

import (
	"bytes"
	"embed"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed static/app.css static/app.js static/service-controls.js static/interaction.js static/navigation.js static/notifications.js static/operations.js static/operations.css static/git.js static/git.css static/domains.css static/domains.js static/mail.css static/mail.js static/fonts/* static/domain-icons/* static/site-removal.js static/plan-sync.js static/mail-import.js static/dns-template.js static/icons.svg static/ace/* static/backups.css static/backups.js
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
		case "service-controls.js", "/service-controls.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w,r,"service-controls.js",time.Time{},bytes.NewReader(mustReadStatic("static/service-controls.js")))
		case "backups.css", "/backups.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			http.ServeContent(w, r, "backups.css", time.Time{}, bytes.NewReader(mustReadStatic("static/backups.css")))
		case "backups.js", "/backups.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "backups.js", time.Time{}, bytes.NewReader(mustReadStatic("static/backups.js")))
		case "mail.css", "/mail.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			http.ServeContent(w, r, "mail.css", time.Time{}, bytes.NewReader(mustReadStatic("static/mail.css")))
		case "mail.js", "/mail.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "mail.js", time.Time{}, bytes.NewReader(mustReadStatic("static/mail.js")))
		case "domain-icons/mail-help.svg", "/domain-icons/mail-help.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			http.ServeContent(w, r, "mail-help.svg", time.Time{}, bytes.NewReader(mustReadStatic("static/domain-icons/mail-help.svg")))
		case "domain-icons/server.svg", "/domain-icons/server.svg", "domain-icons/terminal.svg", "/domain-icons/terminal.svg", "domain-icons/chart.svg", "/domain-icons/chart.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(mustReadStatic("static/"+strings.TrimPrefix(r.URL.Path, "/"))))
		case "domains.css", "/domains.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			http.ServeContent(w, r, "domains.css", time.Time{}, bytes.NewReader(mustReadStatic("static/domains.css")))
		case "domains.js", "/domains.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "domains.js", time.Time{}, bytes.NewReader(mustReadStatic("static/domains.js")))
		case "fonts/inter-variable.woff2", "/fonts/inter-variable.woff2":
			w.Header().Set("Content-Type", "font/woff2")
			http.ServeContent(w, r, "inter-variable.woff2", time.Time{}, bytes.NewReader(mustReadStatic("static/fonts/inter-variable.woff2")))
		case "dns-template.js", "/dns-template.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "dns-template.js", time.Time{}, bytes.NewReader(mustReadStatic("static/dns-template.js")))
		case "mail-import.js", "/mail-import.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "mail-import.js", time.Time{}, bytes.NewReader(mustReadStatic("static/mail-import.js")))
		case "plan-sync.js", "/plan-sync.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "plan-sync.js", time.Time{}, bytes.NewReader(mustReadStatic("static/plan-sync.js")))
		case "site-removal.js", "/site-removal.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "site-removal.js", time.Time{}, bytes.NewReader(mustReadStatic("static/site-removal.js")))
		case "operations.css", "/operations.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			http.ServeContent(w, r, "operations.css", time.Time{}, bytes.NewReader(mustReadStatic("static/operations.css")))
		case "operations.js", "/operations.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "operations.js", time.Time{}, bytes.NewReader(mustReadStatic("static/operations.js")))
		case "notifications.js", "/notifications.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "notifications.js", time.Time{}, bytes.NewReader(mustReadStatic("static/notifications.js")))
		case "navigation.js", "/navigation.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "navigation.js", time.Time{}, bytes.NewReader(mustReadStatic("static/navigation.js")))
		case "interaction.js", "/interaction.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "interaction.js", time.Time{}, bytes.NewReader(mustReadStatic("static/interaction.js")))
		case "git.js", "/git.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			http.ServeContent(w, r, "git.js", time.Time{}, bytes.NewReader(mustReadStatic("static/git.js")))
		case "git.css", "/git.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			http.ServeContent(w, r, "git.css", time.Time{}, bytes.NewReader(mustReadStatic("static/git.css")))
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
