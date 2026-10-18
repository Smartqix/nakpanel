package panelhttp

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/web"
)

func wantsWorkspaceFragment(r *http.Request) bool {
	return r.Method == http.MethodGet && r.Header.Get("X-Nakpanel-Fragment") == "main"
}

func isPrefetchRequest(r *http.Request) bool {
	for _, header := range []string{"Sec-Purpose", "Purpose"} {
		for _, value := range r.Header.Values(header) {
			for _, purpose := range strings.FieldsFunc(strings.ToLower(value), func(c rune) bool { return c == ',' || c == ';' || c == ' ' }) {
				if purpose == "prefetch" {
					return true
				}
			}
		}
	}
	return false
}

// Prefetch responses cannot change browser cookies, including cookies written
// by handlers outside the workspace authentication flow.
func prefetchRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPrefetchRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		defer w.Header().Del("Set-Cookie")
		next.ServeHTTP(prefetchResponseWriter{ResponseWriter: w}, r)
	})
}

type prefetchResponseWriter struct{ http.ResponseWriter }

func (w prefetchResponseWriter) WriteHeader(status int) {
	w.Header().Del("Set-Cookie")
	w.ResponseWriter.WriteHeader(status)
}

func (w prefetchResponseWriter) Write(body []byte) (int, error) {
	w.Header().Del("Set-Cookie")
	return w.ResponseWriter.Write(body)
}

func (w prefetchResponseWriter) Flush() {
	w.Header().Del("Set-Cookie")
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w prefetchResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Apply the same fragment authentication contract to specialized workspace handlers
// (files, setup, removal) as to the central workspace handler.
func (s *Server) fragmentRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fragment := r.Header.Get("X-Nakpanel-Fragment") == "main"
		if fragment {
			w.Header().Add("Vary", "X-Nakpanel-Fragment")
			w.Header().Set("Cache-Control", "no-store")
			if _, ok := s.currentUser(w, r); !ok {
				return
			}
		}
		// The client sends urlencoded bodies like a native submission; only forms
		// declared multipart arrive here as multipart. Parse those once so
		// ParseForm-based handlers still see their fields, within the smaller of
		// the ordinary form limit and the route's limitPostBody reader. Upload
		// handlers authenticate and parse their own multipart bodies.
		if fragment && r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") && !strings.HasSuffix(r.URL.Path, "/files/upload") && !isMailImportMultipartPreview(r) && !strings.HasSuffix(r.URL.Path, "/certificates/custom") {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
			err := r.ParseMultipartForm(maxFormBodyBytes)
			if r.MultipartForm != nil {
				defer r.MultipartForm.RemoveAll()
			}
			if err != nil || r.MultipartForm == nil || len(r.MultipartForm.File) != 0 {
				http.Error(w, "Invalid navigation form; upload files using the normal form", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) renderRoutedPage(w http.ResponseWriter, r *http.Request, title string, user auth.SessionUser, data dashboard.Data, actions web.DashboardActions, view web.WorkspaceView) {
	view.InstantNavDisabled = s.disableInstantNav
	if wantsWorkspaceFragment(r) {
		w.Header().Set("Cache-Control", "no-store")
		renderPage(w, r, web.RoutedFragment(title, user, data, actions, view))
		return
	}
	w.Header().Add("Vary", "X-Nakpanel-Fragment")
	renderPage(w, r, web.RoutedDashboardPage(title, user, data, actions, view))
}

// The shared shell's attention and badge helpers read sites, jobs and alerts,
// never SubscriptionServices. Detail/tool bodies use only their subscription.
func workspaceServiceContext(ctx context.Context, route, rawID string) context.Context {
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		return ctx
	}
	switch route {
	case "subscription-detail":
		return dashboard.WithServiceScope(ctx, id, 0)
	case "site-detail", "site-files", "site-file-edit", "site-setup":
		return dashboard.WithServiceScope(ctx, 0, id)
	default:
		return ctx
	}
}
