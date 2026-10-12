package panelhttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
)

type DatabaseManagerService interface {
	Launch(context.Context, auth.SessionUser, string, int64) (string, error)
	Access(context.Context, auth.SessionUser, string, string) (provision.DatabaseManagerAccess, error)
	Logout(context.Context, auth.SessionUser, string, string) error
}
type managerCapability struct {
	access         provision.DatabaseManagerAccess
	actor          auth.SessionUser
	session, token string
	expires        time.Time
}
type DatabaseManagerProxy struct {
	service      DatabaseManagerService
	key          string
	mu           sync.Mutex
	capabilities map[string]managerCapability
	slots        chan struct{}
	transport    http.RoundTripper
}

func NewDatabaseManagerProxy(service DatabaseManagerService, key string) *DatabaseManagerProxy {
	return &DatabaseManagerProxy{service: service, key: strings.TrimSpace(key), capabilities: make(map[string]managerCapability), slots: make(chan struct{}, 8), transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 8}}
}

func RegisterDatabaseManagerRoutes(mux *http.ServeMux, s *Server, p *DatabaseManagerProxy) {
	mux.HandleFunc("POST /databases/{id}/manager", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.currentUser(w, r)
		if !ok {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		if p == nil || p.service == nil || len(p.key) < 32 {
			managerUnavailable(w, r, actor.Role, http.StatusServiceUnavailable)
			return
		}
		if !p.ready(r.Context()) {
			managerUnavailable(w, r, actor.Role, http.StatusServiceUnavailable)
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			http.NotFound(w, r)
			return
		}
		_, target, allowed := s.databaseWorkspaceTarget(w, r)
		if !allowed {
			return
		}
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		token, err := p.service.Launch(r.Context(), actor, cookie.Value, id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		s.recordAudit(r.Context(), actor, target.CustomerID, target.SubscriptionID, "database.manager_launched", "database", id, nil)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, "/database-manager/"+token+"/", http.StatusSeeOther)
	})
	for _, method := range []string{"GET", "POST"} {
		mux.HandleFunc(method+" /database-manager/{grantID}/{path...}", func(w http.ResponseWriter, r *http.Request) { s.serveDatabaseManager(p, w, r) })
	}
}

var managerTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func validManagerPath(value string) bool {
	if strings.ContainsAny(value, "\\\x00\r\n") || strings.Contains(value, "%") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	lower := strings.ToLower(value)
	return !strings.HasPrefix(lower, "setup") && !strings.Contains(lower, "signon") && !strings.HasPrefix(lower, "__")
}
func managerCookieAllowed(name string) bool {
	name = strings.TrimPrefix(name, "__Secure-")
	return strings.HasPrefix(name, "pma_") || strings.HasPrefix(name, "phpMyAdmin")
}

func (s *Server) serveDatabaseManager(p *DatabaseManagerProxy, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	actor, ok := s.currentUser(w, r)
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	if p == nil || p.service == nil || len(p.key) < 32 {
		managerUnavailable(w, r, actor.Role, http.StatusServiceUnavailable)
		return
	}
	token := r.PathValue("grantID")
	relative := r.PathValue("path")
	if !managerTokenPattern.MatchString(token) || !validManagerPath(relative) || strings.Contains(r.URL.EscapedPath(), "%") {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost && ((r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "") || !isSameOriginPost(r)) {
		http.Error(w, "Forbidden", 403)
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	access, err := p.service.Access(r.Context(), actor, cookie.Value, token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if relative == "logout" || r.URL.Query().Get("route") == "/logout" {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>End database session</title><link rel="stylesheet" href="/assets/app.css"></head><body class="np-app"><main class="np-shell"><h1>End database session?</h1><p>Your Nakpanel session will remain signed in.</p><form method="post"><button type="submit">End database session</button></form><p><a href="/databases">Back to databases</a></p></main></body></html>`)
			return
		}
		if err := p.service.Logout(r.Context(), actor, cookie.Value, token); err != nil {
			http.Error(w, "Database manager is unavailable", 503)
			return
		}
		s.recordAudit(r.Context(), actor, 0, 0, "database.manager_logged_out", "database", access.DatabaseID, nil)
		http.Redirect(w, r, "/databases", 303)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "Database manager is busy", 503)
		return
	}
	capability := ""
	if access.Bootstrap {
		capability, err = p.issueCapability(managerCapability{access: access, actor: actor, session: cookie.Value, token: token, expires: time.Now().Add(10 * time.Second)})
		if err != nil {
			http.Error(w, "Database manager is unavailable", 503)
			return
		}
	}
	prefix := "/database-manager/" + token + "/"
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	r = r.WithContext(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, 17<<20)
	proxy := &httputil.ReverseProxy{Transport: p.transport, Rewrite: func(pr *httputil.ProxyRequest) {
		pr.Out.URL = &url.URL{Scheme: "http", Host: "127.0.0.1:9082", Path: "/" + relative, RawQuery: pr.In.URL.RawQuery}
		if relative == "" && pr.Out.URL.RawQuery == "" {
			pr.Out.URL.Path = "/index.php"
			pr.Out.URL.RawQuery = url.Values{"route": {"/database/structure"}, "db": {access.Database}}.Encode()
		}
		pr.Out.Host = pr.In.Host
		for name := range pr.Out.Header {
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "x-nakpanel-") || strings.HasPrefix(lower, "x-forwarded-") || lower == "forwarded" {
				pr.Out.Header.Del(name)
			}
		}
		pr.Out.Header.Del("Authorization")
		pr.Out.Header.Del("Cookie")
		pr.Out.Header.Del("Referer")
		for _, c := range pr.In.Cookies() {
			if managerCookieAllowed(c.Name) {
				pr.Out.AddCookie(c)
			}
		}
		pr.Out.Header.Set("X-Nakpanel-Manager-Key", p.key)
		pr.Out.Header.Set("X-Nakpanel-Manager-Grant", access.Grant)
		pr.Out.Header.Set("X-Nakpanel-Manager-Path", prefix)
		if capability != "" {
			pr.Out.Header.Set("X-Nakpanel-Manager-Capability", capability)
		}
	}, ModifyResponse: func(resp *http.Response) error {
		for name := range resp.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-nakpanel-") {
				resp.Header.Del(name)
			}
		}
		cookies := resp.Cookies()
		resp.Header.Del("Set-Cookie")
		for _, c := range cookies {
			if managerCookieAllowed(c.Name) {
				c.Path = prefix
				c.Domain = ""
				c.Secure = true
				c.HttpOnly = true
				c.SameSite = http.SameSiteStrictMode
				resp.Header.Add("Set-Cookie", c.String())
			}
		}
		if location := resp.Header.Get("Location"); location != "" {
			u, err := url.Parse(location)
			if err != nil || strings.HasPrefix(location, "//") || (u.Host != "" && (u.Host != r.Host || u.Scheme != "https" || !strings.HasPrefix(u.Path, prefix))) || (u.Host == "" && u.Scheme != "") {
				return errors.New("invalid manager redirect")
			}
			u.Host = ""
			u.Scheme = ""
			if strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, prefix) {
				u.Path = prefix + strings.TrimPrefix(u.Path, "/")
			}
			resp.Header.Set("Location", u.String())
		}
		resp.Header.Set("Cache-Control", "no-store")
		resp.Header.Set("Referrer-Policy", "same-origin")
		return nil
	}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		managerUnavailable(w, r, actor.Role, http.StatusBadGateway)
	}}
	// phpMyAdmin supplies its own policy for its bundled inline initialization.
	// Combining it with the panel's script-src policy disables its CSRF-aware UI.
	w.Header().Del("Content-Security-Policy")
	proxy.ServeHTTP(w, r)
}

func (p *DatabaseManagerProxy) ready(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9082/__nakpanel_health", nil)
	if err != nil {
		return false
	}
	r.Header.Set("X-Nakpanel-Manager-Key", p.key)
	response, err := p.transport.RoundTrip(r)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusNoContent
}

func managerUnavailable(w http.ResponseWriter, r *http.Request, role auth.Role, status int) {
	message := "phpMyAdmin is temporarily unavailable. Please contact your hosting provider."
	if role == auth.RoleAdmin {
		message = "phpMyAdmin is temporarily unavailable. Check the isolated database manager service and bridge socket in Tools & Settings."
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if wantsSPAJSON(r) {
		writeSPAError(w, status, message)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Nakpanel-Complete-Error-Page", "1")
	w.WriteHeader(status)
	_ = userFacingErrorTemplate.Execute(w, map[string]any{
		"Status": status, "Title": "Database manager unavailable", "Message": message,
		"ReturnPath": "/databases", "ReturnLabel": "Back to databases",
	})
}

func (p *DatabaseManagerProxy) issueCapability(c managerCapability) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, value := range p.capabilities {
		if time.Now().After(value.expires) {
			delete(p.capabilities, key)
		}
	}
	p.capabilities[auth.TokenHash(token)] = c
	hash := auth.TokenHash(token)
	time.AfterFunc(time.Until(c.expires), func() { p.mu.Lock(); delete(p.capabilities, hash); p.mu.Unlock() })
	return token, nil
}

// BridgeHandler must only be served on the private runtime-group Unix socket.
func (p *DatabaseManagerProxy) BridgeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" || r.URL.Path != "/redeem" {
			http.NotFound(w, r)
			return
		}
		var input struct {
			Capability string `json:"capability"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !managerTokenPattern.MatchString(input.Capability) {
			http.NotFound(w, r)
			return
		}
		p.mu.Lock()
		c, ok := p.capabilities[auth.TokenHash(input.Capability)]
		delete(p.capabilities, auth.TokenHash(input.Capability))
		p.mu.Unlock()
		if !ok || time.Now().After(c.expires) {
			http.NotFound(w, r)
			return
		}
		if _, err := p.service.Access(r.Context(), c.actor, c.session, c.token); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.access)
	})
}
