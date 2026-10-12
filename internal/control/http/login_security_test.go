package panelhttp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
)

// The handler fixtures represent an available security store with no enrolled
// authenticator. Individual login tests can inject failed or malformed state.
type loginSecurityConnector struct {
	totpError error
	envelope  []byte
}

func (c loginSecurityConnector) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c loginSecurityConnector) Driver() driver.Driver                        { return c }
func (c loginSecurityConnector) Open(string) (driver.Conn, error)             { return c, nil }
func (c loginSecurityConnector) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unsupported test statement")
}
func (c loginSecurityConnector) Close() error { return nil }
func (c loginSecurityConnector) Begin() (driver.Tx, error) {
	return nil, errors.New("unsupported test transaction")
}
func (c loginSecurityConnector) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (c loginSecurityConnector) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "SELECT secret_envelope") {
		if c.totpError != nil {
			return nil, c.totpError
		}
		rows := &loginSecurityRows{columns: []string{"secret_envelope", "confirmed_at", "last_used_step"}}
		if c.envelope != nil {
			rows.values = []driver.Value{c.envelope, time.Now(), int64(-1)}
		}
		return rows, nil
	}
	if strings.Contains(query, "FROM login_attempts WHERE") {
		return &loginSecurityRows{columns: []string{"email_failures", "ip_failures"}, values: []driver.Value{int64(0), int64(0)}}, nil
	}
	return &loginSecurityRows{columns: []string{"unused"}}, nil
}

type loginSecurityRows struct {
	columns []string
	values  []driver.Value
}

func (r *loginSecurityRows) Columns() []string { return r.columns }
func (r *loginSecurityRows) Close() error      { return nil }
func (r *loginSecurityRows) Next(values []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(values, r.values)
	r.values = nil
	return nil
}

func loginSecurityDB(t *testing.T, connector loginSecurityConnector) *sql.DB {
	t.Helper()
	db := sql.OpenDB(connector)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestLoginFailsClosedWhenTOTPStorageUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connector *loginSecurityConnector
	}{
		{name: "missing storage"},
		{name: "lookup failed", connector: &loginSecurityConnector{totpError: errors.New("storage unavailable")}},
		{name: "malformed envelope", connector: &loginSecurityConnector{envelope: []byte(`{invalid`)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := auth.HashPassword("password", auth.TestPasswordParams)
			if err != nil {
				t.Fatal(err)
			}
			store := &fakeSessionStore{}
			options := ServerOptions{}
			if tc.connector != nil {
				options.SecurityDB = loginSecurityDB(t, *tc.connector)
			}
			server := NewServer(fakeUserStore{users: map[string]auth.User{"client@example.test": {ID: 1, Email: "client@example.test", PasswordHash: hash, Role: auth.RoleClient}}}, auth.NewSessionManager(store, auth.SessionOptions{}), options)
			r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("email=client%40example.test&password=password"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status=%d, want 503", w.Code)
			}
			if store.tokenHash != "" {
				t.Error("created a full session without checking TOTP state")
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == SessionCookieName {
					t.Error("set a session cookie without checking TOTP state")
				}
			}
		})
	}
}

func TestLoginWithoutEnrolledTOTPSucceeds(t *testing.T) {
	handler, store := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SecurityDB: loginSecurityDB(t, loginSecurityConnector{})})
	cookie := login(t, handler, "client@nakpanel.test", "NakpanelClient!2026")
	if cookie.Value == "" || store.tokenHash == "" {
		t.Fatal("no session for a user without TOTP")
	}
}

func TestLoginWithConfirmedTOTPStartsChallengeWithoutSession(t *testing.T) {
	handler, store := newTestHandlerWithOptions(t, auth.RoleClient, ServerOptions{SecurityDB: loginSecurityDB(t, loginSecurityConnector{envelope: []byte(`{}`)})})
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("email=client%40nakpanel.test&password=NakpanelClient%212026"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("status=%d location=%q, want TOTP challenge", w.Code, w.Header().Get("Location"))
	}
	if store.tokenHash != "" {
		t.Fatal("created full session before the TOTP challenge")
	}
	challenge := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			t.Fatal("set session cookie before the TOTP challenge")
		}
		if cookie.Name == loginChallengeCookieName && cookie.Value != "" {
			challenge = true
		}
	}
	if !challenge {
		t.Fatal("missing challenge cookie")
	}
}

// fail2banFailregex mirrors deploy/fail2ban/nakpanel-login.conf with <HOST>
// expanded. If these drift apart the jail silently stops matching.
var fail2banFailregex = regexp.MustCompile(`nakpanel-auth: login failed for "[^"]*" from (\S+)\s*$`)

// TestAuthFailureLineAlwaysMatchesFail2banFilter pins a one-character jail
// bypass: the email is attacker-controlled, and %q escapes an embedded quote
// as \", which made [^"]* stop early so the line never matched and the source
// IP was never banned.
func TestAuthFailureLineAlwaysMatchesFail2banFilter(t *testing.T) {
	hostile := []string{
		"victim@example.com",
		`a"b@example.com`,
		`" from 1.2.3.4` + "\n" + `nakpanel-auth: login failed for "x`,
		`back\slash@example.com`,
		strings.Repeat("a", 500) + "@example.com",
		"user with spaces@example.com",
		"\x00\x1b[31m@example.com",
	}
	for _, email := range hostile {
		line := "Aug 27 00:00:00 host nakpanel-auth: login failed for \"" +
			sanitizeLogField(email) + "\" from 203.0.113.5"
		if strings.Count(line, "\n") != 0 {
			t.Fatalf("sanitized line contains a newline for %q", email)
		}
		match := fail2banFailregex.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf("fail2ban filter does not match the line produced for %q:\n%s", email, line)
		}
		if match[1] != "203.0.113.5" {
			t.Fatalf("filter captured host %q (expected 203.0.113.5) for %q", match[1], email)
		}
	}
}

func TestSanitizeLogFieldKeepsOrdinaryEmailsIntact(t *testing.T) {
	for _, email := range []string{"admin@nakpanel.test", "first.last+tag@sub.example.co.uk", "a_b-c@x.io"} {
		if got := sanitizeLogField(email); got != email {
			t.Fatalf("sanitizeLogField(%q) = %q, want it unchanged", email, got)
		}
	}
}
