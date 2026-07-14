package provisioningapi

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

const sessionCookieName = "nakpanel_session"

type RootOptions struct {
	API      http.Handler
	UI       http.Handler
	DB       *sql.DB
	Sessions SessionCreator
}

func NewRootHandler(opts RootOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1" {
			opts.API.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/sso/customer/") {
			handleSSOExchange(opts.DB, opts.Sessions, w, r)
			return
		}
		opts.UI.ServeHTTP(w, r)
	})
}

func handleSSOExchange(db *sql.DB, sessions SessionCreator, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || db == nil || sessions == nil {
		http.NotFound(w, r)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/sso/customer/")
	if !strings.HasPrefix(raw, "sso_") || len(raw) < 40 {
		http.NotFound(w, r)
		return
	}
	digest := sha256.Sum256([]byte(raw))
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "Could not create session", 500)
		return
	}
	defer tx.Rollback()
	var tokenID, userID int64
	err = tx.QueryRowContext(r.Context(), `SELECT token.id,token.user_id
FROM customer_login_tokens token
JOIN billing_accounts b ON b.id=token.billing_account_id
JOIN subscriptions sub ON sub.id=b.subscription_id
JOIN users u ON u.id=token.user_id
WHERE token.token_hash=$1 AND token.used_at IS NULL AND token.expires_at>now()
  AND sub.status IN ('active','suspended') AND b.provisioning_state NOT IN ('terminating','terminated')
  AND u.login_disabled=false
FOR UPDATE OF token`, digest[:]).Scan(&tokenID, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Could not create session", 500)
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE customer_login_tokens SET used_at=now() WHERE id=$1 AND used_at IS NULL`, tokenID); err != nil {
		http.Error(w, "Could not create session", 500)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, "Could not create session", 500)
		return
	}
	token, expiresAt, err := sessions.Create(r.Context(), userID)
	if err != nil {
		http.Error(w, "Could not create session", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", Expires: expiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
