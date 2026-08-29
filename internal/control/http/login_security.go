package panelhttp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/control/web"
	qrcode "github.com/skip2/go-qrcode"
)

// Production login hardening: a durable failure throttle, uniform timing for
// unknown accounts, TOTP second factor with single-use recovery codes, and
// journald-structured failure lines that fail2ban's nakpanel-login jail
// consumes.

const (
	loginChallengeCookieName  = "nakpanel_challenge"
	loginChallengeTTL         = 5 * time.Minute
	loginChallengeMaxAttempts = 5

	loginFailWindow     = 15 * time.Minute
	loginFailEmailLimit = 10
	loginFailIPLimit    = 20

	totpIssuer = "nakpanel"
)

var (
	dummyHashOnce  sync.Once
	dummyHashValue string
)

// dummyPasswordHash gives unknown-email logins the same argon2id cost as a
// real verification, closing the account-enumeration timing oracle.
func dummyPasswordHash() string {
	dummyHashOnce.Do(func() {
		var raw [24]byte
		_, _ = rand.Read(raw[:])
		hash, err := auth.HashPassword(base64.RawStdEncoding.EncodeToString(raw[:]), auth.DefaultPasswordParams)
		if err == nil {
			dummyHashValue = hash
		}
	})
	return dummyHashValue
}

func clientIP(r *http.Request) string {
	// Deliberately no X-Forwarded-For trust: the panel terminates TLS itself.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// logAuthFailure emits the exact line the fail2ban nakpanel-login filter
// matches; keep the format in sync with deploy/fail2ban/nakpanel-login.conf.
//
// The email is attacker-controlled, so it is sanitized rather than %q-quoted:
// %q escapes an embedded quote as \", which lets [^"]* in the filter stop
// early and makes the whole line unmatchable — a one-character jail bypass.
func logAuthFailure(email, ip string) {
	log.Printf("nakpanel-auth: login failed for %q from %s", sanitizeLogField(email), ip)
}

// sanitizeLogField reduces attacker-controlled text to a bounded set of
// characters that can never terminate or confuse the log line the fail2ban
// filter parses.
func sanitizeLogField(value string) string {
	const maxLen = 120
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '@' || r == '.' || r == '-' || r == '_' || r == '+':
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
		if b.Len() >= maxLen {
			break
		}
	}
	return b.String()
}

func (s *Server) recordLoginAttempt(ctx context.Context, email, ip, stage string, succeeded bool) {
	if s.securityDB == nil {
		return
	}
	if _, err := s.securityDB.ExecContext(ctx,
		`INSERT INTO login_attempts(email, ip_address, stage, succeeded) VALUES ($1,$2,$3,$4)`,
		email, ip, stage, succeeded); err != nil {
		log.Printf("record login attempt: %v", err)
		return
	}
	// Opportunistic retention: the table is forensic, not archival.
	_, _ = s.securityDB.ExecContext(ctx,
		`DELETE FROM login_attempts WHERE attempted_at < now() - interval '24 hours'`)
}

func (s *Server) loginThrottled(ctx context.Context, email, ip string) bool {
	if s.securityDB == nil {
		return false
	}
	var emailFails, ipFails int
	err := s.securityDB.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM login_attempts WHERE email=$1 AND NOT succeeded AND attempted_at > now() - $3::interval),
		(SELECT count(*) FROM login_attempts WHERE ip_address=$2 AND NOT succeeded AND attempted_at > now() - $3::interval)`,
		email, ip, loginFailWindow.String()).Scan(&emailFails, &ipFails)
	if err != nil {
		log.Printf("login throttle query: %v", err)
		return false
	}
	return emailFails >= loginFailEmailLimit || ipFails >= loginFailIPLimit
}

// auditAuth writes authentication audit events attributed by email label.
// Deliberately not by actor_user_id: login events exist for every account,
// and an FK reference would make user rows undeletable.
func (s *Server) auditAuth(ctx context.Context, action string, userID int64, email string, metadata map[string]any) {
	if s.securityDB == nil {
		return
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	if userID > 0 {
		metadata["user_id"] = userID
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		data = []byte(`{}`)
	}
	label := strings.TrimSpace(email)
	if label == "" {
		label = "unknown"
	}
	if _, err := s.securityDB.ExecContext(ctx,
		`INSERT INTO audit_events(actor_label, action, target_type, target_id, metadata)
		 VALUES ($1, $2, 'auth', NULL, $3::jsonb)`,
		label, action, string(data)); err != nil {
		log.Printf("write auth audit event: %v", err)
	}
}

// --- security settings ----------------------------------------------------

func (s *Server) securitySettings(ctx context.Context) (requireTOTPAdmin bool, alertEmail string) {
	if s.securityDB == nil {
		return false, ""
	}
	_ = s.securityDB.QueryRowContext(ctx,
		`SELECT require_totp_admin, alert_email FROM security_settings WHERE id`).Scan(&requireTOTPAdmin, &alertEmail)
	return requireTOTPAdmin, alertEmail
}

// --- TOTP persistence ------------------------------------------------------

type userTOTPRecord struct {
	Envelope     serveradmin.Envelope
	Confirmed    bool
	LastUsedStep int64
}

func totpAAD(userID int64) []byte {
	return []byte(fmt.Sprintf("user-totp:%d", userID))
}

func (s *Server) getUserTOTP(ctx context.Context, userID int64) (userTOTPRecord, bool, error) {
	var record userTOTPRecord
	if s.securityDB == nil {
		return record, false, nil
	}
	var envelope []byte
	var confirmedAt sql.NullTime
	err := s.securityDB.QueryRowContext(ctx,
		`SELECT secret_envelope, confirmed_at, last_used_step FROM user_totp WHERE user_id=$1`,
		userID).Scan(&envelope, &confirmedAt, &record.LastUsedStep)
	if errors.Is(err, sql.ErrNoRows) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := json.Unmarshal(envelope, &record.Envelope); err != nil {
		return record, false, fmt.Errorf("decode totp envelope: %w", err)
	}
	record.Confirmed = confirmedAt.Valid
	return record, true, nil
}

func (s *Server) openTOTPSecret(record userTOTPRecord, userID int64) ([]byte, error) {
	if s.securityKeyring == nil {
		return nil, errors.New("the secret keyring is not configured")
	}
	return s.securityKeyring.Open(record.Envelope, totpAAD(userID))
}

func (s *Server) upsertProvisionalTOTP(ctx context.Context, userID int64, secret []byte) error {
	if s.securityDB == nil || s.securityKeyring == nil {
		return errors.New("two-factor authentication requires the secret keyring")
	}
	envelope, err := s.securityKeyring.Seal(secret, totpAAD(userID))
	if err != nil {
		return err
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	_, err = s.securityDB.ExecContext(ctx, `INSERT INTO user_totp(user_id, secret_envelope)
		VALUES ($1, $2::jsonb)
		ON CONFLICT (user_id) DO UPDATE SET secret_envelope=EXCLUDED.secret_envelope,
			confirmed_at=NULL, last_used_step=0, updated_at=now()`, userID, string(payload))
	return err
}

func (s *Server) confirmTOTP(ctx context.Context, userID, acceptedStep int64) error {
	_, err := s.securityDB.ExecContext(ctx,
		`UPDATE user_totp SET confirmed_at=now(), last_used_step=$2, updated_at=now() WHERE user_id=$1`,
		userID, acceptedStep)
	return err
}

func (s *Server) advanceTOTPStep(ctx context.Context, userID, acceptedStep int64) (bool, error) {
	result, err := s.securityDB.ExecContext(ctx,
		`UPDATE user_totp SET last_used_step=$2, updated_at=now()
		 WHERE user_id=$1 AND last_used_step < $2`, userID, acceptedStep)
	if err != nil {
		return false, err
	}
	affected, _ := result.RowsAffected()
	return affected == 1, nil
}

func (s *Server) deleteTOTP(ctx context.Context, userID int64) error {
	if _, err := s.securityDB.ExecContext(ctx, `DELETE FROM user_totp WHERE user_id=$1`, userID); err != nil {
		return err
	}
	_, err := s.securityDB.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id=$1`, userID)
	return err
}

func (s *Server) replaceRecoveryCodes(ctx context.Context, userID int64) ([]string, error) {
	codes, err := auth.GenerateRecoveryCodes(auth.RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	tx, err := s.securityDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return nil, err
	}
	for _, code := range codes {
		hash, err := auth.HashPassword(auth.NormalizeRecoveryCode(code), auth.DefaultPasswordParams)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_recovery_codes(user_id, code_hash) VALUES ($1,$2)`, userID, hash); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *Server) consumeRecoveryCode(ctx context.Context, userID int64, code string) (remaining int, ok bool, err error) {
	normalized := auth.NormalizeRecoveryCode(code)
	if normalized == "" {
		return 0, false, nil
	}
	rows, err := s.securityDB.QueryContext(ctx,
		`SELECT id, code_hash FROM user_recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID)
	if err != nil {
		return 0, false, err
	}
	type candidate struct {
		id   int64
		hash string
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			rows.Close()
			return 0, false, err
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	for _, c := range candidates {
		match, verifyErr := auth.VerifyPassword(normalized, c.hash)
		if verifyErr != nil || !match {
			continue
		}
		result, err := s.securityDB.ExecContext(ctx,
			`UPDATE user_recovery_codes SET used_at=now() WHERE id=$1 AND used_at IS NULL`, c.id)
		if err != nil {
			return 0, false, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			continue // raced another consumer; the code counts as used
		}
		return len(candidates) - 1, true, nil
	}
	return len(candidates), false, nil
}

func (s *Server) countRecoveryCodes(ctx context.Context, userID int64) int {
	if s.securityDB == nil {
		return 0
	}
	var count int
	_ = s.securityDB.QueryRowContext(ctx,
		`SELECT count(*) FROM user_recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&count)
	return count
}

// --- login challenges ------------------------------------------------------

func challengeCSRFToken(cookieValue string) string {
	// A distinct derivation prefix so a challenge token can never forge a
	// session CSRF token or vice versa.
	sum := sha256.Sum256([]byte("nakpanel-csrf-2fa-v1:" + cookieValue))
	return hex.EncodeToString(sum[:])
}

func (s *Server) createLoginChallenge(ctx context.Context, userID int64, ip, userAgent string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	if _, err := s.securityDB.ExecContext(ctx,
		`INSERT INTO login_challenges(token_hash, user_id, expires_at, ip_address, user_agent)
		 VALUES ($1,$2,now() + $3::interval,$4,$5)`,
		auth.TokenHash(token), userID, loginChallengeTTL.String(), ip, userAgent); err != nil {
		return "", err
	}
	_, _ = s.securityDB.ExecContext(ctx, `DELETE FROM login_challenges WHERE expires_at < now()`)
	return token, nil
}

type loginChallenge struct {
	TokenHash string
	UserID    int64
	Attempts  int
	IPAddress string
	UserAgent string
}

func (s *Server) loadLoginChallenge(ctx context.Context, token string) (loginChallenge, bool) {
	var challenge loginChallenge
	if s.securityDB == nil || token == "" {
		return challenge, false
	}
	challenge.TokenHash = auth.TokenHash(token)
	err := s.securityDB.QueryRowContext(ctx,
		`SELECT user_id, attempts, ip_address, user_agent FROM login_challenges
		 WHERE token_hash=$1 AND expires_at > now()`, challenge.TokenHash).
		Scan(&challenge.UserID, &challenge.Attempts, &challenge.IPAddress, &challenge.UserAgent)
	if err != nil {
		return challenge, false
	}
	return challenge, true
}

func (s *Server) bumpChallengeAttempts(ctx context.Context, tokenHash string) int {
	var attempts int
	err := s.securityDB.QueryRowContext(ctx,
		`UPDATE login_challenges SET attempts=attempts+1 WHERE token_hash=$1 RETURNING attempts`,
		tokenHash).Scan(&attempts)
	if err != nil {
		return loginChallengeMaxAttempts + 1
	}
	return attempts
}

func (s *Server) deleteLoginChallenge(ctx context.Context, tokenHash string) {
	_, _ = s.securityDB.ExecContext(ctx, `DELETE FROM login_challenges WHERE token_hash=$1`, tokenHash)
}

func setChallengeCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginChallengeCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(loginChallengeTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearChallengeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginChallengeCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- login alerts ----------------------------------------------------------

func (s *Server) alertRecipients(ctx context.Context, alertEmail string) []string {
	if email := strings.TrimSpace(alertEmail); email != "" {
		return []string{email}
	}
	rows, err := s.securityDB.QueryContext(ctx,
		`SELECT email FROM users WHERE role='admin' AND NOT login_disabled ORDER BY email`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var recipients []string
	for rows.Next() {
		var email string
		if rows.Scan(&email) == nil {
			recipients = append(recipients, email)
		}
	}
	return recipients
}

func (s *Server) insertLoginNotification(ctx context.Context, kind, severity, title, body, dedupeKey string, recipientUserID int64, recipients []string) {
	tx, err := s.securityDB.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()
	var notificationID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO notifications(recipient_user_id,kind,severity,title,body,dedupe_key)
		VALUES (NULLIF($1,0),$2,$3,$4,$5,$6)
		ON CONFLICT (dedupe_key) WHERE resolved_at IS NULL
		DO UPDATE SET body=EXCLUDED.body, updated_at=now()
		RETURNING id`, recipientUserID, kind, severity, title, body, dedupeKey).Scan(&notificationID); err != nil {
		log.Printf("insert %s notification: %v", kind, err)
		return
	}
	for _, recipient := range recipients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries(notification_id,channel,recipient)
			VALUES ($1,'smtp',$2) ON CONFLICT (notification_id,channel,recipient) DO NOTHING`,
			notificationID, recipient); err != nil {
			log.Printf("queue %s delivery: %v", kind, err)
			return
		}
	}
	_ = tx.Commit()
}

// alertNewDevice notifies the account owner (and ops for admin accounts) when
// a session is minted from an IP the account has not used in 90 days.
func (s *Server) alertNewDevice(ctx context.Context, userID int64, email, role, ip, tokenHash string) {
	if s.securityDB == nil || ip == "" {
		return
	}
	var known bool
	err := s.securityDB.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM sessions WHERE user_id=$1 AND ip_address=$2 AND token_hash <> $3
		AND created_at > now() - interval '90 days')`, userID, ip, tokenHash).Scan(&known)
	if err != nil || known {
		return
	}
	_, alertEmail := s.securitySettings(ctx)
	recipients := []string{email}
	if role == "admin" {
		for _, extra := range s.alertRecipients(ctx, alertEmail) {
			if extra != email {
				recipients = append(recipients, extra)
			}
		}
	}
	title := "New sign-in address"
	body := fmt.Sprintf("Account %s signed in from %s, an address it has not used in the last 90 days.", email, ip)
	dedupe := fmt.Sprintf("login_new_device:%d:%s", userID, ip)
	s.insertLoginNotification(ctx, "login_new_device", "info", title, body, dedupe, userID, recipients)
}

// alertFailedBurst notifies ops once per hour bucket when the throttle trips.
func (s *Server) alertFailedBurst(ctx context.Context, email, ip string) {
	if s.securityDB == nil {
		return
	}
	_, alertEmail := s.securitySettings(ctx)
	recipients := s.alertRecipients(ctx, alertEmail)
	title := "Login failure burst"
	body := fmt.Sprintf("Repeated failed logins for %s (latest from %s); further attempts are being throttled.", email, ip)
	dedupe := fmt.Sprintf("login_failed_burst:%s:%s", email, time.Now().UTC().Format("2006-01-02-15"))
	s.insertLoginNotification(ctx, "login_failed_burst", "warning", title, body, dedupe, 0, recipients)
}

// --- login flow ------------------------------------------------------------

func (s *Server) loginFailure(w http.ResponseWriter, r *http.Request, email, ip, stage string) {
	s.recordLoginAttempt(r.Context(), email, ip, stage, false)
	logAuthFailure(email, ip)
	s.auditAuth(r.Context(), "auth.login_failed", 0, email, map[string]any{"ip": ip, "stage": stage})
	http.Error(w, "Invalid email or password", http.StatusUnauthorized)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid login form", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.Form.Get("email")))
	password := r.Form.Get("password")
	ip := clientIP(r)
	userAgent := r.UserAgent()

	if s.loginThrottled(r.Context(), email, ip) {
		// Deliberately no recordLoginAttempt here: writing another failure row
		// for a request that was never evaluated would keep sliding the
		// window forward, so one request per minute could hold an account
		// locked out forever. The lockout must be able to expire.
		logAuthFailure(email, ip)
		s.auditAuth(r.Context(), "auth.login_locked", 0, email, map[string]any{"ip": ip})
		s.alertFailedBurst(r.Context(), email, ip)
		http.Error(w, "Too many login attempts; try again later", http.StatusTooManyRequests)
		return
	}

	user, err := s.users.FindUserByEmail(r.Context(), email)
	if err != nil {
		// Same argon2id cost as a real verification.
		if dummy := dummyPasswordHash(); dummy != "" {
			_, _ = auth.VerifyPassword(password, dummy)
		}
		s.loginFailure(w, r, email, ip, "password")
		return
	}
	if !user.Role.Valid() {
		http.Error(w, "Invalid account role", http.StatusInternalServerError)
		return
	}

	ok, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		s.loginFailure(w, r, email, ip, "password")
		return
	}
	s.recordLoginAttempt(r.Context(), email, ip, "password", true)

	record, exists, err := s.getUserTOTP(r.Context(), user.ID)
	if err != nil {
		log.Printf("load totp state: %v", err)
	}
	if exists && record.Confirmed {
		token, err := s.createLoginChallenge(r.Context(), user.ID, ip, userAgent)
		if err != nil {
			http.Error(w, "Could not start the verification step", http.StatusInternalServerError)
			return
		}
		setChallengeCookie(w, token)
		target := "/login/2fa"
		if r.Form.Get("legacy") == "1" {
			target += "?legacy=1"
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}

	s.finishLogin(w, r, user.ID, email, string(user.Role), ip, userAgent, false)
}

// finishLogin mints the session, audits, alerts, and redirects.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, userID int64, email, role, ip, userAgent string, usedTOTP bool) {
	token, expiresAt, err := s.sessions.Create(r.Context(), userID, auth.SessionMeta{IPAddress: ip, UserAgent: userAgent})
	if err != nil {
		http.Error(w, "Could not create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	s.auditAuth(r.Context(), "auth.login_succeeded", userID, email, map[string]any{"ip": ip, "totp": usedTOTP})
	s.alertNewDevice(r.Context(), userID, email, role, ip, auth.TokenHash(token))

	legacy := r.Form.Get("legacy") == "1" || r.URL.Query().Get("legacy") == "1"
	target := "/dashboard"
	if legacy {
		target = "/?legacy=1"
	}
	if role == "admin" && !usedTOTP {
		if requireTOTP, _ := s.securitySettings(r.Context()); requireTOTP {
			// Soft enforcement: the session exists, but administrators are
			// steered into enrollment until a confirmed authenticator exists.
			if _, exists, _ := s.getUserTOTP(r.Context(), userID); !exists {
				target = "/account/2fa"
			}
		}
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleTOTPChallengeForm(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginChallengeCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if _, ok := s.loadLoginChallenge(r.Context(), cookie.Value); !ok {
		clearChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	renderPage(w, r, web.TOTPChallengePage(challengeCSRFToken(cookie.Value), ""))
}

func (s *Server) handleTOTPChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(loginChallengeCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	challenge, ok := s.loadLoginChallenge(r.Context(), cookie.Value)
	if !ok {
		clearChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip := clientIP(r)

	var email string
	var role string
	if err := s.securityDB.QueryRowContext(r.Context(),
		`SELECT email, role FROM users WHERE id=$1`, challenge.UserID).Scan(&email, &role); err != nil {
		clearChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if attempts := s.bumpChallengeAttempts(r.Context(), challenge.TokenHash); attempts > loginChallengeMaxAttempts {
		s.deleteLoginChallenge(r.Context(), challenge.TokenHash)
		clearChallengeCookie(w)
		s.recordLoginAttempt(r.Context(), email, ip, "totp", false)
		logAuthFailure(email, ip)
		s.auditAuth(r.Context(), "auth.totp_challenge_failed", challenge.UserID, email, map[string]any{"ip": ip, "reason": "attempts"})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	code := strings.TrimSpace(r.Form.Get("code"))
	recoveryCode := strings.TrimSpace(r.Form.Get("recovery_code"))

	if recoveryCode != "" {
		remaining, consumed, err := s.consumeRecoveryCode(r.Context(), challenge.UserID, recoveryCode)
		if err != nil {
			http.Error(w, "Verification is unavailable", http.StatusInternalServerError)
			return
		}
		if !consumed {
			s.recordLoginAttempt(r.Context(), email, ip, "recovery", false)
			logAuthFailure(email, ip)
			s.auditAuth(r.Context(), "auth.totp_challenge_failed", challenge.UserID, email, map[string]any{"ip": ip, "reason": "recovery_code"})
			renderPage(w, r, web.TOTPChallengePage(challengeCSRFToken(cookie.Value), "That recovery code is not valid."))
			return
		}
		s.recordLoginAttempt(r.Context(), email, ip, "recovery", true)
		s.auditAuth(r.Context(), "auth.recovery_code_used", challenge.UserID, email, map[string]any{"ip": ip, "remaining": remaining})
		if remaining <= 2 {
			recipients := []string{email}
			s.insertLoginNotification(r.Context(), "login_new_device", "warning",
				"Recovery codes running low",
				fmt.Sprintf("Account %s has %d unused two-factor recovery codes left. Generate a fresh set from Account Security.", email, remaining),
				fmt.Sprintf("login_new_device:recovery-low:%d", challenge.UserID), challenge.UserID, recipients)
		}
		s.deleteLoginChallenge(r.Context(), challenge.TokenHash)
		clearChallengeCookie(w)
		s.finishLogin(w, r, challenge.UserID, email, role, ip, challenge.UserAgent, true)
		return
	}

	record, exists, err := s.getUserTOTP(r.Context(), challenge.UserID)
	if err != nil || !exists || !record.Confirmed {
		clearChallengeCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secret, err := s.openTOTPSecret(record, challenge.UserID)
	if err != nil {
		http.Error(w, "Verification is unavailable", http.StatusInternalServerError)
		return
	}
	acceptedStep, valid := auth.VerifyTOTP(secret, code, time.Now(), record.LastUsedStep)
	if valid {
		advanced, err := s.advanceTOTPStep(r.Context(), challenge.UserID, acceptedStep)
		if err != nil || !advanced {
			valid = false
		}
	}
	if !valid {
		s.recordLoginAttempt(r.Context(), email, ip, "totp", false)
		logAuthFailure(email, ip)
		s.auditAuth(r.Context(), "auth.totp_challenge_failed", challenge.UserID, email, map[string]any{"ip": ip, "reason": "code"})
		renderPage(w, r, web.TOTPChallengePage(challengeCSRFToken(cookie.Value), "That code is not valid. Codes are single-use and expire quickly."))
		return
	}
	s.recordLoginAttempt(r.Context(), email, ip, "totp", true)
	s.deleteLoginChallenge(r.Context(), challenge.TokenHash)
	clearChallengeCookie(w)
	s.finishLogin(w, r, challenge.UserID, email, role, ip, challenge.UserAgent, true)
}

// --- enrollment ------------------------------------------------------------

func (s *Server) requireRecentAuth(w http.ResponseWriter, r *http.Request) (auth.SessionUser, bool) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return auth.SessionUser{}, false
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		http.Error(w, "Recent authentication is required; confirm your password under Tools & Settings first.", http.StatusPreconditionRequired)
		return auth.SessionUser{}, false
	}
	return user, true
}

func (s *Server) handleTwoFactorPage(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	record, exists, err := s.getUserTOTP(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Two-factor state is unavailable", http.StatusInternalServerError)
		return
	}
	view := web.TwoFactorView{
		CSRFToken:      csrfToken(r),
		Enrolled:       exists && record.Confirmed,
		Pending:        exists && !record.Confirmed,
		RecoveryCodes:  nil,
		RecoveryUnused: s.countRecoveryCodes(r.Context(), user.ID),
		RecentAuth:     s.sessions.RecentlyAuthenticated(user, 10*time.Minute),
	}
	renderPage(w, r, web.TwoFactorPage(user, view))
}

func (s *Server) handleTwoFactorSetup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireRecentAuth(w, r)
	if !ok {
		return
	}
	// Re-enrolling would clear confirmed_at and drop the account back to
	// password-only immediately, bypassing the second-factor proof that
	// handleTwoFactorDisable requires. Disable explicitly first.
	if record, exists, err := s.getUserTOTP(r.Context(), user.ID); err == nil && exists && record.Confirmed {
		http.Error(w, "Two-factor authentication is already enabled; disable it first (which requires a current code or a recovery code) before enrolling a new authenticator.", http.StatusConflict)
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		http.Error(w, "Could not generate a secret", http.StatusInternalServerError)
		return
	}
	if err := s.upsertProvisionalTOTP(r.Context(), user.ID, secret); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uri := auth.OTPAuthURI(totpIssuer, user.Email, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 220)
	qrDataURI := ""
	if err == nil {
		qrDataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	view := web.TwoFactorView{
		CSRFToken:  csrfToken(r),
		Pending:    true,
		Secret:     auth.FormatTOTPSecret(secret),
		OTPAuthURI: uri,
		QRDataURI:  qrDataURI,
		RecentAuth: true,
	}
	renderPage(w, r, web.TwoFactorPage(user, view))
}

func (s *Server) handleTwoFactorActivate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireRecentAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	record, exists, err := s.getUserTOTP(r.Context(), user.ID)
	if err != nil || !exists {
		http.Error(w, "Start enrollment first", http.StatusBadRequest)
		return
	}
	secret, err := s.openTOTPSecret(record, user.ID)
	if err != nil {
		http.Error(w, "Two-factor state is unavailable", http.StatusInternalServerError)
		return
	}
	acceptedStep, valid := auth.VerifyTOTP(secret, r.Form.Get("code"), time.Now(), record.LastUsedStep)
	if !valid {
		view := web.TwoFactorView{
			CSRFToken: csrfToken(r), Pending: true,
			Secret: auth.FormatTOTPSecret(secret), OTPAuthURI: auth.OTPAuthURI(totpIssuer, user.Email, secret),
			Error: "That code did not match. Scan the QR code again and enter the current code.", RecentAuth: true,
		}
		renderPage(w, r, web.TwoFactorPage(user, view))
		return
	}
	if err := s.confirmTOTP(r.Context(), user.ID, acceptedStep); err != nil {
		http.Error(w, "Could not activate two-factor authentication", http.StatusInternalServerError)
		return
	}
	codes, err := s.replaceRecoveryCodes(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Could not generate recovery codes", http.StatusInternalServerError)
		return
	}
	// Any other session for this user predates the second factor.
	if cookie, cookieErr := r.Cookie(SessionCookieName); cookieErr == nil {
		_, _ = s.securityDB.ExecContext(r.Context(),
			`DELETE FROM sessions WHERE user_id=$1 AND token_hash <> $2`, user.ID, auth.TokenHash(cookie.Value))
	}
	s.auditAuth(r.Context(), "auth.totp_enrolled", user.ID, user.Email, nil)
	view := web.TwoFactorView{
		CSRFToken: csrfToken(r), Enrolled: true, RecoveryCodes: codes,
		RecoveryUnused: len(codes), RecentAuth: true,
	}
	renderPage(w, r, web.TwoFactorPage(user, view))
}

func (s *Server) handleTwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireRecentAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	record, exists, err := s.getUserTOTP(r.Context(), user.ID)
	if err != nil || !exists || !record.Confirmed {
		http.Error(w, "Two-factor authentication is not enabled", http.StatusBadRequest)
		return
	}
	verified := false
	if code := strings.TrimSpace(r.Form.Get("code")); code != "" {
		if secret, err := s.openTOTPSecret(record, user.ID); err == nil {
			if step, valid := auth.VerifyTOTP(secret, code, time.Now(), record.LastUsedStep); valid {
				// Consume the step so the same code cannot be replayed.
				if advanced, err := s.advanceTOTPStep(r.Context(), user.ID, step); err == nil && advanced {
					verified = true
				}
			}
		}
	}
	if !verified {
		if _, consumed, _ := s.consumeRecoveryCode(r.Context(), user.ID, r.Form.Get("recovery_code")); consumed {
			verified = true
		}
	}
	if !verified {
		http.Error(w, "A current authenticator code or recovery code is required to disable two-factor authentication", http.StatusForbidden)
		return
	}
	if err := s.deleteTOTP(r.Context(), user.ID); err != nil {
		http.Error(w, "Could not disable two-factor authentication", http.StatusInternalServerError)
		return
	}
	if cookie, cookieErr := r.Cookie(SessionCookieName); cookieErr == nil {
		_, _ = s.securityDB.ExecContext(r.Context(),
			`DELETE FROM sessions WHERE user_id=$1 AND token_hash <> $2`, user.ID, auth.TokenHash(cookie.Value))
	}
	s.auditAuth(r.Context(), "auth.totp_disabled", user.ID, user.Email, nil)
	http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
}

func (s *Server) handleTwoFactorRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireRecentAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	record, exists, err := s.getUserTOTP(r.Context(), user.ID)
	if err != nil || !exists || !record.Confirmed {
		http.Error(w, "Two-factor authentication is not enabled", http.StatusBadRequest)
		return
	}
	secret, err := s.openTOTPSecret(record, user.ID)
	if err != nil {
		http.Error(w, "Two-factor state is unavailable", http.StatusInternalServerError)
		return
	}
	acceptedStep, valid := auth.VerifyTOTP(secret, r.Form.Get("code"), time.Now(), record.LastUsedStep)
	if !valid {
		http.Error(w, "A current authenticator code is required to regenerate recovery codes", http.StatusForbidden)
		return
	}
	// Honour single-use: a code whose step was already consumed must not be
	// replayable here, which is exactly the action worth replaying.
	advanced, err := s.advanceTOTPStep(r.Context(), user.ID, acceptedStep)
	if err != nil {
		http.Error(w, "Could not regenerate recovery codes", http.StatusInternalServerError)
		return
	}
	if !advanced {
		http.Error(w, "That authenticator code was already used; wait for the next one", http.StatusForbidden)
		return
	}
	codes, err := s.replaceRecoveryCodes(r.Context(), user.ID)
	if err != nil {
		http.Error(w, "Could not regenerate recovery codes", http.StatusInternalServerError)
		return
	}
	s.auditAuth(r.Context(), "auth.recovery_codes_regenerated", user.ID, user.Email, nil)
	view := web.TwoFactorView{
		CSRFToken: csrfToken(r), Enrolled: true, RecoveryCodes: codes,
		RecoveryUnused: len(codes), RecentAuth: true,
	}
	renderPage(w, r, web.TwoFactorPage(user, view))
}
