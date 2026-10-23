package operations

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
)

type Preferences struct {
	EmailMode      string `json:"email_mode"`
	CriticalInApp  bool   `json:"critical_in_app"`
	SecurityInApp  bool   `json:"security_in_app"`
	DeliveryHealth string `json:"delivery_health"`
}
type DeliveryPolicy struct {
	Enabled        bool `json:"enabled"`
	SMTPConfigured bool `json:"smtp_configured"`
}

func (s *Store) SetSMTPConfigured(enabled bool) { s.smtpConfigured.Store(enabled) }
func (s *Store) Preferences(ctx context.Context, a auth.SessionUser) (Preferences, error) {
	p := Preferences{CriticalInApp: true, SecurityInApp: true}
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(p.email_mode,'off') FROM users u LEFT JOIN notification_preferences p ON p.user_id=u.id WHERE u.id=$1 AND u.role=$2 AND NOT u.login_disabled`, a.ID, string(a.Role)).Scan(&p.EmailMode)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	var enabled bool
	var failed, pending, accepted int
	var latest string
	if err = s.db.QueryRowContext(ctx, `SELECT enabled FROM notification_delivery_policy WHERE singleton`).Scan(&enabled); err != nil {
		return p, err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE status='failed'),count(*) FILTER(WHERE status='pending'),count(*) FILTER(WHERE status='accepted') FROM notification_email_batches WHERE recipient_user_id=$1`, a.ID).Scan(&failed, &pending, &accepted); err != nil {
		return p, err
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT status FROM notification_email_batches WHERE recipient_user_id=$1 ORDER BY updated_at DESC,id DESC LIMIT 1),'')`, a.ID).Scan(&latest); err != nil {
		return p, err
	}
	switch {
	case !enabled:
		p.DeliveryHealth = "Email is disabled by server policy. Your inbox remains available."
	case !s.smtpConfigured.Load():
		p.DeliveryHealth = "Server SMTP is not configured. Your inbox remains available."
	case p.EmailMode == "off":
		p.DeliveryHealth = "Email updates are off. Your inbox remains available."
	case latest == "accepted":
		p.DeliveryHealth = "Accepted by SMTP most recently. Arrival in the recipient's inbox has not been verified. Previous failed attempts remain in history."
	case failed > 0:
		p.DeliveryHealth = "Email updates need attention. SMTP acceptance could not be confirmed; retries are bounded."
	case pending > 0:
		p.DeliveryHealth = "Email is queued. Daily digests are sent after 00:00 UTC."
	case accepted > 0:
		p.DeliveryHealth = "Accepted by SMTP. Arrival in the recipient's inbox has not been verified."
	default:
		p.DeliveryHealth = "No email has been accepted by SMTP yet."
	}
	return p, nil
}
func (s *Store) SavePreferences(ctx context.Context, a auth.SessionUser, p Preferences) error {
	switch p.EmailMode {
	case "off", "immediate", "digest":
	default:
		return ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO notification_preferences(user_id,email_mode) SELECT id,$3 FROM users WHERE id=$1 AND role=$2 AND NOT login_disabled ON CONFLICT(user_id) DO UPDATE SET email_mode=EXCLUDED.email_mode,updated_at=now()`, a.ID, string(a.Role), p.EmailMode)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}
func (s *Store) DeliveryPolicy(ctx context.Context, a auth.SessionUser) (DeliveryPolicy, error) {
	p := DeliveryPolicy{SMTPConfigured: s.smtpConfigured.Load()}
	err := s.db.QueryRowContext(ctx, `SELECT enabled FROM notification_delivery_policy WHERE singleton AND EXISTS(SELECT 1 FROM users WHERE id=$1 AND role='admin' AND role=$2 AND NOT login_disabled)`, a.ID, string(a.Role)).Scan(&p.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return p, err
}
func (s *Store) SaveDeliveryPolicy(ctx context.Context, a auth.SessionUser, p DeliveryPolicy) error {
	r, err := s.db.ExecContext(ctx, `UPDATE notification_delivery_policy SET enabled=$3,updated_at=now() WHERE singleton AND EXISTS(SELECT 1 FROM users WHERE id=$1 AND role='admin' AND role=$2 AND NOT login_disabled)`, a.ID, string(a.Role), p.Enabled)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}
