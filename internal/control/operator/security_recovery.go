package operator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
)

// Administrator recovery commands. Everything here is plain SQL so it works
// over root SSH while the panel itself is down or locked out.

func (s *Service) lookupUserID(ctx context.Context, email string) (int64, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var id int64
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT id, role FROM users WHERE email=$1`, email).Scan(&id, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("user %s does not exist", email)
	}
	return id, role, err
}

// SetUserPassword replaces a user's password and revokes every session.
func (s *Service) SetUserPassword(ctx context.Context, email, password string) error {
	if len(password) < 12 {
		return errors.New("password must contain at least 12 characters")
	}
	userID, _, err := s.lookupUserID(ctx, email)
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password, auth.DefaultPasswordParams)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, userID, hash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "user.password_reset", "user", userID, map[string]any{"email": email}); err != nil {
		return err
	}
	return tx.Commit()
}

// DisableUserTOTP removes the second factor and recovery codes so the user
// can sign in with their password again, revoking existing sessions.
func (s *Service) DisableUserTOTP(ctx context.Context, email string) error {
	userID, _, err := s.lookupUserID(ctx, email)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_totp WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_challenges WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "user.totp_disabled_by_operator", "user", userID, map[string]any{"email": email}); err != nil {
		return err
	}
	return tx.Commit()
}

// RegenerateRecoveryCodes voids existing codes and prints a fresh set once.
// The TOTP secret itself is untouched (and never needs the keyring here:
// codes are stored hashed).
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, email string) ([]string, error) {
	userID, _, err := s.lookupUserID(ctx, email)
	if err != nil {
		return nil, err
	}
	var enrolled bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_totp WHERE user_id=$1 AND confirmed_at IS NOT NULL)`, userID).Scan(&enrolled); err != nil {
		return nil, err
	}
	if !enrolled {
		return nil, fmt.Errorf("user %s does not have two-factor authentication enabled", email)
	}
	codes, err := auth.GenerateRecoveryCodes(auth.RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
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
	if err := s.auditTx(ctx, tx, "user.recovery_codes_regenerated_by_operator", "user", userID, map[string]any{"email": email}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// UnlockUserLogin clears the durable login throttle and any pending TOTP
// challenges for the account.
func (s *Service) UnlockUserLogin(ctx context.Context, email string) error {
	normalized := strings.ToLower(strings.TrimSpace(email))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_attempts WHERE email=$1`, normalized); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_challenges WHERE user_id IN (SELECT id FROM users WHERE email=$1)`, normalized); err != nil {
		return err
	}
	if err := s.auditTx(ctx, tx, "user.lockout_cleared", "user", 0, map[string]any{"email": normalized}); err != nil {
		return err
	}
	return tx.Commit()
}

// SecuritySettings is the singleton policy row backing admin-2FA enforcement
// and alert routing.
type SecuritySettings struct {
	RequireTOTPAdmin bool
	AlertEmail       string
}

func (s *Service) GetSecuritySettings(ctx context.Context) (SecuritySettings, error) {
	var settings SecuritySettings
	err := s.db.QueryRowContext(ctx,
		`SELECT require_totp_admin, alert_email FROM security_settings WHERE id`).
		Scan(&settings.RequireTOTPAdmin, &settings.AlertEmail)
	if errors.Is(err, sql.ErrNoRows) {
		// The migration seeds this row; a restore or a hand-edited database
		// can lose it. Recreate rather than reporting policy-off silently.
		if _, insertErr := s.db.ExecContext(ctx,
			`INSERT INTO security_settings (id) VALUES (true) ON CONFLICT (id) DO NOTHING`); insertErr != nil {
			return settings, insertErr
		}
		return SecuritySettings{}, nil
	}
	return settings, err
}

// SetSecuritySettings updates the policy row. Nil fields are left unchanged.
func (s *Service) SetSecuritySettings(ctx context.Context, requireTOTPAdmin *bool, alertEmail *string) (SecuritySettings, error) {
	var current SecuritySettings
	current, err := s.GetSecuritySettings(ctx)
	if err != nil {
		return current, err
	}
	if requireTOTPAdmin != nil {
		current.RequireTOTPAdmin = *requireTOTPAdmin
	}
	if alertEmail != nil {
		trimmed := strings.TrimSpace(*alertEmail)
		if trimmed != "" {
			if _, err := mail.ParseAddress(trimmed); err != nil {
				return current, fmt.Errorf("alert email is not a valid address: %s", trimmed)
			}
		}
		current.AlertEmail = trimmed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return current, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO security_settings (id, require_totp_admin, alert_email)
		 VALUES (true, $1, $2)
		 ON CONFLICT (id) DO UPDATE SET require_totp_admin=EXCLUDED.require_totp_admin,
		     alert_email=EXCLUDED.alert_email, updated_at=now()`,
		current.RequireTOTPAdmin, current.AlertEmail); err != nil {
		return current, err
	}
	if err := s.auditTx(ctx, tx, "security.settings_updated", "security", 0, map[string]any{
		"require_totp_admin": current.RequireTOTPAdmin,
		"alert_email_set":    current.AlertEmail != "",
	}); err != nil {
		return current, err
	}
	return current, tx.Commit()
}
