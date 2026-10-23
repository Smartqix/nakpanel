package operations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type EmailTransport func(context.Context, string, string, string) error
type EmailService struct {
	db      *sql.DB
	send    EmailTransport
	profile string
}

func NewEmailService(db *sql.DB, send EmailTransport, profile string) *EmailService {
	return &EmailService{db: db, send: send, profile: profile}
}
func (s *EmailService) Deliver(ctx context.Context) error {
	for n := 0; n < 25; n++ {
		processed, err := s.deliverOne(ctx)
		if err != nil {
			return err
		}
		if !processed {
			return nil
		}
	}
	return nil
}
func (s *EmailService) deliverOne(ctx context.Context) (bool, error) {
	if s.send == nil {
		return false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id, userID int64
	var mode string
	var attempts int
	err = tx.QueryRowContext(ctx, `SELECT id,recipient_user_id,mode,attempts FROM notification_email_batches WHERE status IN ('pending','failed') AND attempts<8 AND next_attempt_at<=now() ORDER BY next_attempt_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id, &userID, &mode, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var enabled bool
	var policyAt time.Time
	if err = tx.QueryRowContext(ctx, `SELECT enabled,updated_at FROM notification_delivery_policy WHERE singleton FOR SHARE`).Scan(&enabled, &policyAt); err != nil {
		return false, err
	}
	if err = lockEmailScopeTx(ctx, tx, id, userID); err != nil {
		return false, err
	}
	var role, email, currentMode string
	var disabled bool
	if err = tx.QueryRowContext(ctx, `SELECT u.role,u.email,u.login_disabled,COALESCE(p.email_mode,'off') FROM users u LEFT JOIN notification_preferences p ON p.user_id=u.id WHERE u.id=$1 FOR SHARE OF u`, userID).Scan(&role, &email, &disabled, &currentMode); err != nil {
		return false, err
	}
	skip := func(reason string) (bool, error) {
		_, err := tx.ExecContext(ctx, `UPDATE notification_email_batches SET status='skipped',last_error=$2,updated_at=now() WHERE id=$1`, id, reason)
		if err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	if !enabled || disabled || currentMode != mode || currentMode == "off" {
		return skip("policy_or_preference_changed")
	}
	rows, err := tx.QueryContext(ctx, `SELECT n.title,CASE WHEN n.kind IN ('threshold','over_limit','suspended','certificate_expiring','login_new_device','login_failed_burst','operation_failed','issue_recovered') THEN left(n.body,2000) ELSE 'Open Activity to review the affected resource.' END FROM notification_email_items item JOIN notifications n ON n.id=item.notification_id LEFT JOIN issues ni ON ni.id=n.issue_id WHERE item.batch_id=$3 AND item.user_id=$1 AND COALESCE(ni.kind,'')<>'notification_delivery' AND `+NotificationVisibilitySQL("n", 1, 2)+` ORDER BY n.id`, userID, role, id)
	if err != nil {
		return false, err
	}
	var messages []string
	total := 0
	for rows.Next() {
		var title, summary string
		if err = rows.Scan(&title, &summary); err != nil {
			rows.Close()
			return false, err
		}
		total++
		if len(messages) < 50 {
			messages = append(messages, strings.Join(strings.Fields(title), " ")+"\n"+summary)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if len(messages) == 0 {
		return skip("recipient_scope_changed")
	}
	if total > len(messages) {
		messages = append(messages, fmt.Sprintf("%d additional updates are available in Activity.", total-len(messages)))
	}
	body := strings.Join(messages, "\n\n") + "\n\nOpen Activity in Nakpanel for current status. Reading an update does not resolve an issue."
	sendCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	sendErr := s.send(sendCtx, email, "Nakpanel updates", body)
	store := NewStore(s.db)
	fingerprint := sha256.Sum256([]byte(s.profile + "|" + policyAt.UTC().Format(time.RFC3339Nano) + "|" + fmt.Sprint(userID) + "|" + role + "|" + email + "|" + currentMode))
	hash := hex.EncodeToString(fingerprint[:])
	revision := int64(binary.BigEndian.Uint64(fingerprint[:8]) & 0x7fffffffffffffff)
	if sendErr != nil {
		delay := time.Minute * time.Duration(1<<min(attempts, 6))
		if _, err = tx.ExecContext(ctx, `UPDATE notification_email_batches SET status='failed',attempts=attempts+1,last_error='smtp_acceptance_unconfirmed',next_attempt_at=$2,updated_at=now() WHERE id=$1`, id, time.Now().Add(delay)); err != nil {
			return false, err
		}
		if err = store.ObserveConditionTx(ctx, tx, ConditionSample{Resource: Resource{Kind: ResourceUser, ID: userID}, Kind: "notification_delivery", Condition: "smtp", Signature: hash, Unhealthy: true, Severity: "warning", Title: "Email updates need attention", Summary: "SMTP acceptance could not be confirmed. Your in-app inbox remains available. Delivery retries are bounded.", IntentRevision: revision, ObservedAt: time.Now().UTC()}); err != nil {
			return false, err
		}
	} else {
		acceptedAt := time.Now().UTC()
		if _, err = tx.ExecContext(ctx, `UPDATE notification_email_batches SET status='accepted',attempts=attempts+1,last_error='',accepted_at=$2,updated_at=now() WHERE id=$1`, id, acceptedAt); err != nil {
			return false, err
		}
		if err = store.ObserveConditionTx(ctx, tx, ConditionSample{Resource: Resource{Kind: ResourceUser, ID: userID}, Kind: "notification_delivery", Condition: "smtp", Signature: hash, Unhealthy: false, ObservedAt: acceptedAt}); err != nil {
			return false, err
		}
		var issueID int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM issues WHERE resource_kind='user' AND resource_id=$1 AND kind='notification_delivery' AND condition='smtp' AND resolved_at IS NULL FOR UPDATE`, userID).Scan(&issueID)
		if err == nil {
			issue, loadErr := store.IssueForUpdateTx(ctx, tx, issueID)
			if loadErr != nil {
				return false, loadErr
			}
			token, checkErr := store.SetCheckingTx(ctx, tx, issue, revision)
			if checkErr != nil {
				return false, checkErr
			}
			receipt := VerificationReceipt{Token: token, IntentHash: hash, Source: "smtp_acceptance", SourceID: id, ObservedAt: acceptedAt, Summary: "Accepted by SMTP. Arrival in the recipient's inbox has not been verified."}
			if err = store.ResolveVerifiedTx(ctx, tx, receipt, hash, revision); err != nil {
				return false, err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	return true, tx.Commit()
}
