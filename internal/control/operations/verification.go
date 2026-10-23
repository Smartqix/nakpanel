package operations

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// VerificationReceipt records exactly what an independent read-only probe proved.
// It carries no archive path, credential, worker arguments or raw diagnostic.
type VerificationReceipt struct {
	Token      VerificationToken `json:"token"`
	IntentHash string            `json:"intent_hash"`
	Source     string            `json:"source"`
	SourceID   int64             `json:"source_id,omitempty"`
	Checksum   string            `json:"checksum,omitempty"`
	SizeBytes  int64             `json:"size_bytes,omitempty"`
	ObservedAt time.Time         `json:"observed_at"`
	Summary    string            `json:"summary"`
}

func (s *Store) IssueForUpdateTx(ctx context.Context, tx *sql.Tx, id int64) (Issue, error) {
	i, err := scanIssue(tx.QueryRowContext(ctx, `SELECT `+issueColumns+` FROM issues WHERE id=$1 FOR UPDATE`, id))
	if err == sql.ErrNoRows {
		err = ErrNotFound
	}
	return i, err
}

func (s *Store) SetCheckingTx(ctx context.Context, tx *sql.Tx, i Issue, revision int64) (VerificationToken, error) {
	token := VerificationToken{IssueID: i.ID, Generation: i.Generation, LatestEventID: i.LatestEventID, IntentRevision: revision}
	if revision < 0 {
		return token, ErrInvalid
	}
	result, err := tx.ExecContext(ctx, `UPDATE issues SET state='checking',last_check_status='checking',last_check_at=now(),intent_revision=$4,updated_at=now() WHERE id=$1 AND generation=$2 AND latest_event_id=$3 AND resolved_at IS NULL`, i.ID, i.Generation, i.LatestEventID, revision)
	if err != nil {
		return token, err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return token, ErrConflict
	}
	return token, err
}

// ResolveVerifiedTx is for trusted verifier services. They must lock and reload
// resource intent in this same transaction and supply its current full hash.
// Browser endpoints never accept a receipt or an asserted healthy result.
func (s *Store) ResolveVerifiedTx(ctx context.Context, tx *sql.Tx, r VerificationReceipt, currentHash string, currentRevision int64) error {
	now := time.Now().UTC()
	if r.Token.IssueID <= 0 || r.Token.Generation <= 0 || r.Token.LatestEventID <= 0 || len(r.IntentHash) != 64 || r.ObservedAt.IsZero() || now.Sub(r.ObservedAt) > 5*time.Minute || r.ObservedAt.After(now.Add(time.Minute)) || !validText(r.Summary, 400) {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(r.IntentHash); err != nil {
		return ErrInvalid
	}
	switch r.Source {
	case "archive_checksum":
		if r.SourceID <= 0 || r.SizeBytes <= 0 || len(r.Checksum) != 64 {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(r.Checksum); err != nil {
			return ErrInvalid
		}
	case "local_tls", "local_hosting", "mail_runtime", "webmail_https":
	default:
		return ErrInvalid
	}
	if r.IntentHash != currentHash || r.Token.IntentRevision != currentRevision {
		return ErrConflict
	}
	i, err := s.IssueForUpdateTx(ctx, tx, r.Token.IssueID)
	if err != nil {
		return err
	}
	if i.Generation != r.Token.Generation || i.LatestEventID != r.Token.LatestEventID || i.IntentRevision != r.Token.IntentRevision || r.ObservedAt.Before(i.ObservedAt) {
		return ErrConflict
	}
	expectedSource := map[string][]string{"backup": {"archive_checksum"}, "tls": {"local_tls"}, "hosting": {"local_hosting"}, "mail": {"mail_runtime", "webmail_https"}}
	matched := false
	for _, source := range expectedSource[i.Kind] {
		if source == r.Source {
			matched = true
		}
	}
	if !matched {
		return ErrInvalid
	}
	if i.ResolvedAt != nil {
		return nil
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE issues SET state='resolved',resolved_at=now(),verification=$2::jsonb,last_check_status='verified',last_check_at=$3,updated_at=now() WHERE id=$1`, i.ID, string(data), r.ObservedAt); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE issue_id=$1 AND resolved_at IS NULL`, i.ID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO operation_events(event_key,resource_kind,resource_id,kind,issue_id,operation_id,summary) VALUES($1,$2,$3,'issue.resolved',$4,$5,$6) ON CONFLICT(event_key) DO NOTHING`, fmt.Sprintf("issue:%d:verified:%d:%d", i.ID, i.Generation, i.LatestEventID), i.Resource.Kind, i.Resource.ID, i.ID, nullableID(i.OperationID), r.Summary)
	return err
}

func (s *Store) VerificationFailedTx(ctx context.Context, tx *sql.Tx, token VerificationToken) error {
	result, err := tx.ExecContext(ctx, `UPDATE issues SET state=CASE WHEN acknowledged_at IS NULL THEN 'open' ELSE 'acknowledged' END,last_check_status='unknown',last_check_at=now(),updated_at=now() WHERE id=$1 AND generation=$2 AND latest_event_id=$3 AND intent_revision=$4 AND resolved_at IS NULL`, token.IssueID, token.Generation, token.LatestEventID, token.IntentRevision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrConflict
	}
	return err
}
