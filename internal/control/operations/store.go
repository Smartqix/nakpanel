package operations

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
)

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const issueColumns = `id,resource_kind,resource_id,kind,condition,severity,title,summary,state,generation,occurrences,latest_event_id,intent_revision,COALESCE(operation_id,0),observed_at,acknowledged_at,resolved_at`

type scanner interface{ Scan(...any) error }

func scanIssue(row scanner, target ...*string) (Issue, error) {
	var i Issue
	args := []any{&i.ID, &i.Resource.Kind, &i.Resource.ID, &i.Kind, &i.Condition, &i.Severity, &i.Title, &i.Summary, &i.State, &i.Generation, &i.Occurrences, &i.LatestEventID, &i.IntentRevision, &i.OperationID, &i.ObservedAt, &i.AcknowledgedAt, &i.ResolvedAt}
	for _, p := range target {
		args = append(args, p)
	}
	err := row.Scan(args...)
	return i, err
}
func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *Store) ObserveIssue(ctx context.Context, o Observation) (Issue, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Issue{}, err
	}
	defer tx.Rollback()
	i, err := s.ObserveIssueTx(ctx, tx, o)
	if err != nil {
		return Issue{}, err
	}
	return i, tx.Commit()
}

// ObserveIssueTx commits the condition and its unique source event together.
// A duplicate event returns its incident without adding another occurrence.
func (s *Store) ObserveIssueTx(ctx context.Context, tx *sql.Tx, o Observation) (Issue, error) {
	if err := o.validate(); err != nil {
		return Issue{}, err
	}
	var eventID int64
	err := tx.QueryRowContext(ctx, `INSERT INTO operation_events(event_key,resource_kind,resource_id,kind,operation_id,summary) VALUES($1,$2,$3,'issue.observed',$4,$5) ON CONFLICT(event_key) DO NOTHING RETURNING id`, o.EventKey, o.Resource.Kind, o.Resource.ID, nullableID(o.OperationID), o.Summary).Scan(&eventID)
	if errors.Is(err, sql.ErrNoRows) {
		var kind ResourceKind
		var id int64
		var issueID sql.NullInt64
		if err = tx.QueryRowContext(ctx, `SELECT resource_kind,resource_id,issue_id FROM operation_events WHERE event_key=$1`, o.EventKey).Scan(&kind, &id, &issueID); err != nil {
			return Issue{}, err
		}
		if kind != o.Resource.Kind || id != o.Resource.ID || !issueID.Valid {
			return Issue{}, ErrConflict
		}
		i, err := scanIssue(tx.QueryRowContext(ctx, `SELECT `+issueColumns+` FROM issues WHERE id=$1`, issueID.Int64))
		if err == nil && (i.Kind != o.Kind || i.Condition != o.Condition) {
			return Issue{}, ErrConflict
		}
		return i, err
	}
	if err != nil {
		return Issue{}, err
	}
	i, err := scanIssue(tx.QueryRowContext(ctx, `INSERT INTO issues(resource_kind,resource_id,kind,condition,severity,title,summary,latest_event_id,intent_revision,operation_id,observed_at,previous_issue_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,(SELECT id FROM issues WHERE resource_kind=$1 AND resource_id=$2 AND kind=$3 AND condition=$4 AND resolved_at IS NOT NULL ORDER BY id DESC LIMIT 1))
 ON CONFLICT(resource_kind,resource_id,kind,condition) WHERE resolved_at IS NULL DO UPDATE SET severity=EXCLUDED.severity,title=EXCLUDED.title,summary=EXCLUDED.summary,generation=issues.generation+1,occurrences=issues.occurrences+1,latest_event_id=EXCLUDED.latest_event_id,intent_revision=EXCLUDED.intent_revision,operation_id=COALESCE(EXCLUDED.operation_id,issues.operation_id),observed_at=GREATEST(issues.observed_at,EXCLUDED.observed_at),updated_at=now(),state=CASE WHEN issues.acknowledged_at IS NULL THEN 'open' ELSE 'acknowledged' END
 RETURNING `+issueColumns, o.Resource.Kind, o.Resource.ID, o.Kind, o.Condition, o.Severity, o.Title, o.Summary, eventID, o.IntentRevision, nullableID(o.OperationID), o.ObservedAt))
	if err != nil {
		return Issue{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE operation_events SET issue_id=$2 WHERE id=$1`, eventID, i.ID)
	return i, err
}

func (s *Store) MarkNotificationRead(ctx context.Context, actor auth.SessionUser, id int64) error {
	if !actor.Role.Valid() || actor.ID <= 0 {
		return ErrNotFound
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO notification_receipts(notification_id,user_id) SELECT n.id,$1 FROM notifications n WHERE n.id=$3 AND `+NotificationVisibilitySQL("n", 1, 2)+` ON CONFLICT(notification_id,user_id) DO UPDATE SET read_at=notification_receipts.read_at`, actor.ID, string(actor.Role), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) AcknowledgeIssue(ctx context.Context, actor auth.SessionUser, id int64) error {
	if !actor.Role.Valid() || actor.ID <= 0 {
		return ErrNotFound
	}
	result, err := s.db.ExecContext(ctx, `UPDATE issues i SET acknowledged_by=COALESCE(acknowledged_by,$1),acknowledged_at=COALESCE(acknowledged_at,now()),state='acknowledged',updated_at=now() WHERE i.id=$3 AND resolved_at IS NULL AND `+resourcePredicate("i", 1, 2), actor.ID, string(actor.Role), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return err
}

const operationColumns = `id,kind,resource_kind,resource_id,title,trigger,state,stage,intent_revision,created_at,updated_at`

func scanOperation(row scanner, target ...*string) (Operation, error) {
	var o Operation
	args := []any{&o.ID, &o.Kind, &o.Resource.Kind, &o.Resource.ID, &o.Title, &o.Trigger, &o.State, &o.Stage, &o.IntentRevision, &o.CreatedAt, &o.UpdatedAt}
	for _, p := range target {
		args = append(args, p)
	}
	err := row.Scan(args...)
	return o, err
}

func (s *Store) CreateOperation(ctx context.Context, in NewOperation) (Operation, error) {
	if !in.Resource.Valid() || !validText(in.Key, 256) || !validText(in.Kind, 80) || !validText(in.Title, 200) || in.IntentRevision < 0 {
		return Operation{}, ErrInvalid
	}
	switch in.Trigger {
	case "manual", "scheduled", "reconciliation", "recovery", "system":
	default:
		return Operation{}, ErrInvalid
	}
	o, err := scanOperation(s.db.QueryRowContext(ctx, `INSERT INTO operations(operation_key,kind,resource_kind,resource_id,title,trigger,intent_revision) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(operation_key) DO UPDATE SET operation_key=EXCLUDED.operation_key RETURNING `+operationColumns, in.Key, in.Kind, in.Resource.Kind, in.Resource.ID, in.Title, in.Trigger, in.IntentRevision))
	if err == nil && (o.Resource != in.Resource || o.Kind != in.Kind || o.IntentRevision != in.IntentRevision) {
		return Operation{}, ErrConflict
	}
	return o, err
}

func (s *Store) StartAttempt(ctx context.Context, opID, riverID int64) (Attempt, error) {
	if opID <= 0 || riverID <= 0 {
		return Attempt{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Attempt{}, err
	}
	defer tx.Rollback()
	var id int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM operations WHERE id=$1 FOR UPDATE`, opID).Scan(&id); err != nil {
		return Attempt{}, err
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM operation_attempts WHERE operation_id=$1 AND finished_at IS NULL)`, opID).Scan(&active); err != nil {
		return Attempt{}, err
	}
	if active {
		return Attempt{}, ErrConflict
	}
	var a Attempt
	err = tx.QueryRowContext(ctx, `INSERT INTO operation_attempts(operation_id,number,river_job_id) SELECT $1,COALESCE(max(number),0)+1,$2 FROM operation_attempts WHERE operation_id=$1 RETURNING id,operation_id,number,river_job_id,state,started_at`, opID, riverID).Scan(&a.ID, &a.OperationID, &a.Number, &a.RiverJobID, &a.State, &a.StartedAt)
	if err != nil {
		return Attempt{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operations SET state='running',updated_at=now() WHERE id=$1`, opID); err != nil {
		return Attempt{}, err
	}
	return a, tx.Commit()
}

func (s *Store) FinishAttempt(ctx context.Context, id int64, state State, code string) error {
	if !state.Terminal() || len(code) > 80 {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Use operation -> attempt lock order consistently with StartAttempt.
	var opID int64
	if err = tx.QueryRowContext(ctx, `SELECT operation_id FROM operation_attempts WHERE id=$1`, id).Scan(&opID); err != nil {
		return err
	}
	var locked int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM operations WHERE id=$1 FOR UPDATE`, opID).Scan(&locked); err != nil {
		return err
	}
	var current State
	var priorCode string
	if err = tx.QueryRowContext(ctx, `SELECT state,error_code FROM operation_attempts WHERE id=$1 FOR UPDATE`, id).Scan(&current, &priorCode); err != nil {
		return err
	}
	if current.Terminal() {
		if current != state || priorCode != code {
			return ErrConflict
		}
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operation_attempts SET state=$2,error_code=$3,finished_at=now() WHERE id=$1`, id, state, code); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE operations SET state=$2,updated_at=now() WHERE id=$1`, opID, state); err != nil {
		return err
	}
	return tx.Commit()
}
