package operations

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type ConditionSample struct {
	Resource                   Resource
	Kind, Condition, Signature string
	Unhealthy                  bool
	Severity, Title, Summary   string
	IntentRevision             int64
	ObservedAt                 time.Time
}

// ObserveConditionTx records condition edges, not another failure on each poll.
// Metadata returning to normal requests verification; it cannot resolve an issue.
func (s *Store) ObserveConditionTx(ctx context.Context, tx *sql.Tx, c ConditionSample) error {
	if !c.Resource.Valid() || !validText(c.Kind, 80) || !validText(c.Condition, 160) || !validText(c.Signature, 200) || c.ObservedAt.IsZero() {
		return ErrInvalid
	}
	var generation int64
	err := tx.QueryRowContext(ctx, `INSERT INTO operation_condition_observations(resource_kind,resource_id,kind,condition,signature,unhealthy,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7)
 ON CONFLICT(resource_kind,resource_id,kind,condition) DO UPDATE SET generation=operation_condition_observations.generation+CASE WHEN operation_condition_observations.signature<>EXCLUDED.signature OR operation_condition_observations.unhealthy<>EXCLUDED.unhealthy THEN 1 ELSE 0 END,signature=EXCLUDED.signature,unhealthy=EXCLUDED.unhealthy,observed_at=EXCLUDED.observed_at RETURNING generation`, c.Resource.Kind, c.Resource.ID, c.Kind, c.Condition, c.Signature, c.Unhealthy, c.ObservedAt).Scan(&generation)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("condition:%s:%d:%s:%s:%d:%s", c.Resource.Kind, c.Resource.ID, c.Kind, c.Condition, generation, c.Signature)
	if c.Unhealthy {
		i, err := s.ObserveIssueTx(ctx, tx, Observation{EventKey: key, Resource: c.Resource, Kind: c.Kind, Condition: c.Condition, Severity: c.Severity, Title: c.Title, Summary: c.Summary, IntentRevision: c.IntentRevision, ObservedAt: c.ObservedAt})
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE issues SET observed_at=GREATEST(observed_at,$2) WHERE id=$1`, i.ID, c.ObservedAt)
		return err
	}
	var issueID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM issues WHERE resource_kind=$1 AND resource_id=$2 AND kind=$3 AND condition=$4 AND resolved_at IS NULL FOR UPDATE`, c.Resource.Kind, c.Resource.ID, c.Kind, c.Condition).Scan(&issueID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	var eventID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO operation_events(event_key,resource_kind,resource_id,kind,issue_id,summary) VALUES($1,$2,$3,'condition.changed',$4,'Resource state changed; recovery verification is required') ON CONFLICT(event_key) DO NOTHING RETURNING id`, key, c.Resource.Kind, c.Resource.ID, issueID).Scan(&eventID)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE issues SET generation=generation+1,latest_event_id=$2,intent_revision=$3,last_check_status='unknown',updated_at=now() WHERE id=$1`, issueID, eventID, c.IntentRevision)
	return err
}
