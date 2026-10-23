package operations

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"time"
)

type Event struct {
	ID          int64     `json:"id"`
	Cursor      int64     `json:"cursor"`
	Kind        string    `json:"kind"`
	Resource    Resource  `json:"resource"`
	OperationID int64     `json:"operation_id,omitempty"`
	IssueID     int64     `json:"issue_id,omitempty"`
	Summary     string    `json:"summary"`
	CreatedAt   time.Time `json:"created_at"`
}
type Feed struct {
	Events []Event `json:"events"`
	Cursor int64   `json:"cursor"`
	More   bool    `json:"more"`
}

const eventColumns = `e.id,COALESCE(e.feed_cursor,0),e.kind,e.resource_kind,e.resource_id,COALESCE(e.operation_id,0),COALESCE(e.issue_id,0),e.summary,e.created_at`

func scanEvent(row scanner) (Event, error) {
	var e Event
	err := row.Scan(&e.ID, &e.Cursor, &e.Kind, &e.Resource.Kind, &e.Resource.ID, &e.OperationID, &e.IssueID, &e.Summary, &e.CreatedAt)
	return e, err
}
func (s *Store) Feed(ctx context.Context, actor auth.SessionUser, after int64, f Filter) (Feed, error) {
	result := Feed{Events: []Event{}, Cursor: after}
	if after < 0 {
		return result, ErrInvalid
	}
	if err := f.validate(); err != nil {
		return result, err
	}
	args := []any{actor.ID, string(actor.Role), after}
	where := resourcePredicate("e", 1, 2) + resourceFilter("e", f, &args) + ` AND (e.recipient_user_id IS NULL OR e.recipient_user_id=$1)`
	rows, err := s.db.QueryContext(ctx, `SELECT `+eventColumns+` FROM operation_events e WHERE e.feed_cursor>$3 AND `+where+` ORDER BY e.feed_cursor LIMIT `+bind(&args, f.limit()+1), args...)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return result, err
		}
		result.Events = append(result.Events, e)
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if len(result.Events) > f.limit() {
		result.More = true
		result.Events = result.Events[:f.limit()]
	}
	if len(result.Events) > 0 {
		result.Cursor = result.Events[len(result.Events)-1].Cursor
	}
	return result, nil
}
func listHistory(ctx context.Context, q queryer, actor auth.SessionUser, f Filter) ([]Event, error) {
	out := []Event{}
	args := []any{actor.ID, string(actor.Role)}
	where := resourcePredicate("e", 1, 2) + resourceFilter("e", f, &args) + ` AND (e.recipient_user_id IS NULL OR e.recipient_user_id=$1)`
	if f.Before > 0 {
		where += ` AND e.id<` + bind(&args, f.Before)
	}
	if f.Search != "" {
		where += ` AND e.summary ILIKE ` + bind(&args, "%"+f.Search+"%")
	}
	rows, err := q.QueryContext(ctx, `SELECT `+eventColumns+` FROM operation_events e WHERE `+where+` ORDER BY e.id DESC LIMIT `+bind(&args, f.limit()+1), args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
