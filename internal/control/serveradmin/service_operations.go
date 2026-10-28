package serveradmin

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ServiceOperation contains presentation-safe state, never agent errors, request
// payloads or credentials. Both the service row and Tasks identify the same task.
type ServiceOperation struct {
	OperationID string          `json:"operation_id"`
	TaskID      int64           `json:"task_id"`
	ServiceID   string          `json:"service_id"`
	Action      string          `json:"action"`
	Status      OperationStatus `json:"status"`
	Stage       string          `json:"stage,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	DurationMS  int64           `json:"duration_ms"`
	Error       string          `json:"error,omitempty"`
}

func (m *Manager) ServiceOperations(ctx context.Context) ([]ServiceOperation, error) {
	if m == nil || m.store == nil {
		return nil, errors.New("service operation store is unavailable")
	}
	rows, err := m.store.db.QueryContext(ctx, `SELECT operation_id,COALESCE(task_id,0),target_key,action,status,COALESCE(result->>'stage',''),created_at,updated_at,completed_at,COALESCE((result->>'duration_ms')::bigint,0) FROM server_operations WHERE category='services' AND target_type='server_service' AND (status IN ('pending','running','awaiting_confirmation') OR updated_at>=now()-interval '10 minutes') ORDER BY CASE WHEN status IN ('pending','running','awaiting_confirmation') THEN 0 ELSE 1 END,id DESC LIMIT 64`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ServiceOperation{}
	for rows.Next() {
		var item ServiceOperation
		var completed sql.NullTime
		if err = rows.Scan(&item.OperationID, &item.TaskID, &item.ServiceID, &item.Action, &item.Status, &item.Stage, &item.CreatedAt, &item.UpdatedAt, &completed, &item.DurationMS); err != nil {
			return nil, err
		}
		if completed.Valid {
			item.CompletedAt = &completed.Time
		}
		if item.Status == OperationFailed {
			item.Error = "The service action could not be verified. Review its task and current service state before trying again."
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
