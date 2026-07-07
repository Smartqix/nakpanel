package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
)

type SQLJobStore struct {
	db *sql.DB
}

func NewSQLJobStore(db *sql.DB) *SQLJobStore {
	return &SQLJobStore{db: db}
}

func (s *SQLJobStore) ListRecentJobs(ctx context.Context, limit int) ([]Job, error) {
	if s.db == nil {
		return nil, errors.New("job database is not configured")
	}
	if limit <= 0 {
		limit = DefaultRecentJobLimit
	}

	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, state::text, queue, attempt, max_attempts,
	    args,
	    COALESCE(
	        CASE
	            WHEN errors IS NULL OR array_length(errors, 1) IS NULL THEN ''
	            ELSE errors[array_length(errors, 1)]->>'error'
	        END,
	        ''
	    ) AS last_error,
	    created_at, scheduled_at, attempted_at, finalized_at
	FROM river_job
	WHERE kind IN ('create_site', 'create_database', 'issue_cert', 'create_backup', 'restore_backup', 'configure_webmail', 'configure_dns_zone', 'reconcile_system')
	ORDER BY created_at DESC, id DESC
	LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []Job
	for rows.Next() {
		var (
			job         Job
			args        []byte
			attemptedAt sql.NullTime
			finalizedAt sql.NullTime
		)
		if err := rows.Scan(
			&job.ID,
			&job.Kind,
			&job.State,
			&job.Queue,
			&job.Attempt,
			&job.MaxAttempts,
			&args,
			&job.LastError,
			&job.CreatedAt,
			&job.ScheduledAt,
			&attemptedAt,
			&finalizedAt,
		); err != nil {
			return nil, err
		}
		job.Target = extractJobTarget(job.Kind, args)
		job.AttemptedAt = NullableTime{Time: attemptedAt.Time, Valid: attemptedAt.Valid}
		job.FinalizedAt = NullableTime{Time: finalizedAt.Time, Valid: finalizedAt.Valid}
		jobs = append(jobs, job)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return jobs, nil
}

func extractJobTarget(kind string, args []byte) string {
	var values map[string]any
	if err := json.Unmarshal(args, &values); err != nil {
		return ""
	}

	switch kind {
	case "create_site", "issue_cert", "create_backup", "restore_backup", "configure_webmail", "configure_dns_zone":
		return stringValue(values["domain"])
	case "create_database":
		return stringValue(values["db_name"])
	case "reconcile_system":
		return "system"
	default:
		for _, key := range []string{"domain", "db_name", "site_id", "database_id"} {
			if value := stringValue(values[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return fmtNumber(typed)
	default:
		return ""
	}
}

func fmtNumber(value float64) string {
	if value == float64(int64(value)) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}
