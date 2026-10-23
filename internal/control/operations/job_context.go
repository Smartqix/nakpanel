package operations

import (
	"context"
	"database/sql"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

type operationJobKey struct{}

// JobContextMiddleware correlates existing domain failure notices with their
// logical operation. Independent security/health notices keep their own identity.
type JobContextMiddleware struct{ river.WorkerMiddlewareDefaults }

func (*JobContextMiddleware) Work(ctx context.Context, job *rivertype.JobRow, inner func(context.Context) error) error {
	return inner(context.WithValue(ctx, operationJobKey{}, job.ID))
}

const workerFailureNoticeKinds = `('php_deployment_failed','wordpress_operation_failed','scheduled_task_failed','maintenance_failed','server_backup_failed')`

func correlateNotificationTx(ctx context.Context, tx *sql.Tx, id int64) error {
	jobID, _ := ctx.Value(operationJobKey{}).(int64)
	if jobID <= 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE notifications n SET operation_id=o.id FROM operations o JOIN operation_attempts a ON a.operation_id=o.id WHERE n.id=$1 AND a.river_job_id=$2 AND a.finished_at IS NULL AND n.kind IN `+workerFailureNoticeKinds, id, jobID)
	return err
}
