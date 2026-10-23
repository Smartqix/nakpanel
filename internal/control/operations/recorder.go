package operations

import (
	"context"
	"database/sql"
)

// InstallRecorder attaches the current River schema after River migrations. The
// database trigger commits operational state with the actual source transition;
// a process crash between worker execution and UI publication cannot lose it.
func InstallRecorder(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `SELECT nakpanel_install_operations_recorder()`)
	return err
}
