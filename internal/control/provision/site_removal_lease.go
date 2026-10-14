package provision

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"time"
)

func acquireServerSnapshotGate(ctx context.Context, connection *sql.Conn, shared bool) error {
	query := `SELECT pg_advisory_lock(hashtextextended('nakpanel:server-snapshot',0))`
	if shared {
		query = `SELECT pg_advisory_lock_shared(hashtextextended('nakpanel:server-snapshot',0))`
	}
	_, err := connection.ExecContext(ctx, query)
	if err != nil {
		discardRemovalLeaseConnection(connection)
	}
	return err
}
func releaseServerSnapshotGate(connection *sql.Conn, shared bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	query := `SELECT pg_advisory_unlock(hashtextextended('nakpanel:server-snapshot',0))`
	if shared {
		query = `SELECT pg_advisory_unlock_shared(hashtextextended('nakpanel:server-snapshot',0))`
	}
	if _, err := connection.ExecContext(ctx, query); err != nil {
		discardRemovalLeaseConnection(connection)
	}
}

// Never return a possibly still-locked session to the connection pool.
func discardRemovalLeaseConnection(connection *sql.Conn) {
	_ = connection.Raw(func(any) error { return driver.ErrBadConn })
}

func serverSnapshotSensitiveJob(kind string) bool {
	switch kind {
	case "server_backup", "converge_subscription", "reconcile_system", "migrate_subscription_account", "teardown_billing_account":
		return true
	}
	return removalJobClassification[kind] == "target"
}
