package phpapp

import (
	"context"
	"database/sql"
	"errors"
)

// phpApplicationFence serializes cross-process agent side effects with every
// browser, CLI, scheduler, and teardown mutation that can advance application
// intent. The subscription key is acquired first to preserve the repository's
// global tenant-lock ordering.
type phpApplicationFence struct {
	conn *sql.Conn
	tx   *sql.Tx
}

func (s *SQLStore) acquirePHPApplicationFence(ctx context.Context, applicationID int64) (*phpApplicationFence, bool, error) {
	if s == nil || s.db == nil || applicationID <= 0 {
		return nil, false, ErrNotFound
	}
	var subscriptionID int64
	err := s.db.QueryRowContext(ctx, `SELECT subscription_id FROM php_applications WHERE id=$1`, applicationID).Scan(&subscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, false, err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		_ = conn.Close()
		return nil, false, err
	}
	fence := &phpApplicationFence{conn: conn, tx: tx}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nakpanel:subscription:' || $1::bigint::text,0))`, subscriptionID); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		return nil, false, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nakpanel:php-application:' || $1::bigint::text,0))`, applicationID); err != nil {
		_ = tx.Rollback()
		_ = conn.Close()
		return nil, false, err
	}
	return fence, false, nil
}

func (f *phpApplicationFence) Release() error {
	if f == nil {
		return nil
	}
	var rollbackErr, closeErr error
	if f.tx != nil {
		rollbackErr = f.tx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
	}
	if f.conn != nil {
		closeErr = f.conn.Close()
	}
	f.tx = nil
	f.conn = nil
	return errors.Join(rollbackErr, closeErr)
}
