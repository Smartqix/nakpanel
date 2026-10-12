package provision

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

var ErrDatabaseExists = errors.New("database name is already in use")
var ErrDatabaseIdempotencyConflict = errors.New("database request key was used with different values")

type databaseCreateReplayRepository interface {
	LookupDatabaseCreate(context.Context, types.CreateDatabaseReq) (int64, error)
}

func (m *Manager) CreateDatabaseIdempotentFor(ctx context.Context, actor auth.SessionUser, ownerID int64, req types.CreateDatabaseReq) (int64, error) {
	if req.IdempotencyKey != "" {
		if err := m.canManageSubscription(ctx, actor, req.SubscriptionID); err != nil {
			return 0, err
		}
		repo, ok := m.databaseRepo.(databaseCreateReplayRepository)
		if !ok {
			return 0, errors.New("idempotent database creation is unavailable")
		}
		id, err := repo.LookupDatabaseCreate(ctx, req)
		if err != nil || id > 0 {
			return id, err
		}
	}
	id, err := m.CreateDatabaseFor(ctx, actor, ownerID, req)
	if err != nil && req.IdempotencyKey != "" {
		// A concurrent matching request may have consumed the last quota slot
		// after the first lookup and before the manager's quota check.
		if repo, ok := m.databaseRepo.(databaseCreateReplayRepository); ok {
			replayID, replayErr := repo.LookupDatabaseCreate(ctx, req)
			if replayErr != nil || replayID > 0 {
				return replayID, replayErr
			}
		}
	}
	return id, err
}

func lookupDatabaseCreateTx(ctx context.Context, tx *sql.Tx, req types.CreateDatabaseReq) (int64, error) {
	if req.IdempotencyKey == "" {
		return 0, nil
	}
	// Lock the key as well as its subscription: conflicting requests may select
	// different subscriptions, but must still converge on one durable result.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('nakpanel:database-create:' || $1 || ':' || $2,0))`, req.IdempotencyScope, req.IdempotencyKey); err != nil {
		return 0, err
	}
	var id int64
	var fingerprint string
	err := tx.QueryRowContext(ctx, `SELECT database_id,payload_hash FROM database_create_requests WHERE scope_hash=$1 AND request_key=$2`, req.IdempotencyScope, req.IdempotencyKey).Scan(&id, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if fingerprint != req.IdempotencyFingerprint {
		return 0, ErrDatabaseIdempotencyConflict
	}
	return id, nil
}

func (r *SQLDatabaseRepository) LookupDatabaseCreate(ctx context.Context, req types.CreateDatabaseReq) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = lockActiveSubscriptionLimits(ctx, tx, req.SubscriptionID); err != nil {
		return 0, err
	}
	return lookupDatabaseCreateTx(ctx, tx, req)
}

type databaseRetryRepository interface {
	RetryDatabase(context.Context, int64, int64) error
}

func (m *Manager) RetryDatabaseFor(ctx context.Context, actor auth.SessionUser, id, subscriptionID int64) error {
	if id <= 0 || subscriptionID <= 0 {
		return ErrForbidden
	}
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return err
	}
	repo, ok := m.databaseRepo.(databaseRetryRepository)
	if !ok {
		return errors.New("database retry is unavailable")
	}
	return repo.RetryDatabase(ctx, id, subscriptionID)
}

func (r *SQLDatabaseRepository) RetryDatabase(ctx context.Context, id, subscriptionID int64) error {
	if r.db == nil || r.river == nil || r.secrets == nil {
		return errors.New("database retry is unavailable")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	limits, err := lockActiveSubscriptionLimits(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	var status, engine, name, user string
	err = tx.QueryRowContext(ctx, `SELECT status,engine,db_name,db_user FROM databases WHERE id=$1 AND subscription_id=$2 FOR UPDATE`, id, subscriptionID).Scan(&status, &engine, &name, &user)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrForbidden
	}
	if err != nil {
		return err
	}
	if status != "failed" {
		return errors.New("database is not failed")
	}
	if err = enforceCountLimitTx(ctx, tx, "databases", subscriptionID, limits.MaxDatabases, limits.OverusePolicy); err != nil {
		return err
	}
	ref, err := databaseCredentialName(id)
	if err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM river_job WHERE kind='create_database' AND args->>'database_id'=$1::text AND state IN ('available','pending','retryable','running','scheduled'))`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		if _, err = r.river.InsertTx(ctx, tx, CreateDatabaseArgs{DatabaseID: id, Engine: types.DBEngine(engine), DBName: name, DBUser: user, CredentialRef: ref}, nil); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE databases SET status='pending',last_error='',updated_at=now() WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}
