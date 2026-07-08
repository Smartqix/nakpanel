package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type SQLSiteRepository struct {
	db      *sql.DB
	queries *store.Queries
	river   *river.Client[*sql.Tx]
}

func NewSQLSiteRepository(db *sql.DB, queries *store.Queries, riverClient *river.Client[*sql.Tx]) *SQLSiteRepository {
	return &SQLSiteRepository{
		db:      db,
		queries: queries,
		river:   riverClient,
	}
}

func (r *SQLSiteRepository) CreateSite(ctx context.Context, ownerID int64, req types.CreateSiteReq) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.queries == nil {
		return 0, errors.New("site queries are not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin site transaction: %w", err)
	}
	defer tx.Rollback()

	site, err := r.queries.WithTx(tx).UpsertSiteIntent(ctx, store.UpsertSiteIntentParams{
		OwnerUserID:    ownerID,
		Username:       req.Username,
		Domain:         req.Domain,
		PhpVersion:     req.PHPVersion,
		SubscriptionID: req.SubscriptionID,
	})
	if err != nil {
		return 0, fmt.Errorf("upsert site intent: %w", err)
	}

	_, err = r.river.InsertTx(ctx, tx, CreateSiteArgs{
		SiteID:     site.ID,
		Username:   site.Username,
		Domain:     site.Domain,
		PHPVersion: site.PhpVersion,
		Limits:     req.Limits,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue create_site job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit site transaction: %w", err)
	}
	return site.ID, nil
}

func (r *SQLSiteRepository) IssueCertificate(ctx context.Context, ownerID int64, domain string, issuer types.CertIssuer) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.queries == nil {
		return 0, errors.New("site queries are not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin certificate transaction: %w", err)
	}
	defer tx.Rollback()

	site, err := r.queries.WithTx(tx).GetSiteByDomain(ctx, domain)
	if err != nil {
		return 0, fmt.Errorf("get site by domain: %w", err)
	}
	if site.Status != "active" {
		return 0, fmt.Errorf("site must be active before issuing tls: status %q", site.Status)
	}
	if err := r.queries.WithTx(tx).MarkSiteTLSPending(ctx, store.MarkSiteTLSPendingParams{
		ID:        site.ID,
		TlsIssuer: string(issuer),
	}); err != nil {
		return 0, fmt.Errorf("mark site tls pending: %w", err)
	}

	_, err = r.river.InsertTx(ctx, tx, IssueCertArgs{
		SiteID:     site.ID,
		Username:   site.Username,
		Domain:     site.Domain,
		PHPVersion: site.PhpVersion,
		Issuer:     issuer,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue issue_cert job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit certificate transaction: %w", err)
	}
	return site.ID, nil
}

type SQLSiteStatusStore struct {
	queries *store.Queries
}

func NewSQLSiteStatusStore(queries *store.Queries) *SQLSiteStatusStore {
	return &SQLSiteStatusStore{queries: queries}
}

func (s *SQLSiteStatusStore) MarkSiteActive(ctx context.Context, id int64) error {
	if s.queries == nil {
		return errors.New("site queries are not configured")
	}
	return s.queries.MarkSiteActive(ctx, id)
}

func (s *SQLSiteStatusStore) MarkSiteFailed(ctx context.Context, id int64, message string) error {
	if s.queries == nil {
		return errors.New("site queries are not configured")
	}
	return s.queries.MarkSiteFailed(ctx, store.MarkSiteFailedParams{
		ID:        id,
		LastError: message,
	})
}

func (s *SQLSiteStatusStore) MarkSiteTLSActive(ctx context.Context, id int64, result types.IssueCertResult) error {
	if s.queries == nil {
		return errors.New("site queries are not configured")
	}
	return s.queries.MarkSiteTLSActive(ctx, store.MarkSiteTLSActiveParams{
		ID:           id,
		TlsIssuer:    string(result.Issuer),
		TlsCertPath:  result.CertPath,
		TlsKeyPath:   result.KeyPath,
		TlsExpiresAt: sql.NullTime{Time: result.ExpiresAt, Valid: !result.ExpiresAt.IsZero()},
	})
}

func (s *SQLSiteStatusStore) MarkSiteTLSFailed(ctx context.Context, id int64, message string) error {
	if s.queries == nil {
		return errors.New("site queries are not configured")
	}
	return s.queries.MarkSiteTLSFailed(ctx, store.MarkSiteTLSFailedParams{
		ID:           id,
		TlsLastError: message,
	})
}

type SQLDatabaseRepository struct {
	db      *sql.DB
	queries *store.Queries
	river   *river.Client[*sql.Tx]
}

func NewSQLDatabaseRepository(db *sql.DB, queries *store.Queries, riverClient *river.Client[*sql.Tx]) *SQLDatabaseRepository {
	return &SQLDatabaseRepository{
		db:      db,
		queries: queries,
		river:   riverClient,
	}
}

func (r *SQLDatabaseRepository) CreateDatabase(ctx context.Context, ownerID int64, req types.CreateDatabaseReq) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.queries == nil {
		return 0, errors.New("database queries are not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin database transaction: %w", err)
	}
	defer tx.Rollback()

	database, err := r.queries.WithTx(tx).UpsertDatabaseIntent(ctx, store.UpsertDatabaseIntentParams{
		OwnerUserID:    ownerID,
		Engine:         string(req.Engine),
		DbName:         req.DBName,
		DbUser:         req.DBUser,
		SubscriptionID: req.SubscriptionID,
	})
	if err != nil {
		return 0, fmt.Errorf("upsert database intent: %w", err)
	}

	_, err = r.river.InsertTx(ctx, tx, CreateDatabaseArgs{
		DatabaseID: database.ID,
		Engine:     types.DBEngine(database.Engine),
		DBName:     database.DbName,
		DBUser:     database.DbUser,
		Password:   req.Password,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue create_database job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit database transaction: %w", err)
	}
	return database.ID, nil
}

type SQLDatabaseStatusStore struct {
	db      *sql.DB
	queries *store.Queries
}

func NewSQLDatabaseStatusStore(db *sql.DB, queries *store.Queries) *SQLDatabaseStatusStore {
	return &SQLDatabaseStatusStore{db: db, queries: queries}
}

func (s *SQLDatabaseStatusStore) MarkDatabaseActive(ctx context.Context, id int64) error {
	if s.queries == nil {
		return errors.New("database queries are not configured")
	}
	return s.queries.MarkDatabaseActive(ctx, id)
}

func (s *SQLDatabaseStatusStore) MarkDatabaseFailed(ctx context.Context, id int64, message string) error {
	if s.queries == nil {
		return errors.New("database queries are not configured")
	}
	return s.queries.MarkDatabaseFailed(ctx, store.MarkDatabaseFailedParams{
		ID:        id,
		LastError: message,
	})
}

func (s *SQLDatabaseStatusStore) ScrubDatabaseJobPassword(ctx context.Context, jobID int64) error {
	if s.db == nil {
		return errors.New("database is not configured")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE river_job SET args = args - 'password' WHERE id = $1 AND kind = 'create_database'", jobID)
	return err
}
