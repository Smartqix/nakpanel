package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type SQLSiteRepository struct {
	db      *sql.DB
	queries *store.Queries
	river   *river.Client[*sql.Tx]
}

var ErrCertificateOperationInProgress = errors.New("certificate operation is already in progress")

const activeCertificateJobSQL = `SELECT EXISTS (
SELECT 1
FROM river_job
WHERE kind IN ('issue_cert', 'install_custom_cert')
  AND state IN ('available', 'pending', 'retryable', 'running', 'scheduled')
  AND args->>'site_id' = $1::text
)`

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
	if err := guardSiteIntentTx(ctx, tx, req.SubscriptionID, req.Domain); err != nil {
		return 0, fmt.Errorf("guard site entitlement: %w", err)
	}

	site, err := r.queries.WithTx(tx).UpsertSiteIntent(ctx, store.UpsertSiteIntentParams{
		OwnerUserID:    ownerID,
		Domain:         req.Domain,
		PhpVersion:     req.PHPVersion,
		SubscriptionID: req.SubscriptionID,
	})
	if err != nil {
		return 0, fmt.Errorf("upsert site intent: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sites child
SET parent_site_id=$1
WHERE child.subscription_id=$2
  AND child.id<>$1
  AND child.domain LIKE '%.' || $3
  AND $1=(
      SELECT candidate.id
      FROM sites candidate
      WHERE candidate.subscription_id=child.subscription_id
        AND candidate.id<>child.id
        AND child.domain LIKE '%.' || candidate.domain
      ORDER BY length(candidate.domain) DESC,candidate.id
      LIMIT 1
  )`, site.ID, req.SubscriptionID, site.Domain); err != nil {
		return 0, fmt.Errorf("update DNS parent relationships: %w", err)
	}

	_, err = r.river.InsertTx(ctx, tx, CreateSiteArgs{
		SiteID:        site.ID,
		Username:      site.Username,
		Domain:        site.Domain,
		PHPVersion:    site.PhpVersion,
		SharedAccount: true,
		Limits:        req.Limits,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue create_site job: %w", err)
	}
	if _, err = controlquota.EnqueueSubscriptionConvergenceTx(ctx, tx, r.river, req.SubscriptionID); err != nil {
		return 0, fmt.Errorf("enqueue subscription convergence: %w", err)
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
	if err := guardCertificateOperationTx(ctx, tx, site.ID); err != nil {
		return 0, err
	}
	limits, err := controlquota.EffectiveSiteResourceLimitsTx(ctx, tx, site.ID)
	if err != nil {
		return 0, fmt.Errorf("resolve site policy for certificate: %w", err)
	}
	if err := r.queries.WithTx(tx).MarkSiteTLSPending(ctx, store.MarkSiteTLSPendingParams{
		ID:        site.ID,
		TlsIssuer: string(issuer),
	}); err != nil {
		return 0, fmt.Errorf("mark site tls pending: %w", err)
	}

	_, err = r.river.InsertTx(ctx, tx, IssueCertArgs{
		SiteID:        site.ID,
		Username:      site.Username,
		Domain:        site.Domain,
		PHPVersion:    site.PhpVersion,
		Issuer:        issuer,
		SharedAccount: controlquota.IsSharedSiteDocumentRoot(site.Username, site.Domain, site.DocumentRoot),
		Limits:        limits,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue issue_cert job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit certificate transaction: %w", err)
	}
	return site.ID, nil
}

func (r *SQLSiteRepository) InstallCustomCertificate(ctx context.Context, ownerID int64, domain, stagingPath string) (int64, error) {
	if r.db == nil || r.queries == nil || r.river == nil {
		return 0, errors.New("custom certificate repository is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	siteRow, err := r.queries.WithTx(tx).GetSiteByDomain(ctx, domain)
	if err != nil {
		return 0, fmt.Errorf("get site by domain: %w", err)
	}
	if siteRow.Status != "active" {
		return 0, fmt.Errorf("site must be active before installing TLS: status %q", siteRow.Status)
	}
	if err := guardCertificateOperationTx(ctx, tx, siteRow.ID); err != nil {
		return 0, err
	}
	limits, err := controlquota.EffectiveSiteResourceLimitsTx(ctx, tx, siteRow.ID)
	if err != nil {
		return 0, err
	}
	if err = r.queries.WithTx(tx).MarkSiteTLSPending(ctx, store.MarkSiteTLSPendingParams{ID: siteRow.ID, TlsIssuer: string(types.CertIssuerCustom)}); err != nil {
		return 0, err
	}
	inserted, err := r.river.InsertTx(ctx, tx, InstallCustomCertArgs{
		SiteID: siteRow.ID, StagingPath: stagingPath, Username: siteRow.Username, Domain: siteRow.Domain,
		PHPVersion: siteRow.PhpVersion, SharedAccount: controlquota.IsSharedSiteDocumentRoot(siteRow.Username, siteRow.Domain, siteRow.DocumentRoot), Limits: limits,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue install_custom_cert job: %w", err)
	}
	if inserted.UniqueSkippedAsDuplicate {
		return 0, errors.New("custom certificate installation is already in progress")
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return inserted.Job.ID, nil
}

func guardCertificateOperationTx(ctx context.Context, tx *sql.Tx, siteID int64) error {
	var lockedID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id = $1 FOR UPDATE`, siteID).Scan(&lockedID); err != nil {
		return fmt.Errorf("lock site certificate state: %w", err)
	}
	var active bool
	if err := tx.QueryRowContext(ctx, activeCertificateJobSQL, strconv.FormatInt(siteID, 10)).Scan(&active); err != nil {
		return fmt.Errorf("check active certificate jobs: %w", err)
	}
	if active {
		return ErrCertificateOperationInProgress
	}
	return nil
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
	secrets *serveradmin.Store
}

func NewSQLDatabaseRepository(db *sql.DB, queries *store.Queries, riverClient *river.Client[*sql.Tx], secretStores ...*serveradmin.Store) *SQLDatabaseRepository {
	repository := &SQLDatabaseRepository{
		db:      db,
		queries: queries,
		river:   riverClient,
	}
	if len(secretStores) > 0 {
		repository.secrets = secretStores[0]
	}
	return repository
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
	if r.secrets == nil {
		return 0, errors.New("database credential store is not configured")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin database transaction: %w", err)
	}
	defer tx.Rollback()
	if err := guardDatabaseIntentTx(ctx, tx, req.SubscriptionID, req.DBName); err != nil {
		return 0, fmt.Errorf("guard database entitlement: %w", err)
	}

	database, err := r.queries.WithTx(tx).UpsertDatabaseIntent(ctx, store.UpsertDatabaseIntentParams{
		OwnerUserID:    ownerID,
		Engine:         string(req.Engine),
		DbName:         req.DBName,
		DbUser:         req.DBUser,
		SubscriptionID: req.SubscriptionID,
		SiteID:         req.SiteID,
	})
	if err != nil {
		return 0, fmt.Errorf("upsert database intent: %w", err)
	}

	credentialName, err := databaseCredentialName(database.ID)
	if err != nil {
		return 0, err
	}
	if _, err := r.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
		Scope:       databaseCredentialScope,
		Name:        credentialName,
		Plaintext:   []byte(req.Password),
		Metadata:    []byte(fmt.Sprintf(`{"database_id":%d}`, database.ID)),
		ActorUserID: ownerID,
	}); err != nil {
		return 0, fmt.Errorf("store encrypted database credential: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, CreateDatabaseArgs{
		DatabaseID:    database.ID,
		Engine:        types.DBEngine(database.Engine),
		DBName:        database.DbName,
		DBUser:        database.DbUser,
		CredentialRef: credentialName,
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
	secrets *serveradmin.Store
}

func NewSQLDatabaseStatusStore(db *sql.DB, queries *store.Queries, secretStores ...*serveradmin.Store) *SQLDatabaseStatusStore {
	statusStore := &SQLDatabaseStatusStore{db: db, queries: queries}
	if len(secretStores) > 0 {
		statusStore.secrets = secretStores[0]
	}
	return statusStore
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

func (s *SQLDatabaseStatusStore) MigrateDatabaseJobCredential(ctx context.Context, jobID, databaseID int64, plaintext []byte) (string, error) {
	if s.db == nil {
		return "", errors.New("database is not configured")
	}
	if s.secrets == nil {
		return "", errors.New("database credential store is not configured")
	}
	credentialRef, err := databaseCredentialName(databaseID)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin legacy credential migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := s.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
		Scope:     databaseCredentialScope,
		Name:      credentialRef,
		Plaintext: plaintext,
		Metadata:  []byte(fmt.Sprintf(`{"database_id":%d}`, databaseID)),
	}); err != nil {
		return "", fmt.Errorf("encrypt legacy database credential: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
UPDATE river_job
SET args = jsonb_set(args - 'password', '{credential_ref}', to_jsonb($2::text), true)
WHERE id = $1 AND kind = 'create_database' AND args ? 'password'`, jobID, credentialRef)
	if err != nil {
		return "", err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected != 1 {
		return "", errors.New("database provisioning job was not found")
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit legacy credential migration: %w", err)
	}
	return credentialRef, nil
}
