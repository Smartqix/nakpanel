package serveradmin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrRevisionConflict    = errors.New("server setting revision conflict")
	ErrSecretUnavailable   = errors.New("service secret storage is unavailable")
	ErrOperationInProgress = errors.New("a matching server operation is already active")

	identifierPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	actionPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,95}$`)
	secretNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	operationIDPattern = regexp.MustCompile(`^op_[A-Za-z0-9_-]{20,64}$`)
)

const (
	CategoryGeneral               = "general"
	CategoryWebPHP                = "web_php"
	CategorySecurity              = "security"
	CategoryToolsResources        = "tools_resources"
	CategoryServerManagement      = "server_management"
	CategoryMail                  = "mail"
	CategoryApplicationsDatabases = "applications_databases"
	CategoryMonitoringLogs        = "monitoring_logs"
	CategoryPanelAdministration   = "panel_administration"
)

type ConvergenceStatus string

const (
	ConvergencePending  ConvergenceStatus = "pending"
	ConvergenceApplying ConvergenceStatus = "applying"
	ConvergenceApplied  ConvergenceStatus = "applied"
	ConvergenceFailed   ConvergenceStatus = "failed"
)

type HealthStatus string

const (
	HealthHealthy     HealthStatus = "healthy"
	HealthWarning     HealthStatus = "warning"
	HealthCritical    HealthStatus = "critical"
	HealthPending     HealthStatus = "pending"
	HealthUnavailable HealthStatus = "unavailable"
	HealthUnknown     HealthStatus = "unknown"
)

type OperationStatus string

const (
	OperationPending              OperationStatus = "pending"
	OperationRunning              OperationStatus = "running"
	OperationAwaitingConfirmation OperationStatus = "awaiting_confirmation"
	OperationSucceeded            OperationStatus = "succeeded"
	OperationFailed               OperationStatus = "failed"
	OperationRolledBack           OperationStatus = "rolled_back"
	OperationCancelled            OperationStatus = "cancelled"
)

type Setting struct {
	Category           string
	Desired            json.RawMessage
	Applied            json.RawMessage
	DesiredRevision    int64
	AppliedRevision    int64
	ConvergenceStatus  ConvergenceStatus
	LastGoodConfigHash []byte
	LastError          string
	UpdatedByUserID    sql.NullInt64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type InventoryItem struct {
	ID           int64
	Kind         string
	ResourceKey  string
	HealthStatus HealthStatus
	Payload      json.RawMessage
	LastError    string
	CheckedAt    time.Time
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (i InventoryItem) Fresh(now time.Time) bool {
	return now.Before(i.ExpiresAt)
}

type Operation struct {
	ID                   int64
	OperationID          string
	Category             string
	Action               string
	TargetType           string
	TargetKey            string
	Request              json.RawMessage
	Result               json.RawMessage
	Status               OperationStatus
	DesiredRevision      sql.NullInt64
	IdempotencyKey       sql.NullString
	ConfirmationDeadline sql.NullTime
	ConfirmedAt          sql.NullTime
	LastError            string
	ActorUserID          int64
	StartedAt            sql.NullTime
	CompletedAt          sql.NullTime
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type SecretReference struct {
	ID              int64
	SecretID        string
	Scope           string
	Name            string
	KeyVersion      int
	Metadata        json.RawMessage
	UpdatedByUserID sql.NullInt64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type SaveDesiredSettingParams struct {
	Category         string
	ExpectedRevision int64
	Desired          json.RawMessage
	ActorUserID      int64
}

type UpsertInventoryParams struct {
	Kind         string
	ResourceKey  string
	HealthStatus HealthStatus
	Payload      json.RawMessage
	LastError    string
	CheckedAt    time.Time
	ExpiresAt    time.Time
}

type CreateOperationParams struct {
	OperationID     string
	Category        string
	Action          string
	TargetType      string
	TargetKey       string
	Request         json.RawMessage
	DesiredRevision int64
	IdempotencyKey  string
	ActorUserID     int64
}

type UpdateOperationParams struct {
	OperationID          string
	Status               OperationStatus
	Result               json.RawMessage
	LastError            string
	StartedAt            sql.NullTime
	CompletedAt          sql.NullTime
	ConfirmationDeadline sql.NullTime
	ConfirmedAt          sql.NullTime
}

type PutSecretParams struct {
	Scope       string
	Name        string
	Plaintext   []byte
	Metadata    json.RawMessage
	ActorUserID int64
}

type Store struct {
	db      *sql.DB
	keyring *Keyring
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func NewStore(db *sql.DB, keyring *Keyring) *Store {
	return &Store{db: db, keyring: keyring}
}

func NewOperationID() (string, error) {
	return randomPublicID("op_", 24)
}

func (s *Store) GetSetting(ctx context.Context, category string) (Setting, error) {
	if !identifierPattern.MatchString(category) {
		return Setting{}, errors.New("invalid server setting category")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT category,desired,applied,desired_revision,applied_revision,
       convergence_status,last_good_config_hash,last_error,
       updated_by_user_id,created_at,updated_at
FROM server_settings WHERE category=$1`, category)
	return scanSetting(row)
}

func (s *Store) ListSettings(ctx context.Context) ([]Setting, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT category,desired,applied,desired_revision,applied_revision,
       convergence_status,last_good_config_hash,last_error,
       updated_by_user_id,created_at,updated_at
FROM server_settings ORDER BY category`)
	if err != nil {
		return nil, fmt.Errorf("list server settings: %w", err)
	}
	defer rows.Close()

	var items []Setting
	for rows.Next() {
		item, err := scanSetting(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list server settings rows: %w", err)
	}
	return items, nil
}

func (s *Store) SaveDesiredSetting(ctx context.Context, params SaveDesiredSettingParams) (Setting, error) {
	if !identifierPattern.MatchString(params.Category) {
		return Setting{}, errors.New("invalid server setting category")
	}
	if params.ExpectedRevision < 0 {
		return Setting{}, errors.New("expected revision must not be negative")
	}
	if params.ActorUserID <= 0 {
		return Setting{}, errors.New("server setting actor is required")
	}
	desired, err := normalizedJSONObject(params.Desired)
	if err != nil {
		return Setting{}, fmt.Errorf("validate desired server setting: %w", err)
	}

	row := s.db.QueryRowContext(ctx, `
INSERT INTO server_settings (
    category,desired,desired_revision,convergence_status,updated_by_user_id
)
SELECT $1,$2::jsonb,1,'pending',$4
WHERE $3::bigint = 0
ON CONFLICT (category) DO UPDATE
SET desired=EXCLUDED.desired,
    desired_revision=server_settings.desired_revision+1,
    convergence_status='pending',
    last_error='',
    updated_by_user_id=EXCLUDED.updated_by_user_id,
    updated_at=now()
WHERE server_settings.desired_revision=$3
RETURNING category,desired,applied,desired_revision,applied_revision,
          convergence_status,last_good_config_hash,last_error,
          updated_by_user_id,created_at,updated_at`,
		params.Category, desired, params.ExpectedRevision, params.ActorUserID)
	setting, err := scanSetting(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Setting{}, ErrRevisionConflict
	}
	return setting, err
}

func (s *Store) MarkSettingApplying(ctx context.Context, category string, revision int64) (Setting, error) {
	return s.updateSettingState(ctx, category, revision, `
UPDATE server_settings
SET convergence_status='applying',last_error='',updated_at=now()
WHERE category=$1 AND desired_revision=$2
RETURNING category,desired,applied,desired_revision,applied_revision,
          convergence_status,last_good_config_hash,last_error,
          updated_by_user_id,created_at,updated_at`, nil)
}

func (s *Store) MarkSettingApplied(ctx context.Context, category string, revision int64, applied json.RawMessage, lastGoodHash []byte) (Setting, error) {
	applied, err := normalizedJSONObject(applied)
	if err != nil {
		return Setting{}, fmt.Errorf("validate applied server setting: %w", err)
	}
	if len(lastGoodHash) != 0 && len(lastGoodHash) != 32 {
		return Setting{}, errors.New("last-known-good hash must contain exactly 32 bytes")
	}
	return s.updateSettingState(ctx, category, revision, `
UPDATE server_settings
SET applied=$3::jsonb,applied_revision=$2,convergence_status='applied',
    last_good_config_hash=NULLIF($4::bytea,'\x'::bytea),last_error='',updated_at=now()
WHERE category=$1 AND desired_revision=$2
RETURNING category,desired,applied,desired_revision,applied_revision,
          convergence_status,last_good_config_hash,last_error,
          updated_by_user_id,created_at,updated_at`, []any{applied, lastGoodHash})
}

func (s *Store) MarkSettingFailed(ctx context.Context, category string, revision int64, failure string) (Setting, error) {
	return s.updateSettingState(ctx, category, revision, `
UPDATE server_settings
SET convergence_status='failed',last_error=$3,updated_at=now()
WHERE category=$1 AND desired_revision=$2
RETURNING category,desired,applied,desired_revision,applied_revision,
          convergence_status,last_good_config_hash,last_error,
          updated_by_user_id,created_at,updated_at`, []any{boundedError(failure)})
}

func (s *Store) updateSettingState(ctx context.Context, category string, revision int64, query string, extra []any) (Setting, error) {
	if !identifierPattern.MatchString(category) || revision < 1 {
		return Setting{}, errors.New("invalid server setting revision target")
	}
	args := []any{category, revision}
	args = append(args, extra...)
	setting, err := scanSetting(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Setting{}, ErrRevisionConflict
	}
	return setting, err
}

func (s *Store) UpsertInventory(ctx context.Context, params UpsertInventoryParams) (InventoryItem, error) {
	if !identifierPattern.MatchString(params.Kind) {
		return InventoryItem{}, errors.New("invalid inventory kind")
	}
	if strings.TrimSpace(params.ResourceKey) == "" || len(params.ResourceKey) > 255 {
		return InventoryItem{}, errors.New("invalid inventory resource key")
	}
	if !params.HealthStatus.valid() {
		return InventoryItem{}, errors.New("invalid inventory health status")
	}
	payload, err := normalizedJSONObject(params.Payload)
	if err != nil {
		return InventoryItem{}, fmt.Errorf("validate inventory payload: %w", err)
	}
	if params.CheckedAt.IsZero() || params.ExpiresAt.Before(params.CheckedAt) {
		return InventoryItem{}, errors.New("invalid inventory freshness window")
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO server_inventory (
    kind,resource_key,health_status,payload,last_error,checked_at,expires_at
) VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7)
ON CONFLICT (kind,resource_key) DO UPDATE
SET health_status=EXCLUDED.health_status,payload=EXCLUDED.payload,
    last_error=EXCLUDED.last_error,checked_at=EXCLUDED.checked_at,
    expires_at=EXCLUDED.expires_at,updated_at=now()
RETURNING id,kind,resource_key,health_status,payload,last_error,
          checked_at,expires_at,created_at,updated_at`,
		params.Kind, params.ResourceKey, params.HealthStatus, payload,
		boundedError(params.LastError), params.CheckedAt, params.ExpiresAt)
	return scanInventory(row)
}

func (s *Store) ListInventory(ctx context.Context, kind string) ([]InventoryItem, error) {
	if kind != "" && !identifierPattern.MatchString(kind) {
		return nil, errors.New("invalid inventory kind")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id,kind,resource_key,health_status,payload,last_error,
       checked_at,expires_at,created_at,updated_at
FROM server_inventory
WHERE $1='' OR kind=$1
ORDER BY kind,resource_key`, kind)
	if err != nil {
		return nil, fmt.Errorf("list server inventory: %w", err)
	}
	defer rows.Close()

	var items []InventoryItem
	for rows.Next() {
		item, err := scanInventory(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list server inventory rows: %w", err)
	}
	return items, nil
}

func (s *Store) CreateOperation(ctx context.Context, params CreateOperationParams) (Operation, error) {
	return s.createOperation(ctx, s.db, params)
}

func (s *Store) CreateOperationTx(ctx context.Context, tx *sql.Tx, params CreateOperationParams) (Operation, error) {
	if tx == nil {
		return Operation{}, errors.New("server operation transaction is required")
	}
	return s.createOperation(ctx, tx, params)
}

func (s *Store) createOperation(ctx context.Context, db queryRower, params CreateOperationParams) (Operation, error) {
	if !operationIDPattern.MatchString(params.OperationID) ||
		!identifierPattern.MatchString(params.Category) ||
		!actionPattern.MatchString(params.Action) ||
		!identifierPattern.MatchString(params.TargetType) {
		return Operation{}, errors.New("invalid server operation identity")
	}
	if strings.TrimSpace(params.TargetKey) == "" || len(params.TargetKey) > 255 {
		return Operation{}, errors.New("invalid server operation target")
	}
	if params.ActorUserID <= 0 {
		return Operation{}, errors.New("server operation actor is required")
	}
	request, err := normalizedJSONObject(params.Request)
	if err != nil {
		return Operation{}, fmt.Errorf("validate server operation request: %w", err)
	}
	if params.DesiredRevision < 0 {
		return Operation{}, errors.New("desired revision must not be negative")
	}
	if len(params.IdempotencyKey) > 128 {
		return Operation{}, errors.New("idempotency key is too long")
	}

	row := db.QueryRowContext(ctx, `
INSERT INTO server_operations (
    operation_id,category,action,target_type,target_key,request,
    desired_revision,idempotency_key,actor_user_id
) VALUES (
    $1,$2,$3,$4,$5,$6::jsonb,NULLIF($7,0),NULLIF($8,''),$9
)
RETURNING id,operation_id,category,action,target_type,target_key,request,result,
          status,desired_revision,idempotency_key,confirmation_deadline,
          confirmed_at,last_error,actor_user_id,started_at,completed_at,
          created_at,updated_at`,
		params.OperationID, params.Category, params.Action, params.TargetType,
		params.TargetKey, request, params.DesiredRevision,
		params.IdempotencyKey, params.ActorUserID)
	operation, err := scanOperation(row)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Operation{}, ErrOperationInProgress
	}
	return operation, err
}

func (s *Store) GetInventory(ctx context.Context, kind, resourceKey string) (InventoryItem, error) {
	if !identifierPattern.MatchString(kind) {
		return InventoryItem{}, errors.New("invalid inventory kind")
	}
	if strings.TrimSpace(resourceKey) == "" || len(resourceKey) > 255 {
		return InventoryItem{}, errors.New("invalid inventory resource key")
	}
	return scanInventory(s.db.QueryRowContext(ctx, `
SELECT id,kind,resource_key,health_status,payload,last_error,
       checked_at,expires_at,created_at,updated_at
FROM server_inventory
WHERE kind=$1 AND resource_key=$2`, kind, resourceKey))
}

func (s *Store) GetOperation(ctx context.Context, operationID string) (Operation, error) {
	if !operationIDPattern.MatchString(operationID) {
		return Operation{}, errors.New("invalid operation ID")
	}
	return scanOperation(s.db.QueryRowContext(ctx, `
SELECT id,operation_id,category,action,target_type,target_key,request,result,
       status,desired_revision,idempotency_key,confirmation_deadline,
       confirmed_at,last_error,actor_user_id,started_at,completed_at,
       created_at,updated_at
FROM server_operations WHERE operation_id=$1`, operationID))
}

func (s *Store) UpdateOperation(ctx context.Context, params UpdateOperationParams) (Operation, error) {
	if !operationIDPattern.MatchString(params.OperationID) || !params.Status.valid() {
		return Operation{}, errors.New("invalid server operation update")
	}
	result, err := normalizedJSONObject(params.Result)
	if err != nil {
		return Operation{}, fmt.Errorf("validate server operation result: %w", err)
	}
	if params.ConfirmedAt.Valid && !params.ConfirmationDeadline.Valid {
		return Operation{}, errors.New("confirmed operation requires a confirmation deadline")
	}
	return scanOperation(s.db.QueryRowContext(ctx, `
UPDATE server_operations
	SET status=$2,result=$3::jsonb,last_error=$4,started_at=COALESCE(started_at,$5),completed_at=$6,
	    confirmation_deadline=$7,confirmed_at=$8,updated_at=now()
	WHERE operation_id=$1
	  AND status NOT IN ('succeeded','failed','rolled_back','cancelled')
RETURNING id,operation_id,category,action,target_type,target_key,request,result,
          status,desired_revision,idempotency_key,confirmation_deadline,
          confirmed_at,last_error,actor_user_id,started_at,completed_at,
          created_at,updated_at`,
		params.OperationID, params.Status, result, boundedError(params.LastError),
		params.StartedAt, params.CompletedAt, params.ConfirmationDeadline, params.ConfirmedAt))
}

type FinishOperationParams struct {
	UpdateOperationParams
	AuditAction string
	AuditTarget string
	AuditData   json.RawMessage
}

// FinishOperation commits the terminal operation state and its audit event
// together so operators never see a successful mutation without its outcome.
func (s *Store) FinishOperation(ctx context.Context, params FinishOperationParams) (Operation, error) {
	if !operationIDPattern.MatchString(params.OperationID) ||
		(params.Status != OperationSucceeded && params.Status != OperationFailed &&
			params.Status != OperationRolledBack && params.Status != OperationCancelled) {
		return Operation{}, errors.New("finished operation requires a terminal status")
	}
	if params.ConfirmedAt.Valid && !params.ConfirmationDeadline.Valid {
		return Operation{}, errors.New("confirmed operation requires a confirmation deadline")
	}
	if !actionPattern.MatchString(params.AuditAction) ||
		!identifierPattern.MatchString(params.AuditTarget) {
		return Operation{}, errors.New("invalid operation audit identity")
	}
	auditData, err := normalizedJSONObject(params.AuditData)
	if err != nil {
		return Operation{}, fmt.Errorf("validate operation audit metadata: %w", err)
	}
	result, err := normalizedJSONObject(params.Result)
	if err != nil {
		return Operation{}, fmt.Errorf("validate server operation result: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, fmt.Errorf("begin operation completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	operation, err := scanOperation(tx.QueryRowContext(ctx, `
UPDATE server_operations
	SET status=$2,result=$3::jsonb,last_error=$4,started_at=COALESCE(started_at,$5),completed_at=$6,
	    confirmation_deadline=$7,confirmed_at=$8,updated_at=now()
	WHERE operation_id=$1
	  AND status NOT IN ('succeeded','failed','rolled_back','cancelled')
RETURNING id,operation_id,category,action,target_type,target_key,request,result,
          status,desired_revision,idempotency_key,confirmation_deadline,
          confirmed_at,last_error,actor_user_id,started_at,completed_at,
          created_at,updated_at`,
		params.OperationID, params.Status, result, boundedError(params.LastError),
		params.StartedAt, params.CompletedAt, params.ConfirmationDeadline, params.ConfirmedAt))
	if err != nil {
		return Operation{}, fmt.Errorf("finish server operation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_events(
    actor_user_id,action,target_type,target_id,metadata
) VALUES ($1,$2,$3,NULL,$4::jsonb)`,
		operation.ActorUserID, params.AuditAction, params.AuditTarget, auditData); err != nil {
		return Operation{}, fmt.Errorf("record server operation outcome: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit server operation outcome: %w", err)
	}
	return operation, nil
}

func (s *Store) RecordOperationRequestTx(ctx context.Context, tx *sql.Tx, actorUserID int64, action, target string, metadata json.RawMessage) error {
	if tx == nil {
		return errors.New("operation audit transaction is required")
	}
	if actorUserID <= 0 || !actionPattern.MatchString(action) || !identifierPattern.MatchString(target) {
		return errors.New("invalid operation request audit")
	}
	data, err := normalizedJSONObject(metadata)
	if err != nil {
		return fmt.Errorf("validate operation request audit metadata: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events(actor_user_id,action,target_type,target_id,metadata)
VALUES ($1,$2,$3,NULL,$4::jsonb)`, actorUserID, action, target, data)
	return err
}

func (s *Store) PutSecret(ctx context.Context, params PutSecretParams) (SecretReference, error) {
	return s.putSecret(ctx, s.db, params)
}

// PutSecretTx stores a secret in the caller's transaction so the encrypted
// value can commit atomically with the configuration that references it.
func (s *Store) PutSecretTx(ctx context.Context, tx *sql.Tx, params PutSecretParams) (SecretReference, error) {
	if tx == nil {
		return SecretReference{}, errors.New("service secret transaction is required")
	}
	return s.putSecret(ctx, tx, params)
}

func (s *Store) putSecret(ctx context.Context, queryer secretQueryer, params PutSecretParams) (SecretReference, error) {
	if s.keyring == nil {
		return SecretReference{}, ErrSecretUnavailable
	}
	if !identifierPattern.MatchString(params.Scope) || !secretNamePattern.MatchString(params.Name) {
		return SecretReference{}, errors.New("invalid service secret identity")
	}
	if params.ActorUserID < 0 {
		return SecretReference{}, errors.New("invalid service secret actor")
	}
	metadata, err := normalizedJSONObject(params.Metadata)
	if err != nil {
		return SecretReference{}, fmt.Errorf("validate service secret metadata: %w", err)
	}
	envelope, err := s.keyring.Seal(params.Plaintext, secretAAD(params.Scope, params.Name))
	if err != nil {
		return SecretReference{}, err
	}
	secretID, err := randomPublicID("sec_", 24)
	if err != nil {
		return SecretReference{}, err
	}
	row := queryer.QueryRowContext(ctx, `
INSERT INTO service_secrets (
    secret_id,scope,name,algorithm,key_version,wrapped_key_nonce,
    wrapped_data_key,value_nonce,ciphertext,metadata,updated_by_user_id
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,NULLIF($11,0)
)
ON CONFLICT (scope,name) DO UPDATE
SET algorithm=EXCLUDED.algorithm,key_version=EXCLUDED.key_version,
    wrapped_key_nonce=EXCLUDED.wrapped_key_nonce,
    wrapped_data_key=EXCLUDED.wrapped_data_key,value_nonce=EXCLUDED.value_nonce,
    ciphertext=EXCLUDED.ciphertext,metadata=EXCLUDED.metadata,
    updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=now()
RETURNING id,secret_id,scope,name,key_version,metadata,
          updated_by_user_id,created_at,updated_at`,
		secretID, params.Scope, params.Name, envelope.Algorithm,
		envelope.KeyVersion, envelope.WrappedKeyNonce, envelope.WrappedDataKey,
		envelope.ValueNonce, envelope.Ciphertext, metadata, params.ActorUserID)
	return scanSecretReference(row)
}

func (s *Store) GetSecret(ctx context.Context, scope, name string) ([]byte, SecretReference, error) {
	if s.keyring == nil {
		return nil, SecretReference{}, ErrSecretUnavailable
	}
	if !identifierPattern.MatchString(scope) || !secretNamePattern.MatchString(name) {
		return nil, SecretReference{}, errors.New("invalid service secret identity")
	}
	record, err := s.loadSecret(ctx, scope, name)
	if err != nil {
		return nil, SecretReference{}, err
	}
	plaintext, err := s.keyring.Open(record.Envelope, secretAAD(scope, name))
	if err != nil {
		return nil, SecretReference{}, fmt.Errorf("decrypt service secret %s/%s: %w", scope, name, err)
	}
	return plaintext, record.Reference, nil
}

func (s *Store) RotateSecret(ctx context.Context, scope, name string, actorUserID int64) (SecretReference, error) {
	if s.keyring == nil {
		return SecretReference{}, ErrSecretUnavailable
	}
	if !identifierPattern.MatchString(scope) || !secretNamePattern.MatchString(name) || actorUserID < 0 {
		return SecretReference{}, errors.New("invalid service secret rotation")
	}
	record, err := s.loadSecret(ctx, scope, name)
	if err != nil {
		return SecretReference{}, err
	}
	if !s.keyring.NeedsRotation(record.Envelope) {
		return record.Reference, nil
	}
	envelope, err := s.keyring.Rotate(record.Envelope, secretAAD(scope, name))
	if err != nil {
		return SecretReference{}, err
	}
	row := s.db.QueryRowContext(ctx, `
UPDATE service_secrets
SET algorithm=$2,key_version=$3,wrapped_key_nonce=$4,wrapped_data_key=$5,
    value_nonce=$6,ciphertext=$7,updated_by_user_id=NULLIF($8,0),updated_at=now()
WHERE id=$1 AND key_version=$9
RETURNING id,secret_id,scope,name,key_version,metadata,
          updated_by_user_id,created_at,updated_at`,
		record.Reference.ID, envelope.Algorithm, envelope.KeyVersion,
		envelope.WrappedKeyNonce, envelope.WrappedDataKey, envelope.ValueNonce,
		envelope.Ciphertext, actorUserID, record.Envelope.KeyVersion)
	reference, err := scanSecretReference(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SecretReference{}, ErrRevisionConflict
	}
	return reference, err
}

func (s *Store) DeleteSecret(ctx context.Context, scope, name string) error {
	return deleteSecret(ctx, s.db, scope, name)
}

// DeleteSecretTx deletes a secret in the caller's transaction so clearing a
// credential cannot commit independently of its related configuration.
func (s *Store) DeleteSecretTx(ctx context.Context, tx *sql.Tx, scope, name string) error {
	if tx == nil {
		return errors.New("service secret transaction is required")
	}
	return deleteSecret(ctx, tx, scope, name)
}

func deleteSecret(ctx context.Context, executor secretExecutor, scope, name string) error {
	if !identifierPattern.MatchString(scope) || !secretNamePattern.MatchString(name) {
		return errors.New("invalid service secret identity")
	}
	_, err := executor.ExecContext(ctx, `DELETE FROM service_secrets WHERE scope=$1 AND name=$2`, scope, name)
	if err != nil {
		return fmt.Errorf("delete service secret: %w", err)
	}
	return nil
}

type loadedSecret struct {
	Reference SecretReference
	Envelope  Envelope
}

func (s *Store) loadSecret(ctx context.Context, scope, name string) (loadedSecret, error) {
	var record loadedSecret
	err := s.db.QueryRowContext(ctx, `
SELECT id,secret_id,scope,name,algorithm,key_version,wrapped_key_nonce,
       wrapped_data_key,value_nonce,ciphertext,metadata,updated_by_user_id,
       created_at,updated_at
FROM service_secrets WHERE scope=$1 AND name=$2`, scope, name).Scan(
		&record.Reference.ID, &record.Reference.SecretID, &record.Reference.Scope,
		&record.Reference.Name, &record.Envelope.Algorithm, &record.Envelope.KeyVersion,
		&record.Envelope.WrappedKeyNonce, &record.Envelope.WrappedDataKey,
		&record.Envelope.ValueNonce, &record.Envelope.Ciphertext,
		&record.Reference.Metadata, &record.Reference.UpdatedByUserID,
		&record.Reference.CreatedAt, &record.Reference.UpdatedAt,
	)
	if err != nil {
		return loadedSecret{}, fmt.Errorf("load service secret: %w", err)
	}
	return record, nil
}

type scanner interface {
	Scan(dest ...any) error
}

type secretQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type secretExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func scanSetting(row scanner) (Setting, error) {
	var item Setting
	err := row.Scan(
		&item.Category, &item.Desired, &item.Applied,
		&item.DesiredRevision, &item.AppliedRevision, &item.ConvergenceStatus,
		&item.LastGoodConfigHash, &item.LastError, &item.UpdatedByUserID,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return Setting{}, err
	}
	return item, nil
}

func scanInventory(row scanner) (InventoryItem, error) {
	var item InventoryItem
	err := row.Scan(
		&item.ID, &item.Kind, &item.ResourceKey, &item.HealthStatus,
		&item.Payload, &item.LastError, &item.CheckedAt, &item.ExpiresAt,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return InventoryItem{}, err
	}
	return item, nil
}

func scanOperation(row scanner) (Operation, error) {
	var item Operation
	err := row.Scan(
		&item.ID, &item.OperationID, &item.Category, &item.Action,
		&item.TargetType, &item.TargetKey, &item.Request, &item.Result,
		&item.Status, &item.DesiredRevision, &item.IdempotencyKey,
		&item.ConfirmationDeadline, &item.ConfirmedAt, &item.LastError,
		&item.ActorUserID, &item.StartedAt, &item.CompletedAt,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return Operation{}, err
	}
	return item, nil
}

func scanSecretReference(row scanner) (SecretReference, error) {
	var item SecretReference
	err := row.Scan(
		&item.ID, &item.SecretID, &item.Scope, &item.Name, &item.KeyVersion,
		&item.Metadata, &item.UpdatedByUserID, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return SecretReference{}, err
	}
	return item, nil
}

func normalizedJSONObject(value json.RawMessage) (json.RawMessage, error) {
	if len(value) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var object map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("value must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("value must contain one JSON object")
		}
		return nil, err
	}
	normalized, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func (s HealthStatus) valid() bool {
	switch s {
	case HealthHealthy, HealthWarning, HealthCritical, HealthPending, HealthUnavailable, HealthUnknown:
		return true
	default:
		return false
	}
}

func (s OperationStatus) valid() bool {
	switch s {
	case OperationPending, OperationRunning, OperationAwaitingConfirmation,
		OperationSucceeded, OperationFailed, OperationRolledBack, OperationCancelled:
		return true
	default:
		return false
	}
}

func boundedError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 4096 {
		return value[:4096]
	}
	return value
}

func secretAAD(scope, name string) []byte {
	return []byte("service-secret:" + scope + ":" + name)
}

func randomPublicID(prefix string, byteCount int) (string, error) {
	random := make([]byte, byteCount)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate public ID: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(random), nil
}
