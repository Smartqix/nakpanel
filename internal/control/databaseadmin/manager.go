// Package databaseadmin resolves control-plane database IDs before calling
// typed privileged database operations. Browser input never supplies database
// names, principals, SQL, command flags, or filesystem paths.
package databaseadmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/platformadmin"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	dbvalidation "github.com/nakroteck/nakpanel/internal/database"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

var (
	ErrUnsupportedEngine   = errors.New("database engine is not supported by server administration")
	ErrOperationInProgress = errors.New("a database administration operation is already in progress")
)

const (
	pendingSecretScope   = "database_pending"
	canonicalSecretScope = "database"
)

type Agent interface {
	InspectDatabaseAdmin(context.Context, types.InspectDatabaseAdminReq) (types.DatabaseAdminSnapshot, error)
	ManageDatabaseAdmin(context.Context, types.ManageDatabaseAdminReq) (types.ManageDatabaseAdminResult, error)
}

type TrackedDatabase struct {
	ID              int64  `json:"id"`
	CustomerID      int64  `json:"customer_id"`
	SubscriptionID  int64  `json:"subscription_id"`
	SiteID          int64  `json:"site_id,omitempty"`
	Engine          string `json:"engine"`
	Name            string `json:"name"`
	Principal       string `json:"principal"`
	Status          string `json:"status"`
	LastError       string `json:"last_error,omitempty"`
	DatabaseExists  bool   `json:"database_exists"`
	PrincipalFound  bool   `json:"principal_exists"`
	InspectionError string `json:"inspection_error,omitempty"`
}

type Snapshot struct {
	Server    types.DatabaseServerHealth `json:"server"`
	Databases []TrackedDatabase          `json:"databases"`
}

type Manager struct {
	db      *sql.DB
	agent   Agent
	secrets adminStore
	river   riverInserter
}

type adminStore interface {
	PutSecretTx(context.Context, *sql.Tx, serveradmin.PutSecretParams) (serveradmin.SecretReference, error)
	DeleteSecretTx(context.Context, *sql.Tx, string, string) error
	GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error)
	CreateOperationTx(context.Context, *sql.Tx, serveradmin.CreateOperationParams) (serveradmin.Operation, error)
	GetOperation(context.Context, string) (serveradmin.Operation, error)
	UpdateOperation(context.Context, serveradmin.UpdateOperationParams) (serveradmin.Operation, error)
}

type riverInserter interface {
	InsertTx(context.Context, *sql.Tx, river.JobArgs, *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

func NewManager(db *sql.DB, agent Agent, secrets adminStore, queue riverInserter) *Manager {
	return &Manager{db: db, agent: agent, secrets: secrets, river: queue}
}

func (m *Manager) SetRiverClient(client *river.Client[*sql.Tx]) {
	m.river = client
}

func (m *Manager) Snapshot(ctx context.Context) (Snapshot, error) {
	if m == nil || m.db == nil || m.agent == nil {
		return Snapshot{}, errors.New("database administration is not configured")
	}
	rows, err := m.db.QueryContext(ctx, `
	SELECT id, customer_id, subscription_id, COALESCE(site_id,0), engine,
	       db_name, db_user, status, (last_error <> '')
FROM databases
WHERE engine IN ('mariadb','mysql')
ORDER BY id`)
	if err != nil {
		return Snapshot{}, fmt.Errorf("list tracked databases: %w", err)
	}
	defer rows.Close()

	items := make([]TrackedDatabase, 0)
	targets := make([]types.DatabaseAdminTarget, 0)
	for rows.Next() {
		var item TrackedDatabase
		var hasStoredError bool
		if err := rows.Scan(
			&item.ID, &item.CustomerID, &item.SubscriptionID, &item.SiteID, &item.Engine,
			&item.Name, &item.Principal, &item.Status, &hasStoredError,
		); err != nil {
			return Snapshot{}, fmt.Errorf("read tracked database: %w", err)
		}
		if hasStoredError {
			item.LastError = "Provisioning requires attention."
		}
		items = append(items, item)
		targets = append(targets, types.DatabaseAdminTarget{
			DatabaseID: item.ID, Name: item.Name, Principal: item.Principal,
		})
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("list tracked database rows: %w", err)
	}

	live, err := m.agent.InspectDatabaseAdmin(ctx, types.InspectDatabaseAdminReq{Targets: targets})
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect MariaDB: %w", err)
	}
	states := make(map[int64]types.TrackedDatabaseState, len(live.Databases))
	for _, state := range live.Databases {
		states[state.DatabaseID] = state
	}
	for i := range items {
		state, ok := states[items[i].ID]
		if !ok {
			items[i].InspectionError = "live state was not returned"
			continue
		}
		items[i].DatabaseExists = state.DatabaseExists
		items[i].PrincipalFound = state.PrincipalExists
		items[i].InspectionError = state.LastError
	}
	return Snapshot{Server: live.Server, Databases: items}, nil
}

func (m *Manager) RotatePassword(ctx context.Context, actorUserID, databaseID int64, password string) (types.ManageDatabaseAdminResult, error) {
	target, err := m.loadTarget(ctx, databaseID)
	if err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	if err := dbvalidation.ValidateCreateDatabaseRequest(types.CreateDatabaseReq{
		Engine: types.EngineMariaDB, DBName: target.Name, DBUser: target.Principal, Password: password,
	}); err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	plaintext := []byte(password)
	defer clear(plaintext)
	return m.queueMutation(ctx, actorUserID, mutationRequest{
		Action: types.DatabaseAdminRotatePassword, Target: target,
	}, plaintext)
}

func (m *Manager) SetRole(ctx context.Context, actorUserID, databaseID int64, role platformadmin.DatabaseRole) (types.ManageDatabaseAdminResult, error) {
	if err := (platformadmin.DatabaseRoleRequest{
		ServerID: "local-mariadb", DatabaseID: databaseID, PrincipalID: databaseID, Role: role,
	}).Validate(); err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	target, err := m.loadTarget(ctx, databaseID)
	if err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	return m.queueMutation(ctx, actorUserID, mutationRequest{
		Action: types.DatabaseAdminSetRole, Target: target, Role: types.DatabaseAdminRole(role),
	})
}

func (m *Manager) Check(ctx context.Context, databaseID int64) (types.ManageDatabaseAdminResult, error) {
	target, err := m.loadTarget(ctx, databaseID)
	if err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	operationID, err := serveradmin.NewOperationID()
	if err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	return m.agent.ManageDatabaseAdmin(ctx, types.ManageDatabaseAdminReq{
		OperationID: operationID, Action: types.DatabaseAdminCheck, Target: target,
	})
}

func (m *Manager) loadTarget(ctx context.Context, databaseID int64) (types.DatabaseAdminTarget, error) {
	if m == nil || m.db == nil || m.agent == nil {
		return types.DatabaseAdminTarget{}, errors.New("database administration is not configured")
	}
	if databaseID <= 0 {
		return types.DatabaseAdminTarget{}, errors.New("tracked database id is required")
	}
	var engine string
	var target types.DatabaseAdminTarget
	err := m.db.QueryRowContext(ctx, `
SELECT id, engine, db_name, db_user
FROM databases
WHERE id=$1`, databaseID).Scan(&target.DatabaseID, &engine, &target.Name, &target.Principal)
	if err != nil {
		return types.DatabaseAdminTarget{}, fmt.Errorf("load tracked database: %w", err)
	}
	if engine != "mariadb" && engine != "mysql" {
		return types.DatabaseAdminTarget{}, fmt.Errorf("%w: %s", ErrUnsupportedEngine, engine)
	}
	return target, nil
}

func SafeError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, sql.ErrNoRows):
		return "Tracked database was not found."
	case errors.Is(err, ErrUnsupportedEngine):
		return "This database engine is not available in MariaDB administration."
	case errors.Is(err, ErrOperationInProgress):
		return "A database administration operation is already in progress."
	default:
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "password") || strings.Contains(message, "database name") ||
			strings.Contains(message, "database user") || strings.Contains(message, "role") {
			return "The database administration request was invalid."
		}
		return "The database administration operation could not be completed."
	}
}

type mutationRequest struct {
	Action          types.DatabaseAdminAction `json:"action"`
	Target          types.DatabaseAdminTarget `json:"target"`
	Role            types.DatabaseAdminRole   `json:"role,omitempty"`
	CredentialScope string                    `json:"credential_scope,omitempty"`
	CredentialName  string                    `json:"credential_name,omitempty"`
}

func (m *Manager) queueMutation(ctx context.Context, actorUserID int64, request mutationRequest, plaintext ...[]byte) (types.ManageDatabaseAdminResult, error) {
	if m == nil || m.db == nil || m.agent == nil || m.secrets == nil || m.river == nil {
		return types.ManageDatabaseAdminResult{}, errors.New("database administration queue is not configured")
	}
	if actorUserID <= 0 {
		return types.ManageDatabaseAdminResult{}, errors.New("database administration actor is required")
	}
	operationID, err := serveradmin.NewOperationID()
	if err != nil {
		return types.ManageDatabaseAdminResult{}, err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return types.ManageDatabaseAdminResult{}, fmt.Errorf("begin database administration operation: %w", err)
	}
	defer tx.Rollback()

	// Serialize creation per tracked target. River uniqueness is a second line of
	// defense; the advisory lock prevents an orphaned pending operation record.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, request.Target.DatabaseID+26000000); err != nil {
		return types.ManageDatabaseAdminResult{}, fmt.Errorf("lock database administration target: %w", err)
	}
	var activeOperationID, activeAction string
	var activePayload []byte
	err = tx.QueryRowContext(ctx, `
SELECT operation_id, action, request
FROM server_operations
WHERE target_type='database' AND target_key=$1
  AND status IN ('pending','running','awaiting_confirmation')
ORDER BY id DESC
LIMIT 1`, strconv.FormatInt(request.Target.DatabaseID, 10)).Scan(&activeOperationID, &activeAction, &activePayload)
	if err == nil {
		var activeRequest mutationRequest
		_ = json.Unmarshal(activePayload, &activeRequest)
		return types.ManageDatabaseAdminResult{
			OperationID: activeOperationID, DatabaseID: request.Target.DatabaseID,
			Action: types.DatabaseAdminAction(activeAction), Role: activeRequest.Role, Status: "queued",
		}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return types.ManageDatabaseAdminResult{}, fmt.Errorf("check active database administration operation: %w", err)
	}

	if request.Action == types.DatabaseAdminRotatePassword {
		if len(plaintext) != 1 || len(plaintext[0]) == 0 {
			return types.ManageDatabaseAdminResult{}, errors.New("replacement database password is required")
		}
		request.CredentialScope = pendingSecretScope
		request.CredentialName = "rotation-" + operationID
		if _, err := m.secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
			Scope: request.CredentialScope, Name: request.CredentialName,
			Plaintext: plaintext[0], ActorUserID: actorUserID,
			Metadata: mustJSON(map[string]any{
				"database_id": request.Target.DatabaseID, "operation_id": operationID, "purpose": "password_rotation",
			}),
		}); err != nil {
			return types.ManageDatabaseAdminResult{}, fmt.Errorf("stage encrypted database credential: %w", err)
		}
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return types.ManageDatabaseAdminResult{}, fmt.Errorf("encode database administration operation: %w", err)
	}
	if _, err := m.secrets.CreateOperationTx(ctx, tx, serveradmin.CreateOperationParams{
		OperationID: operationID, Category: serveradmin.CategoryApplicationsDatabases,
		Action: string(request.Action), TargetType: "database",
		TargetKey: strconv.FormatInt(request.Target.DatabaseID, 10),
		Request:   payload, IdempotencyKey: operationID, ActorUserID: actorUserID,
	}); err != nil {
		return types.ManageDatabaseAdminResult{}, fmt.Errorf("persist database administration operation: %w", err)
	}
	if _, err := m.river.InsertTx(ctx, tx, MutationArgs{
		OperationID: operationID, DatabaseID: request.Target.DatabaseID,
	}, nil); err != nil {
		return types.ManageDatabaseAdminResult{}, fmt.Errorf("queue database administration operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return types.ManageDatabaseAdminResult{}, fmt.Errorf("commit database administration operation: %w", err)
	}
	return types.ManageDatabaseAdminResult{
		OperationID: operationID, DatabaseID: request.Target.DatabaseID,
		Action: request.Action, Role: request.Role, Status: "queued",
	}, nil
}

func mustJSON(value map[string]any) json.RawMessage {
	payload, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return payload
}
