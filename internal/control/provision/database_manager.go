package provision

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

var ErrDatabaseManagerDenied = errors.New("database manager access is unavailable")

type DatabaseManagerAccess struct {
	DatabaseID int64
	Grant      string `json:"grant"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Database   string `json:"database"`
	Bootstrap  bool   `json:"-"`
}

type SQLDatabaseManager struct {
	db      *sql.DB
	secrets *serveradmin.Store
}

func NewSQLDatabaseManager(db *sql.DB, secrets *serveradmin.Store) *SQLDatabaseManager {
	return &SQLDatabaseManager{db: db, secrets: secrets}
}

// The encrypted value itself is the revision: re-encryption also safely revokes access.
const managerDatabaseScope = `SELECT d.db_name, d.db_user, md5(encode(sec.ciphertext,'hex'))
 FROM databases d JOIN subscriptions s ON s.id=d.subscription_id
 JOIN customers c ON c.id=s.customer_id
 LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id
 JOIN service_secrets sec ON sec.scope='database' AND sec.name='provision-'||d.id::text
 WHERE d.id=$1 AND d.status='active' AND d.engine IN ('mariadb','mysql')
 AND s.status='active' AND c.status='active' AND (ra.id IS NULL OR (ra.status='active' AND EXISTS (SELECT 1 FROM reseller_subscriptions rs WHERE rs.reseller_id=ra.id AND rs.status='active')))
 AND NOT EXISTS (SELECT 1 FROM server_operations op WHERE op.target_type='database' AND op.target_key=d.id::text AND op.action='rotate_password' AND op.status IN ('pending','running','awaiting_confirmation'))
 AND ($2='admin' OR ($2='client' AND c.login_user_id=$3)
 OR ($2='reseller' AND ra.login_user_id=$3))`

func (m *SQLDatabaseManager) scoped(ctx context.Context, actor auth.SessionUser, id int64) (DatabaseManagerAccess, string, error) {
	var a DatabaseManagerAccess
	var revision string
	if m == nil || m.db == nil || m.secrets == nil || actor.ID <= 0 {
		return a, "", ErrDatabaseManagerDenied
	}
	err := m.db.QueryRowContext(ctx, managerDatabaseScope, id, string(actor.Role), actor.ID).Scan(&a.Database, &a.Username, &revision)
	a.DatabaseID = id
	if err != nil {
		return a, "", ErrDatabaseManagerDenied
	}
	return a, revision, nil
}

func (m *SQLDatabaseManager) Launch(ctx context.Context, actor auth.SessionUser, session string, id int64) (string, error) {
	if session == "" {
		return "", ErrDatabaseManagerDenied
	}
	_, revision, err := m.scoped(ctx, actor, id)
	if err != nil {
		return "", err
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	_, err = m.db.ExecContext(ctx, `INSERT INTO database_manager_grants(token_hash,session_hash,actor_user_id,database_id,credential_revision) VALUES($1,$2,$3,$4,$5)`, auth.TokenHash(token), auth.TokenHash(session), actor.ID, id, revision)
	return token, err
}

func (m *SQLDatabaseManager) Access(ctx context.Context, actor auth.SessionUser, session, token string) (DatabaseManagerAccess, error) {
	if m == nil || m.db == nil || session == "" || token == "" {
		return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
	}
	var role string
	if err := m.db.QueryRowContext(ctx, `SELECT u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.user_id=$2 AND s.expires_at>now() AND s.revoked_at IS NULL AND u.login_disabled=false`, auth.TokenHash(session), actor.ID).Scan(&role); err != nil {
		return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
	}
	actor.Role = auth.Role(role)
	var id int64
	var revision string
	var consumed sql.NullTime
	hash := auth.TokenHash(token)
	err := m.db.QueryRowContext(ctx, `SELECT database_id,credential_revision,consumed_at FROM database_manager_grants WHERE token_hash=$1 AND session_hash=$2 AND actor_user_id=$3 AND revoked_at IS NULL AND created_at>now()-interval '60 minutes' AND last_used_at>now()-interval '15 minutes' AND (consumed_at IS NOT NULL OR created_at>now()-interval '60 seconds')`, hash, auth.TokenHash(session), actor.ID).Scan(&id, &revision, &consumed)
	if err != nil {
		return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
	}
	a, current, err := m.scoped(ctx, actor, id)
	if err != nil || current != revision {
		return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
	}
	if !consumed.Valid {
		name, _ := databaseCredentialName(id)
		plaintext, _, secretErr := m.secrets.GetSecret(ctx, databaseCredentialScope, name)
		if secretErr != nil {
			return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
		}
		defer func() {
			for i := range plaintext {
				plaintext[i] = 0
			}
		}()
		_, after, checkErr := m.scoped(ctx, actor, id)
		if checkErr != nil || after != revision {
			return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
		}
		result, updateErr := m.db.ExecContext(ctx, `UPDATE database_manager_grants SET consumed_at=now(),last_used_at=now() WHERE token_hash=$1 AND consumed_at IS NULL AND revoked_at IS NULL AND created_at>now()-interval '60 seconds'`, hash)
		if updateErr != nil {
			return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
		}
		a.Password = string(plaintext)
		a.Bootstrap = true
	} else {
		result, updateErr := m.db.ExecContext(ctx, `UPDATE database_manager_grants SET last_used_at=now() WHERE token_hash=$1 AND revoked_at IS NULL`, hash)
		if updateErr != nil {
			return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return DatabaseManagerAccess{}, ErrDatabaseManagerDenied
		}
	}
	a.Grant = hash
	return a, nil
}

func (m *SQLDatabaseManager) Logout(ctx context.Context, actor auth.SessionUser, session, token string) error {
	_, err := m.db.ExecContext(ctx, `UPDATE database_manager_grants SET revoked_at=now() WHERE token_hash=$1 AND session_hash=$2 AND actor_user_id=$3`, auth.TokenHash(token), auth.TokenHash(session), actor.ID)
	return err
}
