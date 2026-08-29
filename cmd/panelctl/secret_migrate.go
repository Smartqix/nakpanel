package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

type secretMigrationStore interface {
	PutSecret(context.Context, serveradmin.PutSecretParams) (serveradmin.SecretReference, error)
	GetSecret(context.Context, string, string) ([]byte, serveradmin.SecretReference, error)
	PutSecretTx(context.Context, *sql.Tx, serveradmin.PutSecretParams) (serveradmin.SecretReference, error)
}

type secretMigrationResult struct {
	encryptedCredentials int
	migratedJobs         int64
	scrubbedJobs         int64
}

type legacyDatabaseJob struct {
	id    int64
	state string
	args  []byte
}

type legacyDatabaseJobArgs struct {
	DatabaseID    int64  `json:"database_id"`
	CredentialRef string `json:"credential_ref"`
	Password      string `json:"password"`
}

func runSecretMigration(ctx context.Context, databaseURL string, args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("secret-key migrate", flag.ContinueOnError)
	set.SetOutput(stderr)
	path := set.String("path", config.DefaultSecretKeyFile, "absolute secret key file path")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return errors.New("secret-key migrate does not accept positional arguments")
	}
	keyring, err := serveradmin.LoadKeyring(strings.TrimSpace(*path))
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open PostgreSQL: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	secrets := serveradmin.NewStore(db, keyring)

	result, err := migrateLegacySecrets(ctx, db, secrets)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout,
		"Verified %d encrypted service credential(s); migrated %d active database job credential(s); scrubbed %d terminal database job(s); cleared legacy plaintext.\n",
		result.encryptedCredentials, result.migratedJobs, result.scrubbedJobs)
	return nil
}

func migrateLegacySecrets(ctx context.Context, db *sql.DB, secrets secretMigrationStore) (secretMigrationResult, error) {
	var result secretMigrationResult
	if db == nil || secrets == nil {
		return result, errors.New("secret migration is not configured")
	}

	var host, password string
	err := db.QueryRowContext(ctx, `SELECT smarthost_host,smarthost_password FROM mail_settings WHERE id`).Scan(&host, &password)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("read legacy relay credential: %w", err)
	}
	if strings.TrimSpace(host) == "" && password != "" {
		return result, errors.New("legacy relay password exists without a smarthost host; correct mail_settings before migrating")
	}
	if strings.TrimSpace(host) != "" {
		if password != "" {
			if _, err := secrets.PutSecret(ctx, serveradmin.PutSecretParams{
				Scope: "mail", Name: "smarthost", Plaintext: []byte(password),
			}); err != nil {
				return result, fmt.Errorf("encrypt relay credential: %w", err)
			}
		}
		verified, _, err := secrets.GetSecret(ctx, "mail", "smarthost")
		if err != nil {
			return result, fmt.Errorf("verify encrypted relay credential: %w", err)
		}
		if len(verified) == 0 {
			clear(verified)
			return result, errors.New("encrypted relay credential is empty")
		}
		if password != "" && subtle.ConstantTimeCompare(verified, []byte(password)) != 1 {
			clear(verified)
			return result, errors.New("encrypted relay credential verification failed")
		}
		clear(verified)
		result.encryptedCredentials++
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin plaintext scrub: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	jobs, err := lockedLegacyDatabaseJobs(ctx, tx)
	if err != nil {
		return result, err
	}
	for _, job := range jobs {
		switch job.state {
		case "completed", "cancelled", "discarded":
			affected, err := scrubLegacyDatabaseJob(ctx, tx, job.id)
			if err != nil {
				return result, err
			}
			result.scrubbedJobs += affected
		case "available", "pending", "retryable", "running", "scheduled":
			if err := migrateActiveDatabaseJob(ctx, tx, secrets, job); err != nil {
				return result, err
			}
			result.migratedJobs++
			result.encryptedCredentials++
		default:
			return result, fmt.Errorf("legacy database job %d has unsupported state %q; stop the panel and resolve the job before retrying", job.id, job.state)
		}
	}

	if password != "" {
		update, err := tx.ExecContext(ctx, `
UPDATE mail_settings
SET smarthost_password='',updated_at=now()
WHERE id AND smarthost_password=$1`, password)
		if err != nil {
			return result, fmt.Errorf("clear legacy relay credential: %w", err)
		}
		affected, err := update.RowsAffected()
		if err != nil {
			return result, fmt.Errorf("check legacy relay credential scrub: %w", err)
		}
		if affected != 1 {
			return result, errors.New("legacy relay credential changed during migration; no plaintext was cleared, retry with the panel stopped")
		}
	}

	var remaining int64
	if err := tx.QueryRowContext(ctx, `
SELECT count(*)
FROM river_job
WHERE kind='create_database' AND args ? 'password'`).Scan(&remaining); err != nil {
		return result, fmt.Errorf("verify database job credential scrub: %w", err)
	}
	if remaining != 0 {
		return result, fmt.Errorf("%d create_database job(s) still contain plaintext password arguments; migration was rolled back", remaining)
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit plaintext credential scrub: %w", err)
	}
	return result, nil
}

func lockedLegacyDatabaseJobs(ctx context.Context, tx *sql.Tx) ([]legacyDatabaseJob, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id,state,args
FROM river_job
WHERE kind='create_database' AND args ? 'password'
ORDER BY id
FOR UPDATE`)
	if err != nil {
		return nil, fmt.Errorf("list legacy database jobs: %w", err)
	}
	defer rows.Close()

	var jobs []legacyDatabaseJob
	for rows.Next() {
		var job legacyDatabaseJob
		if err := rows.Scan(&job.id, &job.state, &job.args); err != nil {
			return nil, fmt.Errorf("read legacy database job: %w", err)
		}
		job.args = append([]byte(nil), job.args...)
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list legacy database jobs: %w", err)
	}
	return jobs, nil
}

func migrateActiveDatabaseJob(ctx context.Context, tx *sql.Tx, secrets secretMigrationStore, job legacyDatabaseJob) error {
	var payload legacyDatabaseJobArgs
	if err := json.Unmarshal(job.args, &payload); err != nil {
		return fmt.Errorf("legacy database job %d has invalid arguments: %w", job.id, err)
	}
	if payload.DatabaseID <= 0 {
		return fmt.Errorf("legacy database job %d has an invalid database_id", job.id)
	}
	if payload.Password == "" {
		return fmt.Errorf("legacy database job %d has an empty plaintext password", job.id)
	}
	credentialRef := fmt.Sprintf("provision-%d", payload.DatabaseID)
	if payload.CredentialRef != "" && payload.CredentialRef != credentialRef {
		return fmt.Errorf("legacy database job %d has credential_ref %q, expected %q", job.id, payload.CredentialRef, credentialRef)
	}
	plaintext := []byte(payload.Password)
	defer clear(plaintext)
	if _, err := secrets.PutSecretTx(ctx, tx, serveradmin.PutSecretParams{
		Scope: "database", Name: credentialRef, Plaintext: plaintext,
		Metadata: []byte(fmt.Sprintf(`{"database_id":%d}`, payload.DatabaseID)),
	}); err != nil {
		return fmt.Errorf("encrypt legacy database job %d credential: %w", job.id, err)
	}
	update, err := tx.ExecContext(ctx, `
UPDATE river_job
SET args=jsonb_set(args-'password','{credential_ref}',to_jsonb($2::text),true)
WHERE id=$1 AND kind='create_database' AND args ? 'password'`, job.id, credentialRef)
	if err != nil {
		return fmt.Errorf("scrub legacy database job %d: %w", job.id, err)
	}
	affected, err := update.RowsAffected()
	if err != nil {
		return fmt.Errorf("check legacy database job %d scrub: %w", job.id, err)
	}
	if affected != 1 {
		return fmt.Errorf("legacy database job %d changed during migration; retry with workers stopped", job.id)
	}
	return nil
}

func scrubLegacyDatabaseJob(ctx context.Context, tx *sql.Tx, jobID int64) (int64, error) {
	update, err := tx.ExecContext(ctx, `
UPDATE river_job
SET args=args-'password'
WHERE id=$1 AND kind='create_database' AND args ? 'password'`, jobID)
	if err != nil {
		return 0, fmt.Errorf("scrub terminal database job %d: %w", jobID, err)
	}
	affected, err := update.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("check terminal database job %d scrub: %w", jobID, err)
	}
	if affected != 1 {
		return 0, fmt.Errorf("terminal database job %d changed during migration; retry with workers stopped", jobID)
	}
	return affected, nil
}
