package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"regexp"
)

var gitRevisionRE = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)

// Connection tests reuse bounded fetch but never the automatic publication path.
func gitAgentWorkspaceRequest(request types.EnsureGitRepositoryReq) types.EnsureGitRepositoryReq {
	if request.Action == "test" {
		request.Action = "fetch"
		request.Automatic = false
		request.Deploy = false
	}
	return request
}

const persistGitWorkspaceResultSQL = `UPDATE git_repositories SET convergence_status='in_sync',last_revision=COALESCE(NULLIF($2,''),last_revision),
deploy_public_key=CASE WHEN $12 THEN '' ELSE COALESCE(NULLIF($3,''),deploy_public_key) END,last_error='',updated_at=now(),
connection_status=COALESCE(NULLIF($5,''),connection_status),
fetched_revision=CASE WHEN $12 THEN '' ELSE COALESCE(NULLIF($6,''),fetched_revision) END,
deployed_revision=COALESCE(NULLIF($7,''),deployed_revision),
previous_revision=CASE WHEN $12 THEN '' WHEN $13 THEN $8 ELSE previous_revision END,
branches=CASE WHEN $12 THEN '[]'::jsonb WHEN $9='null' THEN branches ELSE $9::jsonb END,
commits=CASE WHEN $12 THEN '[]'::jsonb WHEN $10='null' THEN commits ELSE $10::jsonb END,
conflicts=CASE WHEN $12 OR $11='null' THEN '[]'::jsonb ELSE $11::jsonb END
WHERE id=$1 AND operation_revision=$4`

func persistGitWorkspaceResult(ctx context.Context, db *sql.DB, repository types.EnsureGitRepositoryReq, result types.EnsureGitRepositoryResult) error {
	branches, _ := json.Marshal(result.Branches)
	commits, _ := json.Marshal(result.Commits)
	conflicts, _ := json.Marshal(result.Conflicts)
	disconnected := repository.Action == "disconnect"
	published := result.DeployedRevision != "" && result.Status != "conflicts" && (repository.Action == "deploy" || repository.Action == "rollback" || repository.Action == "fetch")
	_, err := db.ExecContext(ctx, persistGitWorkspaceResultSQL, repository.RepositoryID, result.DeployedRevision, result.DeployPublicKey, repository.OperationRevision, result.ConnectionStatus, result.FetchedRevision, result.DeployedRevision, result.PreviousRevision, string(branches), string(commits), string(conflicts), disconnected, published)
	return err
}

func validateGitOperation(input types.GitWorkspaceOperationInput) error {
	switch input.Action {
	case "prepare", "fetch", "test", "disconnect":
	case "preview", "deploy", "rollback":
		if !gitRevisionRE.MatchString(input.Revision) {
			return errors.New("a full immutable commit revision is required")
		}
	default:
		return errors.New("invalid Git workspace action")
	}
	if (input.Action == "deploy" || input.Action == "rollback") && !input.ConfirmOverwrite {
		return errors.New("confirm code overwrite before deployment or rollback")
	}
	if len(input.IdempotencyKey) > 128 {
		return errors.New("idempotency key is too long")
	}
	return nil
}

func (s *SQLStore) QueueGitWorkspaceOperation(ctx context.Context, subscriptionID, siteID int64, input types.GitWorkspaceOperationInput) (int64, error) {
	if err := validateGitOperation(input); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = lockActiveSubscriptionTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	if err = requireGitPermissionTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	var id, revision int64
	var mode, previous string
	if err = tx.QueryRowContext(ctx, `SELECT r.id,r.operation_revision,r.deployment_mode,r.previous_revision FROM git_repositories r JOIN sites s ON s.id=r.site_id WHERE r.site_id=$1 AND s.subscription_id=$2 AND s.desired_status='active' FOR UPDATE OF r`, siteID, subscriptionID).Scan(&id, &revision, &mode, &previous); err != nil {
		return 0, err
	}
	if input.IdempotencyKey != "" {
		var existing int64
		var action, target string
		var confirm bool
		err = tx.QueryRowContext(ctx, `SELECT id,action,revision,confirm_overwrite FROM git_deployments WHERE repository_id=$1 AND idempotency_key=$2`, id, input.IdempotencyKey).Scan(&existing, &action, &target, &confirm)
		if err == nil {
			if action != input.Action || target != input.Revision || confirm != input.ConfirmOverwrite {
				return 0, errors.New("idempotency key belongs to a different operation")
			}
			return existing, tx.Commit()
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
	}
	if input.ExpectedRevision != revision {
		return 0, errors.New("Git workspace changed; refresh before retrying")
	}
	if mode == "disabled" && (input.Action == "deploy" || input.Action == "rollback") {
		return 0, errors.New("Git deployment is disabled")
	}
	if input.Action == "rollback" && (previous == "" || input.Revision != previous) {
		return 0, errors.New("rollback must target the previous successful deployment")
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM git_deployments WHERE repository_id=$1 AND status IN ('pending','running'))`, id).Scan(&active); err != nil {
		return 0, err
	}
	if active {
		return 0, errors.New("a Git workspace operation is already pending")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE git_repositories SET operation_revision=operation_revision+1,convergence_status='pending',last_error='',deployment_mode=CASE WHEN $2='disconnect' THEN 'disabled' ELSE deployment_mode END,automatic=CASE WHEN $2='disconnect' THEN false ELSE automatic END,webhook_secret_hash=CASE WHEN $2='disconnect' THEN '' ELSE webhook_secret_hash END,updated_at=now() WHERE id=$1`, id, input.Action); err != nil {
		return 0, err
	}
	var operationID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO git_deployments(repository_id,revision,status,action,operation_revision,confirm_overwrite,idempotency_key) VALUES($1,$2,'pending',$3,$4,$5,$6) RETURNING id`, id, input.Revision, input.Action, revision+1, input.ConfirmOverwrite, input.IdempotencyKey).Scan(&operationID); err != nil {
		return 0, err
	}
	if err = s.markSubscriptionPendingTx(ctx, tx, subscriptionID); err != nil {
		return 0, err
	}
	return operationID, tx.Commit()
}
