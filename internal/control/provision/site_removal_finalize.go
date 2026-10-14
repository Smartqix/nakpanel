package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"slices"
	"strings"
)

func (s *SiteRemovalService) Finalize(ctx context.Context, operationID, revision int64) error {
	op, err := readRemoval(s.db.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=$1", operationID))
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Staging rows can reference a second subscription: lock both in order.
	ids := removalSelectedSites(op.Snapshot)
	subs := []int64{op.SubscriptionID}
	for _, resource := range op.Snapshot.Resources {
		if resource.Kind == "staging" {
			rows, err := tx.QueryContext(ctx, "SELECT DISTINCT subscription_id FROM sites WHERE id IN ($1,$2)", resource.SiteID, resource.ParentID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id int64
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				subs = append(subs, id)
			}
			if err = rows.Err(); err != nil {
				rows.Close()
				return err
			}
			rows.Close()
		}
	}
	slices.Sort(subs)
	for _, id := range slices.Compact(subs) {
		if err = quota.LockSubscriptionMutationTx(ctx, tx, id); err != nil {
			return err
		}
	}
	op, err = readRemoval(tx.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=$1 FOR UPDATE", operationID))
	if err != nil {
		return err
	}
	if op.Revision != revision {
		return errors.New("website removal revision changed")
	}
	if op.State == "completed" {
		return nil
	}
	if op.State != "running" {
		return errors.New("retry this failed or interrupted website removal before finalization")
	}
	for _, stage := range []string{string(types.RemovalStopServices), string(types.RemovalHosting), string(types.RemovalShared), "surviving-access", "surviving-mail", string(types.RemovalFinalize)} {
		if !slices.Contains(op.Checkpoints, stage) {
			return errors.New("website removal services have not completed")
		}
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('nakpanel.site_removal_operation',$1,true)", fmt.Sprint(op.ID)); err != nil {
		return err
	}
	secretIDs, err := removalSecretIDs(ctx, tx, ids, op)
	if err != nil {
		return err
	}
	for _, query := range []string{
		`UPDATE php_applications SET active_deployment_id=NULL,previous_deployment_id=NULL WHERE site_id=ANY($1)`,
		`DELETE FROM php_deployments WHERE application_id IN (SELECT id FROM php_applications WHERE site_id=ANY($1))`,
		`DELETE FROM php_applications WHERE site_id=ANY($1)`,
		`DELETE FROM wordpress_instances WHERE site_id=ANY($1)`,
		`DELETE FROM application_instances WHERE site_id=ANY($1)`,
		`DELETE FROM git_repositories WHERE site_id=ANY($1)`,
		`DELETE FROM scheduled_tasks WHERE site_id=ANY($1)`,
		`DELETE FROM staging_operations WHERE source_site_id=ANY($1) OR target_site_id=ANY($1)`,
	} {
		if _, err = tx.ExecContext(ctx, query, pq.Array(ids)); err != nil {
			return err
		}
	}
	for _, resource := range op.Snapshot.Resources {
		if resource.Kind == "mail_domain" {
			if _, err = tx.ExecContext(ctx, "DELETE FROM mail_domains WHERE id=$1 AND subscription_id=$2 AND domain=$3", resource.ID, op.SubscriptionID, resource.Name); err != nil {
				return err
			}
		}
		if resource.Kind == "sftp_identity" {
			if _, err = tx.ExecContext(ctx, "DELETE FROM sftp_access_identities WHERE id=$1 AND subscription_id=$2", resource.ID, op.SubscriptionID); err != nil {
				return err
			}
		}
	}
	for _, database := range op.Snapshot.Databases {
		if slices.Contains(op.DeleteDatabaseIDs, database.ID) {
			if !slices.Contains(op.Checkpoints, "database-removed:"+fmt.Sprint(database.ID)) {
				return errors.New("selected database cleanup has not completed")
			}
			if _, err = tx.ExecContext(ctx, "DELETE FROM databases WHERE id=$1 AND site_id=$2 AND subscription_id=$3", database.ID, database.SiteID, op.SubscriptionID); err != nil {
				return err
			}
		}
	}
	if err = s.requeueKeptPendingDatabases(ctx, tx, op, ids); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE databases SET site_id=NULL WHERE site_id=ANY($1) AND subscription_id=$2", pq.Array(ids), op.SubscriptionID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE backups SET site_id=NULL,status=CASE WHEN status='pending' THEN 'failed' ELSE status END,last_error=CASE WHEN status='pending' THEN 'Website removed before the backup completed; no recovery point is available.' ELSE last_error END WHERE site_id=ANY($1) AND subscription_id=$2`, pq.Array(ids), op.SubscriptionID); err != nil {
		return err
	}
	// Parent links never change as a side effect of deleting their children.
	ordered := append([]types.SiteRemovalSite(nil), op.Snapshot.Sites...)
	slices.SortFunc(ordered, func(a, b types.SiteRemovalSite) int {
		return strings.Count(b.Domain, ".") - strings.Count(a.Domain, ".")
	})
	for _, item := range ordered {
		result, err := tx.ExecContext(ctx, "DELETE FROM sites WHERE id=$1 AND subscription_id=$2 AND customer_id=$3 AND domain=$4 AND removal_state<>'none'", item.SiteID, item.SubscriptionID, item.CustomerID, item.Domain)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errors.New("website removal target identity changed")
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM service_secrets secret WHERE secret.id=ANY($1)
 AND NOT EXISTS(SELECT 1 FROM php_environment_bindings WHERE secret_id=secret.id)
 AND NOT EXISTS(SELECT 1 FROM application_secret_bindings WHERE secret_id=secret.id)
 AND NOT EXISTS(SELECT 1 FROM wordpress_instances WHERE admin_secret_id=secret.id)`, pq.Array(secretIDs)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE site_removal_targets SET released=true WHERE operation_id=$1`, op.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE site_removal_operations SET state='completed',stage='completed',last_error='',completed_at=now(),updated_at=now() WHERE id=$1`, op.ID); err != nil {
		return err
	}
	metadata, _ := json.Marshal(map[string]int{"sites_removed": len(ids), "databases_retained": len(op.Snapshot.Databases) - len(op.DeleteDatabaseIDs), "backups_retained": len(op.Snapshot.Backups)})
	actor := auth.SessionUser{ID: op.ActorUserID, Email: op.ActorLabel}
	if err = removalAudit(ctx, tx, actor, op, "site.removal_completed", metadata); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SiteRemovalService) requeueKeptPendingDatabases(ctx context.Context, tx *sql.Tx, op types.SiteRemovalOperation, ids []int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT database.id,database.engine,database.db_name,database.db_user,
 EXISTS(SELECT 1 FROM service_secrets WHERE scope='database' AND name='provision-'||database.id::text)
 FROM databases database WHERE database.site_id=ANY($1) AND database.subscription_id=$2 AND database.status='pending'`, pq.Array(ids), op.SubscriptionID)
	if err != nil {
		return err
	}
	type pending struct {
		args       CreateDatabaseArgs
		credential bool
	}
	items := []pending{}
	for rows.Next() {
		var item pending
		if err = rows.Scan(&item.args.DatabaseID, &item.args.Engine, &item.args.DBName, &item.args.DBUser, &item.credential); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range items {
		if !item.credential {
			if _, err = tx.ExecContext(ctx, "UPDATE databases SET status='failed',last_error='Website removed before database setup completed and no recoverable credential is available. Create a new database.' WHERE id=$1", item.args.DatabaseID); err != nil {
				return err
			}
			continue
		}
		if s.river == nil {
			return errors.New("retained database recovery queue is unavailable")
		}
		item.args.CredentialRef = fmt.Sprintf("provision-%d", item.args.DatabaseID)
		if _, err = s.river.InsertTx(ctx, tx, item.args, nil); err != nil {
			return err
		}
	}
	return nil
}

func removalSecretIDs(ctx context.Context, tx *sql.Tx, siteIDs []int64, op types.SiteRemovalOperation) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT binding.secret_id FROM php_environment_bindings binding JOIN php_applications app ON app.id=binding.application_id WHERE app.site_id=ANY($1) AND binding.secret_id IS NOT NULL
 UNION SELECT binding.secret_id FROM application_secret_bindings binding JOIN application_instances app ON app.id=binding.application_id WHERE app.site_id=ANY($1)
 UNION SELECT admin_secret_id FROM wordpress_instances WHERE site_id=ANY($1) AND admin_secret_id IS NOT NULL`, pq.Array(siteIDs))
	if err != nil {
		return nil, err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, database := range op.Snapshot.Databases {
		if slices.Contains(op.DeleteDatabaseIDs, database.ID) && slices.Contains(op.Checkpoints, "database-principal-removed:"+fmt.Sprint(database.ID)) {
			var id int64
			err := tx.QueryRowContext(ctx, "SELECT id FROM service_secrets WHERE scope='database' AND name=$1", fmt.Sprintf("provision-%d", database.ID)).Scan(&id)
			if err == nil {
				ids = append(ids, id)
			} else if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
		}
	}
	return ids, nil
}
