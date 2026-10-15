package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"time"
)

type SiteJobFence struct {
	river.WorkerMiddlewareDefaults
	db *sql.DB
}

func NewSiteJobFence(db *sql.DB) *SiteJobFence { return &SiteJobFence{db: db} }

type removalFenceArgs struct {
	SiteID        int64           `json:"site_id"`
	ApplicationID int64           `json:"application_id"`
	InstanceID    int64           `json:"instance_id"`
	ZoneID        int64           `json:"zone_id"`
	WebmailID     int64           `json:"webmail_id"`
	BackupID      int64           `json:"backup_id"`
	DatabaseID    int64           `json:"database_id"`
	RunID         int64           `json:"run_id"`
	OperationID   json.RawMessage `json:"operation_id"`
	Domain        string          `json:"domain"`
	ImportID      string          `json:"import_id"`
}

const fenceSiteQuery = `SELECT site.removal_state,site.created_at FROM sites site WHERE site.id=$1`

func (f *SiteJobFence) Work(ctx context.Context, job *rivertype.JobRow, inner func(context.Context) error) error {
	if serverSnapshotSensitiveJob(job.Kind) {
		connection, err := f.db.Conn(ctx)
		if err != nil {
			return err
		}
		defer connection.Close()
		shared := job.Kind != "server_backup"
		if err = acquireServerSnapshotGate(ctx, connection, shared); err != nil {
			return err
		}
		defer releaseServerSnapshotGate(connection, shared)
	}
	if removalJobClassification[job.Kind] != "target" {
		return inner(ctx)
	}
	var args removalFenceArgs
	if len(job.EncodedArgs) > 16<<20 || json.Unmarshal(job.EncodedArgs, &args) != nil {
		return river.JobCancel(errors.New("invalid scoped job identity"))
	}
	if job.Kind == "maintenance_delete_backup" && args.BackupID > 0 {
		var protected bool
		if err := f.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM site_removal_operations operation
 WHERE operation.state<>'completed' AND operation.snapshot->'backups' @> jsonb_build_array(jsonb_build_object('id',$1::bigint)))`, args.BackupID).Scan(&protected); err != nil {
			return err
		}
		if protected {
			return river.JobCancel(errors.New("backup is reserved as website removal recovery evidence"))
		}
	}
	query, id := removalFenceQuery(job.Kind, args)
	values := []any{id}
	if query == "" {
		return river.JobCancel(errors.New("scoped job identity is unavailable"))
	}
	missing := id == nil
	switch value := id.(type) {
	case int64:
		missing = value <= 0
	case string:
		missing = value == ""
	}
	if missing {
		if args.Domain == "" || query != fenceSiteQuery {
			return river.JobCancel(errors.New("scoped job identity is unavailable"))
		}
		query = `SELECT site.removal_state,site.created_at FROM sites site WHERE site.domain=$1`
		values = []any{args.Domain}
	}
	var state string
	var created time.Time
	err := f.db.QueryRowContext(ctx, query, values...).Scan(&state, &created)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (state != "none" || (!job.CreatedAt.IsZero() && created.After(job.CreatedAt)))) {
		return river.JobCancel(errors.New("scoped resource is missing or website removal has started"))
	}
	if err != nil {
		return err
	}
	return inner(ctx)
}

func removalFenceQuery(kind string, args removalFenceArgs) (string, any) {
	switch kind {
	case "mail_import":
		return `SELECT site.removal_state,site.created_at FROM mail_imports i JOIN mailboxes mb ON mb.id=i.mailbox_id JOIN mail_domains md ON md.id=mb.mail_domain_id JOIN sites site ON site.id=md.site_id WHERE i.id=$1`, args.ImportID
	case "create_site", "issue_cert", "install_custom_cert", "set_hosting_state", "generate_web_statistics", "maintenance_prune_site_backups":
		return fenceSiteQuery, args.SiteID
	case "create_backup", "restore_backup":
		if args.SiteID > 0 {
			return fenceSiteQuery, args.SiteID
		}
		return `SELECT site.removal_state,site.created_at FROM backups backup JOIN sites site ON site.id=backup.site_id WHERE backup.id=$1`, args.BackupID
	case "configure_webmail":
		return `SELECT site.removal_state,site.created_at FROM webmail_hosts host JOIN sites site ON site.id=host.site_id WHERE host.id=$1`, args.WebmailID
	case "configure_dns_zone":
		return `SELECT site.removal_state,site.created_at FROM dns_zones zone JOIN sites site ON site.id=zone.site_id WHERE zone.id=$1`, args.ZoneID
	case "deploy_php_release", "rollback_php_release", "reconcile_php_application", "reconcile_php_workers":
		return `SELECT site.removal_state,site.created_at FROM php_applications app JOIN sites site ON site.id=app.site_id WHERE app.id=$1`, args.ApplicationID
	case "wordpress_operation", "cleanup_wordpress_removal":
		return `SELECT site.removal_state,site.created_at FROM wordpress_instances instance JOIN sites site ON site.id=instance.site_id WHERE instance.id=$1`, args.InstanceID
	case "converge_application":
		return `SELECT site.removal_state,site.created_at FROM application_instances app JOIN sites site ON site.id=app.site_id WHERE app.id=$1`, args.ApplicationID
	case "run_staging_operation":
		var id int64
		_ = json.Unmarshal(args.OperationID, &id)
		return `SELECT CASE WHEN source.removal_state<>'none' OR target.removal_state<>'none' THEN 'removing' ELSE 'none' END,operation.created_at FROM staging_operations operation JOIN sites source ON source.id=operation.source_site_id JOIN sites target ON target.id=operation.target_site_id WHERE operation.id=$1`, id
	case "run_scheduled_task":
		return `SELECT COALESCE(site.removal_state,'none'),task.created_at FROM scheduled_task_runs run JOIN scheduled_tasks task ON task.id=run.task_id LEFT JOIN sites site ON site.id=task.site_id WHERE run.id=$1`, args.RunID
	case "create_database", "system_database_mutation":
		return `SELECT COALESCE(site.removal_state,'none'),database.created_at FROM databases database LEFT JOIN sites site ON site.id=database.site_id WHERE database.id=$1`, args.DatabaseID
	case "maintenance_delete_backup":
		return `SELECT COALESCE(site.removal_state,'none'),backup.created_at FROM backups backup LEFT JOIN sites site ON site.id=backup.site_id WHERE backup.id=$1`, args.BackupID
	}
	return "", nil
}
