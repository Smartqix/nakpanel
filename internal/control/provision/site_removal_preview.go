package provision

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"sort"
	"strings"
)

type removalQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *SiteRemovalService) PreviewSiteRemoval(ctx context.Context, actor auth.SessionUser, siteID int64) (types.SiteRemovalPreview, error) {
	if err := s.authorizeSite(ctx, actor, siteID); err != nil {
		return types.SiteRemovalPreview{}, err
	}
	return s.preview(ctx, s.db, siteID)
}

func (s *SiteRemovalService) preview(ctx context.Context, q removalQueryer, siteID int64) (types.SiteRemovalPreview, error) {
	var preview types.SiteRemovalPreview
	var removalState string
	err := q.QueryRowContext(ctx, `SELECT site.id,site.subscription_id,site.customer_id,COALESCE(site.parent_site_id,0),
 COALESCE(sub.primary_site_id,0),site.domain,site.removal_state FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id WHERE site.id=$1`, siteID).
		Scan(&preview.SiteID, &preview.SubscriptionID, &preview.CustomerID, &preview.ParentSiteID, &preview.PrimarySiteID, &preview.Domain, &removalState)
	if errors.Is(err, sql.ErrNoRows) {
		return preview, ErrForbidden
	}
	if err != nil {
		return preview, err
	}
	if preview.ParentSiteID > 0 {
		var validParent bool
		err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sites child JOIN sites parent ON parent.id=child.parent_site_id
 WHERE child.id=$1 AND parent.subscription_id=child.subscription_id AND parent.customer_id=child.customer_id
 AND parent.system_account_id=child.system_account_id AND child.domain LIKE '%.'||parent.domain)`, siteID).Scan(&validParent)
		if err != nil {
			return preview, err
		}
		if !validParent {
			return preview, errors.New("website parent has inconsistent ownership or identity")
		}
	}
	preview.Kind = "website"
	if preview.ParentSiteID > 0 {
		preview.Kind = "subdomain"
	}
	// Content inventory may be stale; require the exact hostname conservatively.
	preview.RequiresHostnameConfirmation = true
	preview.Snapshot.SchemaVersion = 1
	if removalState != "none" {
		preview.BlockedReasons = append(preview.BlockedReasons, "Removal has already started. Open the existing operation.")
		op, loadErr := readRemoval(q.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=(SELECT operation_id FROM site_removal_targets WHERE site_id=$1 AND NOT released)", siteID))
		if loadErr != nil {
			return preview, errors.New("website removal reservation is inconsistent")
		}
		preview.Operation = &op
	}
	rows, err := q.QueryContext(ctx, `WITH RECURSIVE target AS (
 SELECT id,subscription_id,customer_id,parent_site_id,username,domain,php_version,system_account_id,document_root,ARRAY[id] AS path,false AS cycle FROM sites WHERE id=$1
 UNION ALL SELECT child.id,child.subscription_id,child.customer_id,child.parent_site_id,child.username,child.domain,child.php_version,child.system_account_id,child.document_root,
 parent.path||child.id,child.id=ANY(parent.path) FROM sites child JOIN target parent ON child.parent_site_id=parent.id WHERE NOT parent.cycle
 ) SELECT target.id,target.subscription_id,target.customer_id,COALESCE(target.parent_site_id,0),target.username,target.domain,target.php_version,target.cycle,
 target.document_root,COALESCE(account.home_path,''),COALESCE(account.username,'')
 FROM target LEFT JOIN subscription_system_accounts account ON account.id=target.system_account_id AND account.subscription_id=target.subscription_id ORDER BY target.id`, siteID)
	if err != nil {
		return preview, err
	}
	ids := []int64{}
	for rows.Next() {
		var current types.SiteRemovalSite
		var cycle bool
		var documentRoot, accountHome, accountUser string
		if err = rows.Scan(&current.SiteID, &current.SubscriptionID, &current.CustomerID, &current.ParentSiteID, &current.Username, &current.Domain, &current.PHPVersion, &cycle, &documentRoot, &accountHome, &accountUser); err != nil {
			rows.Close()
			return preview, err
		}
		if cycle || current.SubscriptionID != preview.SubscriptionID || current.CustomerID != preview.CustomerID || site.ValidateDomain(current.Domain) != nil || site.NormalizeDomain(current.Domain) != current.Domain {
			rows.Close()
			return preview, errors.New("website descendants have inconsistent ownership or identity")
		}
		ids = append(ids, current.SiteID)
		if current.Username != accountUser || accountHome != "/home/"+accountUser || documentRoot != accountHome+"/domains/"+current.Domain+"/public_html" {
			preview.BlockedReasons = append(preview.BlockedReasons, "This website has a legacy or nonstandard account root. Migrate it before removal.")
		}
		preview.Snapshot.Sites = append(preview.Snapshot.Sites, current)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return preview, err
	}
	for _, current := range preview.Snapshot.Sites {
		if current.SiteID == preview.PrimarySiteID {
			preview.BlockedReasons = append(preview.BlockedReasons, "The subscription primary website cannot be individually removed.")
		}
		if current.SiteID != preview.SiteID && !strings.HasSuffix(current.Domain, "."+preview.Domain) {
			return preview, errors.New("website descendants do not match their parent domain")
		}
	}
	dependencies := []string{s.options.PanelHostname}
	depRows, err := q.QueryContext(ctx, `SELECT mail_hostname FROM mail_settings WHERE id
 UNION SELECT primary_nameserver FROM dns_template_revisions revision JOIN dns_template_state state ON revision.id=state.active_revision_id WHERE state.singleton
 UNION SELECT record.value_template FROM dns_template_records record JOIN dns_template_state state ON record.revision_id=state.active_revision_id
 WHERE state.singleton AND record.record_type='NS' AND record.value_template NOT LIKE '%$%'`)
	if err != nil {
		return preview, err
	}
	for depRows.Next() {
		var host string
		if err = depRows.Scan(&host); err != nil {
			depRows.Close()
			return preview, err
		}
		dependencies = append(dependencies, host)
	}
	err = depRows.Err()
	depRows.Close()
	if err != nil {
		return preview, err
	}
	seen := map[string]bool{}
	for _, dep := range dependencies {
		dep = site.NormalizeDomain(strings.TrimSuffix(dep, "."))
		if dep == "" || site.ValidateDomain(dep) != nil || seen[dep] {
			continue
		}
		seen[dep] = true
		preview.Snapshot.Dependencies = append(preview.Snapshot.Dependencies, dep)
		for _, current := range preview.Snapshot.Sites {
			if current.Domain == dep || strings.HasSuffix(dep, "."+current.Domain) {
				preview.BlockedReasons = append(preview.BlockedReasons, "This website or its DNS zone is required by server services ("+dep+").")
			}
		}
	}
	sort.Strings(preview.Snapshot.Dependencies)
	if err = s.loadRemovalResources(ctx, q, ids, &preview.Snapshot); err != nil {
		return preview, err
	}
	if err = s.loadRemovalData(ctx, q, ids, &preview.Snapshot); err != nil {
		return preview, err
	}
	preview.Allowed = len(preview.BlockedReasons) == 0
	preview.Digest = preview.Snapshot.Digest()
	return preview, nil
}

func (s *SiteRemovalService) loadRemovalResources(ctx context.Context, q removalQueryer, ids []int64, snapshot *types.SiteRemovalSnapshot) error {
	queries := []struct{ kind, query string }{
		{"php_application", "SELECT id,site_id,0,desired_revision,'' FROM php_applications WHERE site_id=ANY($1)"},
		{"php_worker", "SELECT worker.id,app.site_id,app.id,worker.desired_revision,worker.name FROM php_workers worker JOIN php_applications app ON app.id=worker.application_id WHERE app.site_id=ANY($1)"},
		{"php_deployment", "SELECT deployment.id,app.site_id,app.id,0,'' FROM php_deployments deployment JOIN php_applications app ON app.id=deployment.application_id WHERE app.site_id=ANY($1)"},
		{"php_environment", "SELECT binding.id,app.site_id,COALESCE(binding.secret_id,0),binding.desired_revision,binding.name FROM php_environment_bindings binding JOIN php_applications app ON app.id=binding.application_id WHERE app.site_id=ANY($1)"},
		{"wordpress", "SELECT id,site_id,COALESCE(admin_secret_id,0),desired_revision,'' FROM wordpress_instances WHERE site_id=ANY($1)"},
		{"git", "SELECT id,site_id,0,0,'' FROM git_repositories WHERE site_id=ANY($1)"},
		{"git_deployment", "SELECT deployment.id,repo.site_id,repo.id,0,'' FROM git_deployments deployment JOIN git_repositories repo ON repo.id=deployment.repository_id WHERE repo.site_id=ANY($1)"},
		{"application", "SELECT id,site_id,0,desired_revision,name FROM application_instances WHERE site_id=ANY($1)"},
		{"application_generation", "SELECT generation.id,app.site_id,app.id,generation.desired_revision,'' FROM application_generations generation JOIN application_instances app ON app.id=generation.application_id WHERE app.site_id=ANY($1)"},
		{"application_secret", "SELECT binding.secret_id,app.site_id,app.id,0,binding.name FROM application_secret_bindings binding JOIN application_instances app ON app.id=binding.application_id WHERE app.site_id=ANY($1)"},
		{"task", "SELECT id,site_id,0,0,name FROM scheduled_tasks WHERE site_id=ANY($1)"},
		{"staging", "SELECT id,source_site_id,target_site_id,0,direction FROM staging_operations WHERE source_site_id=ANY($1) OR target_site_id=ANY($1)"},
		{"ftp", "SELECT id,site_id,0,0,name FROM ftp_accounts WHERE site_id=ANY($1)"},
		{"sftp_identity", "SELECT identity.id,site.id,identity.subscription_id,0,identity.name FROM sftp_access_identities identity JOIN sites site ON site.subscription_id=identity.subscription_id WHERE site.id=ANY($1) AND (identity.relative_root='domains/'||site.domain OR identity.relative_root LIKE 'domains/'||site.domain||'/%')"},
		{"protected_directory", "SELECT id,site_id,0,0,relative_path FROM protected_directories WHERE site_id=ANY($1)"},
		{"mail_domain", "SELECT domain.id,selected.id,0,0,domain.domain FROM mail_domains domain JOIN sites selected ON selected.id=ANY($1) AND domain.subscription_id=selected.subscription_id AND (domain.site_id=selected.id OR (domain.site_id IS NULL AND domain.domain=selected.domain))"},
		{"mailbox", "SELECT box.id,selected.id,domain.id,0,lower(box.local_part)||'@'||domain.domain FROM mailboxes box JOIN mail_domains domain ON domain.id=box.mail_domain_id JOIN sites selected ON selected.id=ANY($1) AND domain.subscription_id=selected.subscription_id AND (domain.site_id=selected.id OR (domain.site_id IS NULL AND domain.domain=selected.domain))"},
		{"mail_alias", "SELECT alias.id,selected.id,domain.id,0,lower(alias.local_part)||'@'||domain.domain FROM mail_aliases alias JOIN mail_domains domain ON domain.id=alias.mail_domain_id JOIN sites selected ON selected.id=ANY($1) AND domain.subscription_id=selected.subscription_id AND (domain.site_id=selected.id OR (domain.site_id IS NULL AND domain.domain=selected.domain))"},
		{"webmail", "SELECT id,site_id,0,0,hostname FROM webmail_hosts WHERE site_id=ANY($1)"},
		{"dns_zone", "SELECT id,site_id,COALESCE(parent_zone_id,0),COALESCE(desired_revision,0),domain FROM dns_zones WHERE site_id=ANY($1)"},
		{"dns_record", `SELECT DISTINCT record.id,COALESCE(selected.id,record.owner_site_id,zone.site_id),zone.id,0,record.host,
 jsonb_build_array(record.record_type,record.value,record.priority,record.ttl,record.owner_site_id)::text
 FROM dns_records record JOIN dns_zones zone ON zone.id=record.zone_id JOIN sites zone_site ON zone_site.id=zone.site_id
 LEFT JOIN sites selected ON selected.id=ANY($1) AND selected.subscription_id=zone_site.subscription_id
   AND selected.domain LIKE '%.'||zone.domain
   AND record.host=left(selected.domain,length(selected.domain)-length(zone.domain)-1)
 WHERE record.owner_site_id=ANY($1) OR zone.site_id=ANY($1) OR selected.id IS NOT NULL`},
		{"runtime_generation", "SELECT id,site_id,0,generation,'' FROM site_runtime_generations WHERE site_id=ANY($1)"},
		{"statistics", "SELECT site_id,site_id,0,report_generation,'' FROM site_web_statistics WHERE site_id=ANY($1)"},
		{"site_policy", "SELECT site_id,site_id,0,(extract(epoch from updated_at)*1000000)::bigint,'' FROM site_policy_overrides WHERE site_id=ANY($1)"},
	}
	for _, source := range queries {
		rows, err := q.QueryContext(ctx, source.query, pq.Array(ids))
		if err != nil {
			return fmt.Errorf("load %s removal inventory: %w", source.kind, err)
		}
		for rows.Next() {
			var item types.SiteRemovalResource
			item.Kind = source.kind
			fields := []any{&item.ID, &item.SiteID, &item.ParentID, &item.Revision, &item.Name}
			if source.kind == "dns_record" {
				fields = append(fields, &item.IntentDigest)
			}
			if err = rows.Scan(fields...); err != nil {
				rows.Close()
				return err
			}
			if source.kind == "dns_record" {
				item.IntentDigest = fmt.Sprintf("%x", sha256.Sum256([]byte(item.IntentDigest)))
			}
			snapshot.Resources = append(snapshot.Resources, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SiteRemovalService) loadRemovalData(ctx context.Context, q removalQueryer, ids []int64, snapshot *types.SiteRemovalSnapshot) error {
	rows, err := q.QueryContext(ctx, `SELECT db.id,db.site_id,db.subscription_id,db.db_name,db.db_user,
 EXISTS(SELECT 1 FROM databases other WHERE other.db_user=db.db_user AND other.id<>db.id),
 EXISTS(SELECT 1 FROM wordpress_instances wp WHERE wp.database_id=db.id AND NOT wp.database_managed),
 EXISTS(SELECT 1 FROM wordpress_instances wp WHERE wp.database_id=db.id AND wp.database_managed),
 EXISTS(SELECT 1 FROM php_environment_bindings binding JOIN php_applications app ON app.id=binding.application_id
 WHERE app.subscription_id=db.subscription_id AND NOT app.site_id=ANY($1)
 AND (binding.plain_value=db.db_name OR (binding.secret_id IS NOT NULL AND binding.name IN ('DATABASE_URL','DB_DATABASE','DB_NAME')))),
 COALESCE((SELECT backup.id FROM backups backup WHERE backup.subscription_id=db.subscription_id AND backup.status='active'
   AND db.db_name=ANY(backup.database_names) AND backup.checksum_sha256 ~ '^[a-f0-9]{64}$' AND backup.archive_path<>'' ORDER BY backup.created_at DESC LIMIT 1),0)
 FROM databases db WHERE db.site_id=ANY($1) ORDER BY db.id`, pq.Array(ids))
	if err != nil {
		return err
	}
	for rows.Next() {
		var item types.SiteRemovalDatabase
		var shared, external, managed, outsideApplication bool
		if err = rows.Scan(&item.ID, &item.SiteID, &item.SubscriptionID, &item.Name, &item.Principal, &shared, &external, &managed, &outsideApplication, &item.RecoveryBackupID); err != nil {
			rows.Close()
			return err
		}
		item.Provenance = "panel"
		if managed {
			item.Provenance = "wordpress_toolkit"
		}
		if external {
			item.Provenance = "external_wordpress"
		}
		item.DeletionEligible = true
		switch {
		case shared:
			item.IneligibleReason = "This database principal is shared."
		case external:
			item.IneligibleReason = "Externally discovered WordPress data must be retained."
		case outsideApplication:
			item.IneligibleReason = "Another application may reference this database; retain it."
		case managed && item.RecoveryBackupID == 0:
			item.IneligibleReason = "Create a verified recovery backup before deleting this Toolkit database."
		}
		item.DeletionEligible = item.IneligibleReason == ""
		snapshot.Databases = append(snapshot.Databases, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = q.QueryContext(ctx, "SELECT id,site_id,target_name FROM backups WHERE site_id=ANY($1) ORDER BY id", pq.Array(ids))
	if err != nil {
		return err
	}
	for rows.Next() {
		var item types.SiteRemovalResource
		item.Kind = "backup"
		if err = rows.Scan(&item.ID, &item.SiteID, &item.Name); err != nil {
			rows.Close()
			return err
		}
		snapshot.Backups = append(snapshot.Backups, item)
	}
	err = rows.Err()
	rows.Close()
	return err
}
