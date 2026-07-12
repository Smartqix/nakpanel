package workspace

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

var ErrNotFound = errors.New("workspace object not found")

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) CanManageSubscription(ctx context.Context, actor auth.SessionUser, subscriptionID int64) (bool, error) {
	if actor.Role == auth.RoleAdmin {
		return true, nil
	}
	if (actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller) || subscriptionID <= 0 {
		return false, nil
	}
	return s.exists(ctx, `SELECT EXISTS (
SELECT 1 FROM subscriptions sub
JOIN customers c ON c.id = sub.customer_id
LEFT JOIN reseller_accounts r ON r.id=c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active'
WHERE sub.id = $1
AND (( $3::text='client' AND c.login_user_id=$2) OR ($3::text='reseller' AND r.login_user_id=$2 AND r.status='active' AND rs.id IS NOT NULL))
)`, subscriptionID, actor.ID, string(actor.Role))
}

func (s *Store) CanManageDomain(ctx context.Context, actor auth.SessionUser, domain string) (bool, error) {
	if actor.Role == auth.RoleAdmin {
		return true, nil
	}
	if actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller {
		return false, nil
	}
	return s.exists(ctx, `SELECT EXISTS (
SELECT 1 FROM sites r
JOIN subscriptions sub ON sub.id = r.subscription_id
JOIN customers c ON c.id = sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE r.domain = $1 AND r.status <> 'failed' AND sub.status = 'active' AND c.status = 'active'
AND (($3::text='client' AND c.login_user_id=$2) OR ($3::text='reseller' AND ra.login_user_id=$2 AND ra.status='active' AND rs.id IS NOT NULL))
)`, strings.ToLower(strings.TrimSpace(domain)), actor.ID, string(actor.Role))
}

func (s *Store) CanManageDNS(ctx context.Context, actor auth.SessionUser, domain string) (bool, error) {
	if actor.Role == auth.RoleAdmin {
		return s.exists(ctx, `SELECT EXISTS (
SELECT 1 FROM sites r
JOIN subscriptions sub ON sub.id=r.subscription_id
JOIN customers c ON c.id=sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE r.domain=$1 AND r.status<>'failed' AND sub.status='active' AND c.status='active'
AND (c.reseller_id IS NULL OR (ra.status='active' AND rs.id IS NOT NULL))
)`, strings.ToLower(strings.TrimSpace(domain)))
	}
	if actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller {
		return false, nil
	}
	return s.exists(ctx, `SELECT EXISTS (
SELECT 1 FROM sites r
JOIN subscriptions sub ON sub.id = r.subscription_id
JOIN subscription_entitlements e ON e.subscription_id = sub.id
JOIN customers c ON c.id = sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE r.domain = $1 AND r.status <> 'failed' AND sub.status = 'active' AND e.allow_dns = TRUE AND c.status = 'active'
AND (($3::text='client' AND c.login_user_id=$2) OR ($3::text='reseller' AND ra.login_user_id=$2 AND ra.status='active' AND rs.id IS NOT NULL))
)`, strings.ToLower(strings.TrimSpace(domain)), actor.ID, string(actor.Role))
}

func (s *Store) CanManagePHP(ctx context.Context, actor auth.SessionUser, domain string) (bool, error) {
	return s.canManageDomainCapability(ctx, actor, domain, "allow_php_settings")
}

func (s *Store) CanManageTLS(ctx context.Context, actor auth.SessionUser, domain string) (bool, error) {
	return s.canManageDomainCapability(ctx, actor, domain, "allow_tls")
}

func (s *Store) canManageDomainCapability(ctx context.Context, actor auth.SessionUser, domain, capability string) (bool, error) {
	if actor.Role == auth.RoleAdmin {
		return true, nil
	}
	if actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller {
		return false, nil
	}
	column := map[string]string{"allow_php_settings": "e.allow_php_settings", "allow_tls": "e.allow_tls"}[capability]
	if column == "" {
		return false, nil
	}
	return s.exists(ctx, `SELECT EXISTS (
SELECT 1 FROM sites r
JOIN subscriptions sub ON sub.id=r.subscription_id
JOIN subscription_entitlements e ON e.subscription_id=sub.id
JOIN customers c ON c.id=sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE r.domain=$1 AND r.status<>'failed' AND sub.status='active' AND c.status='active' AND `+column+`=TRUE
AND (($3::text='client' AND c.login_user_id=$2) OR ($3::text='reseller' AND ra.login_user_id=$2 AND ra.status='active' AND rs.id IS NOT NULL))
)`, strings.ToLower(strings.TrimSpace(domain)), actor.ID, string(actor.Role))
}

func (s *Store) CanManageBackup(ctx context.Context, actor auth.SessionUser, backupID int64) (bool, error) {
	if actor.Role == auth.RoleAdmin {
		return true, nil
	}
	if (actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller) || backupID <= 0 {
		return false, nil
	}
	return s.exists(ctx, `SELECT EXISTS (
SELECT 1 FROM backups b
JOIN subscriptions sub ON sub.id = b.subscription_id
JOIN subscription_entitlements e ON e.subscription_id=sub.id
JOIN customers c ON c.id = sub.customer_id
LEFT JOIN reseller_accounts ra ON ra.id=c.reseller_id
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=ra.id AND rs.status='active'
WHERE b.id = $1 AND sub.status = 'active' AND e.allow_backups=TRUE AND c.status = 'active'
AND (($3::text='client' AND c.login_user_id=$2) OR ($3::text='reseller' AND ra.login_user_id=$2 AND ra.status='active' AND rs.id IS NOT NULL))
)`, backupID, actor.ID, string(actor.Role))
}

func (s *Store) CanManageCustomer(ctx context.Context, actor auth.SessionUser, customerID int64) (bool, error) {
	if actor.Role == auth.RoleAdmin {
		return true, nil
	}
	if actor.Role != auth.RoleReseller || customerID <= 0 {
		return false, nil
	}
	return s.exists(ctx, `SELECT EXISTS(SELECT 1 FROM customers c JOIN reseller_accounts r ON r.id=c.reseller_id JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active' WHERE c.id=$1 AND r.login_user_id=$2 AND r.status='active')`, customerID, actor.ID)
}

func (s *Store) CanManagePlan(ctx context.Context, actor auth.SessionUser, planID int64) (bool, error) {
	if actor.Role == auth.RoleAdmin {
		return true, nil
	}
	if actor.Role != auth.RoleReseller || planID <= 0 {
		return false, nil
	}
	return s.exists(ctx, `SELECT EXISTS(SELECT 1 FROM plans p JOIN reseller_accounts r ON r.id=p.reseller_id JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active' WHERE p.id=$1 AND r.login_user_id=$2 AND r.status='active')`, planID, actor.ID)
}

func (s *Store) exists(ctx context.Context, query string, args ...any) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("workspace database is not configured")
	}
	var ok bool
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func (s *Store) ListSitesForUser(ctx context.Context, userID int64) ([]dashboard.Site, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.username, r.domain, r.php_version, r.status, r.last_error,
	       r.tls_status, r.tls_issuer, r.tls_expires_at, r.tls_last_error, r.tls_cert_path, r.tls_key_path,
	       COALESCE(r.subscription_id, 0), COALESCE(r.customer_id, 0), r.desired_status, r.desired_php_version,
	       r.https_redirect, r.desired_https_redirect, r.settings_status, r.settings_error
FROM sites r JOIN customers c ON c.id = r.customer_id
WHERE c.login_user_id = $1 OR c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY r.domain`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dashboard.Site
	for rows.Next() {
		var item dashboard.Site
		var expires sql.NullTime
		if err := rows.Scan(&item.ID, &item.Username, &item.Domain, &item.PHPVersion, &item.Status, &item.LastError,
			&item.TLSStatus, &item.TLSIssuer, &expires, &item.TLSLastError, &item.TLSCertPath, &item.TLSKeyPath,
			&item.SubscriptionID, &item.CustomerID, &item.DesiredStatus, &item.DesiredPHPVersion,
			&item.HTTPSRedirect, &item.DesiredHTTPSRedirect, &item.SettingsStatus, &item.SettingsError); err != nil {
			return nil, err
		}
		item.TLSExpiresAt = dashboard.NullableTime{Time: expires.Time, Valid: expires.Valid}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListDatabasesForUser(ctx context.Context, userID int64) ([]dashboard.Database, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.engine, r.db_name, r.db_user, r.status, r.last_error,
	       COALESCE(r.subscription_id, 0), COALESCE(r.customer_id, 0), COALESCE(r.site_id,0)
FROM databases r JOIN customers c ON c.id = r.customer_id
WHERE c.login_user_id = $1 OR c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY r.db_name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dashboard.Database
	for rows.Next() {
		var item dashboard.Database
		if err := rows.Scan(&item.ID, &item.Engine, &item.Name, &item.User, &item.Status, &item.LastError, &item.SubscriptionID, &item.CustomerID, &item.SiteID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) GetPhase6ForUser(ctx context.Context, userID int64) (dashboard.Phase6Data, error) {
	data := dashboard.Phase6Data{}
	rows, err := s.db.QueryContext(ctx, `SELECT b.id, b.target_name, b.status, b.archive_path, b.size_bytes, b.last_error, b.created_at, COALESCE(b.site_id,0), COALESCE(b.subscription_id,0)
FROM backups b JOIN customers c ON c.id = b.customer_id WHERE c.login_user_id = $1 OR c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY b.created_at DESC LIMIT 50`, userID)
	if err != nil {
		return data, err
	}
	for rows.Next() {
		var b dashboard.Backup
		if err := rows.Scan(&b.ID, &b.TargetName, &b.Status, &b.ArchivePath, &b.SizeBytes, &b.LastError, &b.CreatedAt, &b.SiteID, &b.SubscriptionID); err != nil {
			rows.Close()
			return data, err
		}
		data.Backups = append(data.Backups, b)
	}
	if err := rows.Close(); err != nil {
		return data, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT z.id,z.domain,z.address,z.serial,z.status,z.zone_path,z.last_error,z.created_at,z.site_id
FROM dns_zones z JOIN sites r ON r.id=z.site_id JOIN customers c ON c.id=r.customer_id WHERE c.login_user_id=$1 OR c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY z.created_at DESC LIMIT 50`, userID)
	if err != nil {
		return data, err
	}
	defer rows.Close()
	for rows.Next() {
		var z dashboard.DNSZone
		if err := rows.Scan(&z.ID, &z.Domain, &z.Address, &z.Serial, &z.Status, &z.ZonePath, &z.LastError, &z.CreatedAt, &z.SiteID); err != nil {
			return data, err
		}
		data.DNSZones = append(data.DNSZones, z)
	}
	if err := rows.Err(); err != nil {
		return data, err
	}
	if err := rows.Close(); err != nil {
		return data, err
	}
	recordRows, err := s.db.QueryContext(ctx, `SELECT dr.id,dr.zone_id,dr.host,dr.record_type,dr.value,COALESCE(dr.priority,0),dr.ttl
FROM dns_records dr JOIN dns_zones z ON z.id=dr.zone_id JOIN sites r ON r.id=z.site_id JOIN customers c ON c.id=r.customer_id
WHERE c.login_user_id=$1 OR c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1)
ORDER BY dr.zone_id,dr.host,dr.record_type,dr.id`, userID)
	if err != nil {
		return data, err
	}
	defer recordRows.Close()
	for recordRows.Next() {
		var record types.DNSRecord
		if err := recordRows.Scan(&record.ID, &record.ZoneID, &record.Host, &record.Type, &record.Value, &record.Priority, &record.TTL); err != nil {
			return data, err
		}
		data.DNSRecords = append(data.DNSRecords, record)
	}
	return data, recordRows.Err()
}

func (s *Store) Search(ctx context.Context, actor auth.SessionUser, query string, limit int) ([]types.SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return []types.SearchResult{}, nil
	}
	if limit <= 0 || limit > 20 {
		limit = 8
	}
	rows, err := s.db.QueryContext(ctx, `
WITH visible_customers AS (
  SELECT c.id FROM customers c WHERE $2::text = 'admin' OR c.login_user_id = $3
  OR ($2::text='reseller' AND c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$3))
), results AS (
  SELECT 'site'::text kind, r.id, r.domain label, r.status detail, '/sites/' || r.id url, 1 rank
  FROM sites r WHERE r.customer_id IN (SELECT id FROM visible_customers) AND r.domain ILIKE '%' || $1 || '%'
  UNION ALL
  SELECT 'database', d.id, d.db_name, d.engine || ' / ' || d.status, '/databases?focus=' || d.id, 2
  FROM databases d WHERE d.customer_id IN (SELECT id FROM visible_customers) AND d.db_name ILIKE '%' || $1 || '%'
  UNION ALL
  SELECT 'subscription', sub.id, COALESCE(NULLIF(sub.name,''),'Subscription ' || sub.id), e.plan_name, '/subscriptions/' || sub.id, 3
  FROM subscriptions sub JOIN subscription_entitlements e ON e.subscription_id=sub.id WHERE sub.customer_id IN (SELECT id FROM visible_customers) AND (sub.name ILIKE '%' || $1 || '%' OR e.plan_name ILIKE '%' || $1 || '%')
  UNION ALL
  SELECT 'customer', c.id, COALESCE(NULLIF(c.display_name,''),c.email), c.email, '/customers/' || c.id, 4
  FROM customers c WHERE ($2::text = 'admin' OR ($2::text='reseller' AND c.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$3))) AND (c.email ILIKE '%' || $1 || '%' OR c.display_name ILIKE '%' || $1 || '%')
)
SELECT kind,id,label,detail,url FROM results ORDER BY rank,label LIMIT $4`, query, string(actor.Role), actor.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []types.SearchResult
	for rows.Next() {
		var item types.SearchResult
		if err := rows.Scan(&item.Kind, &item.ID, &item.Label, &item.Detail, &item.URL); err != nil {
			return nil, err
		}
		results = append(results, item)
	}
	return results, rows.Err()
}

func (s *Store) RecordAudit(ctx context.Context, event types.AuditEvent) error {
	if event.Metadata == nil {
		event.Metadata = json.RawMessage(`{}`)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
VALUES($1,NULLIF($2,0),NULLIF($3,0),$4,$5,NULLIF($6,0),$7)`, event.ActorUserID, event.CustomerID, event.SubscriptionID, event.Action, event.TargetType, event.TargetID, event.Metadata)
	return err
}

func (s *Store) ListAudit(ctx context.Context, actor auth.SessionUser, limit int) ([]types.AuditEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if actor.Role != auth.RoleAdmin {
		return []types.AuditEvent{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.id,e.actor_user_id,u.email,COALESCE(e.customer_id,0),COALESCE(e.subscription_id,0),e.action,e.target_type,COALESCE(e.target_id,0),e.metadata,e.created_at
FROM audit_events e JOIN users u ON u.id=e.actor_user_id ORDER BY e.created_at DESC,e.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.AuditEvent
	for rows.Next() {
		var e types.AuditEvent
		if err := rows.Scan(&e.ID, &e.ActorUserID, &e.ActorEmail, &e.CustomerID, &e.SubscriptionID, &e.Action, &e.TargetType, &e.TargetID, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CustomerIDForSubscription(ctx context.Context, subscriptionID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT customer_id FROM subscriptions WHERE id=$1`, subscriptionID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) CustomerIDForDomain(ctx context.Context, domain string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT customer_id FROM sites WHERE domain=$1`, strings.ToLower(strings.TrimSpace(domain))).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) CustomerIDForBackup(ctx context.Context, backupID int64) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT customer_id FROM backups WHERE id=$1`, backupID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) String() string { return fmt.Sprintf("workspace.Store(%p)", s.db) }
