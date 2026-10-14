package provision

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"slices"
	"time"
)

type SiteRemovalSharedAgent interface {
	controlquota.SubscriptionConvergenceAgent
	AgentDNSClient
	MailAgent
}
type SiteRemovalSharedServices struct {
	db    *sql.DB
	agent SiteRemovalSharedAgent
	mail  *ConfigureMailWorker
}

func NewSiteRemovalSharedServices(db *sql.DB, agent SiteRemovalSharedAgent, secrets *serveradmin.Store) *SiteRemovalSharedServices {
	return &SiteRemovalSharedServices{db: db, agent: agent, mail: NewConfigureMailWorker(db, agent, secrets)}
}
func (s *SiteRemovalSharedServices) SetRiverClient(client *river.Client[*sql.Tx]) {
	s.mail.SetRiverClient(client)
}

func (s *SiteRemovalSharedServices) prepareDNS(ctx context.Context, operation types.SiteRemovalOperation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = controlquota.LockSubscriptionMutationTx(ctx, tx, operation.SubscriptionID); err != nil {
		return err
	}
	current, err := readRemoval(tx.QueryRowContext(ctx, "SELECT "+removalOperationColumns+" FROM site_removal_operations WHERE id=$1 FOR UPDATE", operation.ID))
	if err != nil {
		return err
	}
	if current.Revision != operation.Revision || current.State == "completed" || current.Snapshot.Digest() != operation.Snapshot.Digest() {
		return errors.New("website removal shared intent changed")
	}
	if slices.Contains(current.Checkpoints, "shared-dns-intent") {
		return nil
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('nakpanel.site_removal_operation',$1,true)", fmt.Sprint(operation.ID)); err != nil {
		return err
	}
	selected := map[int64]bool{}
	for _, item := range operation.Snapshot.Sites {
		selected[item.SiteID] = true
	}
	changed := map[int64]bool{}
	for _, resource := range operation.Snapshot.Resources {
		if resource.Kind != "dns_record" {
			continue
		}
		var siteID, serial int64
		var mode, digest string
		err = tx.QueryRowContext(ctx, `SELECT zone.site_id,zone.mode,zone.serial,jsonb_build_array(record.record_type,record.value,record.priority,record.ttl,record.owner_site_id)::text FROM dns_records record JOIN dns_zones zone ON zone.id=record.zone_id WHERE record.id=$1 AND record.zone_id=$2 FOR UPDATE OF record,zone`, resource.ID, resource.ParentID).Scan(&siteID, &mode, &serial, &digest)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256([]byte(digest))) != resource.IntentDigest {
			return errors.New("approved DNS record changed before removal")
		}
		if selected[siteID] || mode != "primary" {
			continue
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM dns_records WHERE id=$1 AND zone_id=$2", resource.ID, resource.ParentID); err != nil {
			return err
		}
		changed[resource.ParentID] = true
	}
	for zoneID := range changed {
		var previous int64
		var format string
		if err = tx.QueryRowContext(ctx, `SELECT zone.serial,COALESCE(zone.soa_override->>'serial_format',revision.serial_format,'unix') FROM dns_zones zone JOIN dns_template_revisions revision ON revision.revision=zone.template_revision WHERE zone.id=$1 FOR UPDATE OF zone`, zoneID).Scan(&previous, &format); err != nil {
			return err
		}
		serial, err := nextProvisionDNSSerial(time.Now().UTC(), previous, format)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE dns_zones SET serial=$2,desired_revision=desired_revision+1,status='pending',last_error='',updated_at=now() WHERE id=$1`, zoneID, serial); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE site_removal_operations SET checkpoints=array_append(checkpoints,'shared-dns-intent'),updated_at=now() WHERE id=$1`, operation.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SiteRemovalSharedServices) Converge(ctx context.Context, operation types.SiteRemovalOperation) (types.TeardownSiteResult, error) {
	result := types.TeardownSiteResult{OperationID: operation.ID, Revision: operation.Revision}
	if s == nil || s.db == nil || s.agent == nil {
		return result, errors.New("shared website services are not configured")
	}
	if err := s.prepareDNS(ctx, operation); err != nil {
		return result, err
	}
	selected := []int64{}
	for _, item := range operation.Snapshot.Sites {
		selected = append(selected, item.SiteID)
	}
	zones := map[int64]bool{}
	for _, resource := range operation.Snapshot.Resources {
		if resource.Kind == "dns_record" {
			zones[resource.ParentID] = true
		}
	}
	for id := range zones {
		var siteID int64
		var mode string
		if err := s.db.QueryRowContext(ctx, "SELECT site_id,mode FROM dns_zones WHERE id=$1", id).Scan(&siteID, &mode); err != nil {
			return result, err
		}
		if slices.Contains(selected, siteID) || mode != "primary" {
			continue
		}
		req, err := LoadDNSZoneRequest(ctx, s.db, id)
		if err != nil {
			return result, err
		}
		req.SiteID = siteID
		resp, err := s.agent.ConfigureDNSZone(ctx, req)
		if err != nil {
			return result, err
		}
		var applied types.ConfigureDNSZoneResult
		if err = decodeAgentResult(resp, &applied); err != nil {
			return result, err
		}
		update, err := s.db.ExecContext(ctx, `UPDATE dns_zones SET status='active',applied_revision=$2,last_error='',updated_at=now() WHERE id=$1 AND desired_revision=$2`, id, req.DesiredRevision)
		if err != nil {
			return result, err
		}
		count, err := update.RowsAffected()
		if err != nil || count != 1 {
			return result, errors.New("DNS intent changed during removal convergence")
		}
		result.Checkpoints = append(result.Checkpoints, fmt.Sprintf("parent-dns:%d:%d", id, req.DesiredRevision))
	}
	if err := controlquota.ConvergeRemovalAccess(ctx, s.db, s.agent, operation.SubscriptionID); err != nil {
		return result, err
	}
	if err := s.mail.Work(ctx, &river.Job[controlquota.ConfigureMailArgs]{Args: controlquota.NewConfigureMailArgs()}); err != nil {
		return result, err
	}
	result.Checkpoints = append(result.Checkpoints, "surviving-access", "surviving-mail")
	return result, nil
}

// Kept records and unrelated rows never acquire a broader deletion scope.
func removalSelectedSites(snapshot types.SiteRemovalSnapshot) []int64 {
	ids := []int64{}
	for _, item := range snapshot.Sites {
		ids = append(ids, item.SiteID)
	}
	return ids
}
