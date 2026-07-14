package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

// The mail queue sweep watches Stalwart's outbound backlog per sender domain.
// A tenant pushing past the per-domain rate limit (a compromised site turned
// spam cannon) shows up as deferred queue growth, which raises a deduped
// warning instead of being silently sent.
type MailQueueSweepArgs struct{}

func (MailQueueSweepArgs) Kind() string                 { return "maintenance_mail_queue_sweep" }
func (MailQueueSweepArgs) InsertOpts() river.InsertOpts { return uniqueSweepOpts() }

type MailQueueAgent interface {
	CollectMailQueue(context.Context) (types.Response, error)
}

type MailQueueSweepWorker struct {
	river.WorkerDefaults[MailQueueSweepArgs]
	service *Service
	agent   MailQueueAgent
}

func NewMailQueueSweepWorker(service *Service, agent MailQueueAgent) *MailQueueSweepWorker {
	return &MailQueueSweepWorker{service: service, agent: agent}
}

func (w *MailQueueSweepWorker) Work(ctx context.Context, _ *river.Job[MailQueueSweepArgs]) error {
	return w.service.sweepMailQueue(ctx, w.agent)
}

func (s *Service) sweepMailQueue(ctx context.Context, agent MailQueueAgent) error {
	if s.db == nil || agent == nil {
		return errors.New("mail queue sweep is not configured")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT md.domain,md.subscription_id,sub.customer_id
FROM mail_domains md JOIN subscriptions sub ON sub.id=md.subscription_id
WHERE md.enabled AND NOT md.delete_requested ORDER BY md.domain`)
	if err != nil {
		return err
	}
	type mailTenant struct {
		domain                     string
		subscriptionID, customerID int64
	}
	var tenants []mailTenant
	for rows.Next() {
		var tenant mailTenant
		if err := rows.Scan(&tenant.domain, &tenant.subscriptionID, &tenant.customerID); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, tenant)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(tenants) == 0 {
		return nil
	}
	settings, err := controlquota.ReadMailSettings(ctx, s.db)
	if err != nil {
		return err
	}
	response, err := agent.CollectMailQueue(ctx)
	if err == nil && !response.OK {
		err = errors.New(response.Error)
	}
	if err != nil {
		return fmt.Errorf("collect mail queue: %w", err)
	}
	var queue types.CollectMailQueueResult
	if err := json.Unmarshal(response.Data, &queue); err != nil {
		return err
	}
	actor, err := s.schedulerID(ctx)
	if err != nil {
		return err
	}
	for _, tenant := range tenants {
		backlog := queue.SenderDomains[tenant.domain]
		key := "mail-spike:" + tenant.domain
		if backlog < settings.QueueAlertThreshold {
			if _, err := s.db.ExecContext(ctx, `UPDATE notifications SET resolved_at=now(),updated_at=now() WHERE dedupe_key=$1 AND resolved_at IS NULL`, key); err != nil {
				return err
			}
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		body := fmt.Sprintf("%d outbound messages from %s are queued (alert threshold %d). The per-domain rate limit is throttling them; check the tenant's sites for compromise.", backlog, tenant.domain, settings.QueueAlertThreshold)
		if _, err = tx.ExecContext(ctx, `WITH recipient AS (
SELECT id,login_user_id,reseller_id,email FROM customers WHERE id=$1
), upserted AS (
INSERT INTO notifications(recipient_user_id,customer_id,reseller_id,subscription_id,kind,severity,title,body,dedupe_key)
SELECT login_user_id,id,reseller_id,NULLIF($2,0),'mail_outbound_spike','warning','Outbound mail spike',$3,$4 FROM recipient
ON CONFLICT(dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET body=EXCLUDED.body,updated_at=now()
RETURNING id
)
INSERT INTO notification_deliveries(notification_id,channel,recipient)
SELECT upserted.id,'smtp',recipient.email FROM upserted CROSS JOIN recipient WHERE recipient.email<>''
ON CONFLICT(notification_id,channel,recipient) DO NOTHING`, tenant.customerID, tenant.subscriptionID, body, key); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = s.auditTx(ctx, tx, actor, tenant.customerID, tenant.subscriptionID, "mail.outbound_spike", "mail_domain", 0, map[string]any{"domain": tenant.domain, "queued": backlog}); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
