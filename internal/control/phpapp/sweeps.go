package phpapp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type SweepPHPApplicationsWorker struct {
	river.WorkerDefaults[SweepPHPApplicationsArgs]
	store *SQLStore
}

const sweepApplicationCandidatesSQL = `SELECT application.id,application.desired_revision
FROM php_applications application
JOIN sites site ON site.id=application.site_id
JOIN subscriptions subscription ON subscription.id=application.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
WHERE application.convergence_status<>'in_sync' OR application.applied_revision<application.desired_revision
 OR (application.observed_state='suspended' AND application.desired_state='active' AND site.desired_status='active'
     AND subscription.status='active' AND customer.status='active'
     AND (customer.reseller_id IS NULL OR EXISTS (
         SELECT 1 FROM reseller_accounts reseller JOIN reseller_subscriptions allocation ON allocation.reseller_id=reseller.id
         WHERE reseller.id=customer.reseller_id AND reseller.status='active' AND allocation.status='active')))
 OR (application.observed_state<>'suspended' AND (application.desired_state='suspended' OR site.desired_status<>'active'
     OR subscription.status<>'active' OR customer.status<>'active' OR (customer.reseller_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM reseller_accounts reseller JOIN reseller_subscriptions allocation ON allocation.reseller_id=reseller.id
         WHERE reseller.id=customer.reseller_id AND reseller.status='active' AND allocation.status='active'))))
ORDER BY application.updated_at,application.id LIMIT 100 FOR UPDATE OF application SKIP LOCKED`

const sweepWorkerCandidatesSQL = `SELECT application.id,application.desired_revision
FROM php_applications application
WHERE EXISTS (SELECT 1 FROM php_workers worker WHERE worker.application_id=application.id
 AND (worker.convergence_status<>'in_sync' OR worker.applied_revision<worker.desired_revision))
ORDER BY application.id LIMIT 100 FOR UPDATE OF application SKIP LOCKED`

func NewSweepPHPApplicationsWorker(store *SQLStore) *SweepPHPApplicationsWorker {
	return &SweepPHPApplicationsWorker{store: store}
}

func (w *SweepPHPApplicationsWorker) Work(ctx context.Context, _ *river.Job[SweepPHPApplicationsArgs]) error {
	if w == nil || w.store == nil || w.store.db == nil || w.store.river == nil {
		return errors.New("PHP application sweep is unavailable")
	}
	tx, err := w.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, sweepApplicationCandidatesSQL)
	if err != nil {
		return err
	}
	type candidate struct{ id, revision int64 }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.revision); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, candidate := range candidates {
		if _, err = w.store.river.InsertTx(ctx, tx, ReconcilePHPApplicationArgs{ApplicationID: candidate.id, DesiredRevision: candidate.revision}, nil); err != nil {
			return err
		}
	}
	workerRows, err := tx.QueryContext(ctx, sweepWorkerCandidatesSQL)
	if err != nil {
		return err
	}
	defer workerRows.Close()
	for workerRows.Next() {
		var applicationID, revision int64
		if err := workerRows.Scan(&applicationID, &revision); err != nil {
			return err
		}
		if _, err = w.store.river.InsertTx(ctx, tx, ReconcilePHPWorkersArgs{ApplicationID: applicationID, DesiredRevision: revision}, nil); err != nil {
			return err
		}
	}
	if err := workerRows.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

type SweepPHPRuntimesWorker struct {
	river.WorkerDefaults[SweepPHPRuntimesArgs]
	store        *SQLStore
	capabilities CapabilityReader
}

func NewSweepPHPRuntimesWorker(store *SQLStore, capabilities CapabilityReader) *SweepPHPRuntimesWorker {
	return &SweepPHPRuntimesWorker{store: store, capabilities: capabilities}
}

func (w *SweepPHPRuntimesWorker) Work(ctx context.Context, _ *river.Job[SweepPHPRuntimesArgs]) error {
	if w == nil || w.store == nil || w.store.db == nil || w.capabilities == nil {
		return errors.New("PHP runtime sweep is unavailable")
	}
	inventory, err := w.capabilities.RuntimeCapabilities(ctx)
	if err != nil {
		return err
	}
	byVersion := make(map[string]types.PHPRuntimeCapability, len(inventory.PHPRuntimes))
	for _, runtime := range inventory.PHPRuntimes {
		byVersion[runtime.Version] = runtime
	}
	rows, err := w.store.db.QueryContext(ctx, `SELECT DISTINCT application.subscription_id,subscription.customer_id,application.php_version
FROM php_applications application JOIN subscriptions subscription ON subscription.id=application.subscription_id
ORDER BY application.subscription_id,application.php_version`)
	if err != nil {
		return err
	}
	type target struct {
		subscriptionID, customerID int64
		version                    string
	}
	var targets []target
	for rows.Next() {
		var item target
		if err := rows.Scan(&item.subscriptionID, &item.customerID, &item.version); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	tx, err := w.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, target := range targets {
		runtime, exists := byVersion[target.version]
		key := fmt.Sprintf("php:runtime:%d:%s", target.subscriptionID, target.version)
		if !exists || !runtime.Ready {
			body := fmt.Sprintf("PHP %s is not ready on this server.", target.version)
			if exists && len(runtime.ValidationErrors) > 0 {
				body += " " + strings.Join(runtime.ValidationErrors, "; ")
			}
			if err := upsertNotificationTx(ctx, tx, target.subscriptionID, target.customerID, "php_runtime_unsupported", "critical", "PHP runtime unavailable", safeMessage(body), key); err != nil {
				return err
			}
			continue
		}
		if runtime.SupportStatus == types.PHPSupportUnsupported || runtime.SupportStatus == types.PHPSupportSecuritySupported {
			severity, title := "critical", "PHP runtime is end of support"
			if runtime.SupportStatus == types.PHPSupportSecuritySupported {
				severity, title = "warning", "PHP runtime is in security support"
			}
			if err := upsertNotificationTx(ctx, tx, target.subscriptionID, target.customerID, "php_runtime_unsupported", severity, title,
				fmt.Sprintf("PHP %s support status is %s. Plan an upgrade.", target.version, runtime.SupportStatus), key); err != nil {
				return err
			}
			continue
		}
		if err := resolveNotificationTx(ctx, tx, key); err != nil {
			return err
		}
	}
	return tx.Commit()
}
