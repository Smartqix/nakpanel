package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/agentclient"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlfiles "github.com/nakroteck/nakpanel/internal/control/filemanager"
	panelhttp "github.com/nakroteck/nakpanel/internal/control/http"
	controlmaintenance "github.com/nakroteck/nakpanel/internal/control/maintenance"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/control/provisioningapi"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/store"
	paneltls "github.com/nakroteck/nakpanel/internal/control/tls"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/robfig/cron/v3"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.PanelRuntimeConfigFromEnv()
	webhookConfig := provisioningapi.WebhookConfig{URL: cfg.BillingWebhookURL, Secret: cfg.BillingWebhookSecret}
	if err := webhookConfig.Validate(); err != nil {
		log.Fatalf("billing webhook configuration: %v", err)
	}

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("ping database: %v", err)
	}

	queries := store.New(db)
	authStore := store.NewAuthStore(queries)
	sessionManager := auth.NewSessionManager(authStore, auth.SessionOptions{})

	riverClient, err := newRiverClient(db, queries, cfg)
	if err != nil {
		log.Fatalf("create river client: %v", err)
	}
	if err := riverClient.Start(ctx); err != nil {
		log.Fatalf("start river client: %v", err)
	}
	defer func() {
		if err := riverClient.Stop(context.Background()); err != nil {
			log.Printf("stop river client: %v", err)
		}
	}()

	siteRepo := provision.NewSQLSiteRepository(db, queries, riverClient)
	databaseRepo := provision.NewSQLDatabaseRepository(db, queries, riverClient)
	phase6Repo := provision.NewSQLPhase6Repository(db, riverClient)
	quotaStore := controlquota.NewSQLStore(db, riverClient)
	workspaceStore := workspace.NewStore(db)
	fileManager := controlfiles.NewManager(controlfiles.ManagerOptions{
		Store: controlfiles.NewSQLStore(db), Access: workspaceStore, Agent: agentclient.New(config.AgentSocket),
		TransferDir: cfg.FileTransferDir, UploadMaxBytes: cfg.FileUploadMaxBytes,
	})
	if err := os.MkdirAll(cfg.FileTransferDir, 0o700); err != nil {
		log.Fatalf("create file transfer directory: %v", err)
	}
	if err := fileManager.SweepTransfers(time.Hour); err != nil {
		log.Printf("sweep stale file transfers: %v", err)
	}
	agentCapabilities := agentclient.New(config.AgentSocket)
	dashboardStore := dashboard.NewStore(
		dashboardQuerier{queries: queries},
		dashboard.WithJobReader(dashboard.NewSQLJobStore(db)),
		dashboard.WithPhase6Reader(dashboard.NewSQLPhase6Store(db)),
		dashboard.WithQuotaReader(quotaStore),
		dashboard.WithScopedReader(workspaceStore),
		dashboard.WithAuditReader(workspaceStore),
		dashboard.WithCapabilityReader(agentCapabilities),
	)
	siteManager := provision.NewManager(
		siteRepo,
		provision.WithDatabaseRepository(databaseRepo),
		provision.WithCertificateRepository(siteRepo),
		provision.WithCustomCertificateRepository(siteRepo),
		provision.WithCustomCertificateStager(&provision.FileCustomCertificateStager{Dir: provision.DefaultCustomTLSStagingDir}),
		provision.WithPhase6Repository(phase6Repo),
		provision.WithQuotaStore(quotaStore),
		provision.WithAccessPolicy(workspaceStore),
		provision.WithRuntimeCapabilities(agentCapabilities),
		provision.WithMailAgent(agentCapabilities),
	)
	if err := provision.SweepCustomTLSStagingForJobs(ctx, db, provision.DefaultCustomTLSStagingDir, 24*time.Hour); err != nil {
		log.Printf("sweep stale custom TLS staging files: %v", err)
	}
	go sweepCustomTLSStaging(ctx, db)
	jobRetrier := provision.NewSQLJobRetrier(db)
	uiHandler := panelhttp.NewServer(authStore, sessionManager, panelhttp.ServerOptions{
		SiteCreator:                siteManager,
		DatabaseCreator:            siteManager,
		CertificateIssuer:          siteManager,
		CustomCertificateInstaller: siteManager,
		DashboardReader:            dashboardStore,
		JobRetrier:                 jobRetrier,
		Phase6Manager:              siteManager,
		QuotaManager:               siteManager,
		Workspace:                  workspaceStore,
		DomainManager:              siteManager,
		FileManager:                fileManager,
		MailManager:                siteManager,
	}).Handler()
	accountService := &provisioningapi.AccountService{DB: db, River: riverClient, PublicURL: cfg.PublicURL, Quota: quotaStore}
	apiHandler := provisioningapi.NewHandler(provisioningapi.HandlerOptions{
		DB: db, PanelVersion: "phase20", PublicURL: cfg.PublicURL, Sessions: sessionManager, Accounts: accountService,
	})
	handler := provisioningapi.NewRootHandler(provisioningapi.RootOptions{API: apiHandler, UI: uiHandler, DB: db, Sessions: sessionManager})

	certFile, keyFile, err := paneltls.EnsureSelfSigned(cfg.TLSDir)
	if err != nil {
		log.Fatalf("ensure panel TLS certificate: %v", err)
	}

	server := newHTTPServer(cfg, handler)
	go func() {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("shutdown panel HTTPS server: %v", err)
		}
	}()

	log.Printf("nakpanel panel listening on https://0.0.0.0%s", cfg.HTTPSAddr)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve panel HTTPS: %v", err)
	}
}

type dashboardQuerier struct{ queries *store.Queries }

func (q dashboardQuerier) ListSites(ctx context.Context) ([]store.Site, error) {
	rows, err := q.queries.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]store.Site, 0, len(rows))
	for _, row := range rows {
		items = append(items, store.Site{
			ID: row.ID, OwnerUserID: row.OwnerUserID, Username: row.Username, Domain: row.Domain,
			PhpVersion: row.PhpVersion, Status: row.Status, LastError: row.LastError,
			CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, TlsStatus: row.TlsStatus,
			TlsIssuer: row.TlsIssuer, TlsCertPath: row.TlsCertPath, TlsKeyPath: row.TlsKeyPath,
			TlsExpiresAt: row.TlsExpiresAt, TlsLastError: row.TlsLastError,
			SubscriptionID: row.SubscriptionID, CustomerID: row.CustomerID,
			DesiredStatus: row.DesiredStatus, DesiredPhpVersion: row.DesiredPhpVersion,
			HttpsRedirect: row.HttpsRedirect, DesiredHttpsRedirect: row.DesiredHttpsRedirect,
			SettingsStatus: row.SettingsStatus, SettingsError: row.SettingsError, TlsAutoRenew: row.TlsAutoRenew,
			SystemAccountID: row.SystemAccountID, DocumentRoot: row.DocumentRoot,
		})
	}
	return items, nil
}

func (q dashboardQuerier) ListDatabases(ctx context.Context) ([]store.Database, error) {
	return q.queries.ListDatabases(ctx)
}

func newRiverClient(db *sql.DB, queries *store.Queries, configs ...config.PanelRuntimeConfig) (*river.Client[*sql.Tx], error) {
	workers := river.NewWorkers()
	agent := agentclient.New(config.AgentSocket)
	var runtimeConfig config.PanelRuntimeConfig
	if len(configs) > 0 {
		runtimeConfig = configs[0]
	}
	siteStatus := provision.NewSQLSiteStatusStore(queries)
	databaseStatus := provision.NewSQLDatabaseStatusStore(db, queries)
	phase6Status := provision.NewSQLPhase6StatusStore(db)
	maintenanceService := controlmaintenance.NewService(db, nil, agent)
	river.AddWorker(workers, provision.NewCreateSiteWorker(agent, siteStatus))
	river.AddWorker(workers, provision.NewCreateDatabaseWorker(agent, databaseStatus))
	river.AddWorker(workers, provision.NewIssueCertWorker(agent, siteStatus, maintenanceService))
	river.AddWorker(workers, provision.NewInstallCustomCertWorker(agent, siteStatus))
	river.AddWorker(workers, provision.NewCreateBackupWorker(agent, phase6Status, maintenanceService))
	river.AddWorker(workers, provision.NewRestoreBackupWorker(agent, phase6Status))
	river.AddWorker(workers, provision.NewConfigureWebmailWorker(agent, phase6Status))
	river.AddWorker(workers, provision.NewConfigureDNSZoneWorker(agent, phase6Status))
	river.AddWorker(workers, provision.NewReconcileSystemWorker(agent, phase6Status, maintenanceService))
	river.AddWorker(workers, controlmaintenance.NewRenewCertsWorker(maintenanceService))
	river.AddWorker(workers, controlmaintenance.NewScheduledBackupsWorker(maintenanceService))
	river.AddWorker(workers, controlmaintenance.NewPruneBackupsWorker(maintenanceService))
	river.AddWorker(workers, controlmaintenance.NewPruneSiteWorker(maintenanceService))
	river.AddWorker(workers, controlmaintenance.NewDeleteBackupWorker(maintenanceService))
	river.AddWorker(workers, controlmaintenance.NewReconcileWorker(maintenanceService))
	river.AddWorker(workers, controlmaintenance.NewMailQueueSweepWorker(maintenanceService, agent))
	river.AddWorker(workers, controlquota.NewSetHostingStateWorker(agent, db))
	river.AddWorker(workers, controlquota.NewSyncPlanWorker(db))
	river.AddWorker(workers, controlquota.NewSyncAddonWorker(db))
	convergenceWorker := controlquota.NewConvergeSubscriptionWorker(db, agent)
	river.AddWorker(workers, convergenceWorker)
	configureMailWorker := provision.NewConfigureMailWorker(db, agent)
	river.AddWorker(workers, configureMailWorker)
	river.AddWorker(workers, controlquota.NewConvergeApplicationWorker(db, agent))
	pendingConvergenceWorker := controlquota.NewConvergePendingSubscriptionsWorker(db)
	river.AddWorker(workers, pendingConvergenceWorker)
	migrationSweepWorker := controlquota.NewSweepLegacyAccountMigrationsWorker(db)
	migrationWorker := controlquota.NewMigrateSubscriptionAccountWorker(db, agent)
	cleanupSweepWorker := controlquota.NewSweepLegacyAccountCleanupWorker(db)
	river.AddWorker(workers, migrationSweepWorker)
	river.AddWorker(workers, migrationWorker)
	river.AddWorker(workers, cleanupSweepWorker)
	river.AddWorker(workers, controlquota.NewCleanupLegacyHomesWorker(db, agent))
	usageWorker := controlquota.NewCollectUsageWorker(db, agent)
	river.AddWorker(workers, usageWorker)
	river.AddWorker(workers, controlquota.NewDeliverNotificationsWorker(db, controlquota.SMTPConfig{
		Host: runtimeConfig.SMTPHost, Port: runtimeConfig.SMTPPort, Username: runtimeConfig.SMTPUsername,
		Password: runtimeConfig.SMTPPassword, From: runtimeConfig.SMTPFrom, TLSMode: runtimeConfig.SMTPTLSMode,
	}))
	river.AddWorker(workers, provisioningapi.NewFinalizeAccountWorker(db))
	river.AddWorker(workers, provisioningapi.NewTeardownAccountWorker(db, agent))
	webhookConfig := provisioningapi.WebhookConfig{URL: runtimeConfig.BillingWebhookURL, Secret: runtimeConfig.BillingWebhookSecret}
	webhookSweepWorker := provisioningapi.NewSweepWebhookWorker(db, webhookConfig.URL != "")
	river.AddWorker(workers, webhookSweepWorker)
	river.AddWorker(workers, provisioningapi.NewDeliverWebhookWorker(db, webhookConfig))

	backupSchedule, err := cron.ParseStandard("0 2 * * *")
	if err != nil {
		return nil, err
	}
	pruneSchedule, err := cron.ParseStandard("0 3 * * *")
	if err != nil {
		return nil, err
	}
	client, err := river.NewClient(riverdatabasesql.New(db), &river.Config{
		PeriodicJobs: []*river.PeriodicJob{
			river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) {
				return provisioningapi.SweepWebhookArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(15*time.Minute), func() (river.JobArgs, *river.InsertOpts) {
				return controlquota.CollectUsageArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) {
				return controlquota.DeliverNotificationsArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(5*time.Minute), func() (river.JobArgs, *river.InsertOpts) {
				return controlquota.SweepLegacyAccountMigrationsArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(time.Hour), func() (river.JobArgs, *river.InsertOpts) {
				return controlquota.SweepLegacyAccountCleanupArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(time.Minute), func() (river.JobArgs, *river.InsertOpts) {
				return controlquota.ConvergePendingSubscriptionsArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(6*time.Hour), func() (river.JobArgs, *river.InsertOpts) {
				return controlmaintenance.RenewCertsArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(backupSchedule, func() (river.JobArgs, *river.InsertOpts) {
				return controlmaintenance.ScheduledBackupsArgs{Window: time.Now().Format("2006-01-02")}, nil
			}, nil),
			river.NewPeriodicJob(pruneSchedule, func() (river.JobArgs, *river.InsertOpts) {
				return controlmaintenance.PruneBackupsArgs{}, nil
			}, nil),
			river.NewPeriodicJob(river.PeriodicInterval(time.Hour), func() (river.JobArgs, *river.InsertOpts) {
				return controlmaintenance.ReconcileArgs{Scope: "system"}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
			river.NewPeriodicJob(river.PeriodicInterval(15*time.Minute), func() (river.JobArgs, *river.InsertOpts) {
				return controlmaintenance.MailQueueSweepArgs{}, nil
			}, &river.PeriodicJobOpts{RunOnStart: true}),
		},
		Queues: map[string]river.QueueConfig{
			river.QueueDefault:           {MaxWorkers: 4},
			controlquota.HeavyQueue:      {MaxWorkers: 2},
			controlquota.MigrationQueue:  {MaxWorkers: 1},
			controlmaintenance.Queue:     {MaxWorkers: 2},
			provisioningapi.WebhookQueue: {MaxWorkers: 4},
		},
		Workers: workers,
	})
	if err != nil {
		return nil, err
	}
	usageWorker.SetRiverClient(client)
	convergenceWorker.SetRiverClient(client)
	configureMailWorker.SetRiverClient(client)
	pendingConvergenceWorker.SetRiverClient(client)
	migrationSweepWorker.SetRiverClient(client)
	cleanupSweepWorker.SetRiverClient(client)
	migrationWorker.SetRiverClient(client)
	maintenanceService.SetRiverClient(client)
	webhookSweepWorker.SetRiverClient(client)
	return client, nil
}

func sweepCustomTLSStaging(ctx context.Context, db *sql.DB) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := provision.SweepCustomTLSStagingForJobs(ctx, db, provision.DefaultCustomTLSStagingDir, 24*time.Hour); err != nil {
				log.Printf("sweep stale custom TLS staging files: %v", err)
			}
		}
	}
}

func newHTTPServer(cfg config.PanelRuntimeConfig, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.HTTPSAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}
