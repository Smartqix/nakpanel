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

	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/agentclient"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	panelhttp "github.com/nakroteck/nakpanel/internal/control/http"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/store"
	paneltls "github.com/nakroteck/nakpanel/internal/control/tls"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.PanelRuntimeConfigFromEnv()

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

	riverClient, err := newRiverClient(db, queries)
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
	quotaStore := controlquota.NewSQLStore(db)
	dashboardStore := dashboard.NewStore(
		queries,
		dashboard.WithJobReader(dashboard.NewSQLJobStore(db)),
		dashboard.WithPhase6Reader(dashboard.NewSQLPhase6Store(db)),
		dashboard.WithQuotaReader(quotaStore),
	)
	siteManager := provision.NewManager(
		siteRepo,
		provision.WithDatabaseRepository(databaseRepo),
		provision.WithCertificateRepository(siteRepo),
		provision.WithPhase6Repository(phase6Repo),
		provision.WithQuotaStore(quotaStore),
	)
	jobRetrier := provision.NewSQLJobRetrier(db)
	handler := panelhttp.NewServer(authStore, sessionManager, panelhttp.ServerOptions{
		SiteCreator:       siteManager,
		DatabaseCreator:   siteManager,
		CertificateIssuer: siteManager,
		DashboardReader:   dashboardStore,
		JobRetrier:        jobRetrier,
		Phase6Manager:     siteManager,
		QuotaManager:      siteManager,
	}).Handler()

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

func newRiverClient(db *sql.DB, queries *store.Queries) (*river.Client[*sql.Tx], error) {
	workers := river.NewWorkers()
	agent := agentclient.New(config.AgentSocket)
	siteStatus := provision.NewSQLSiteStatusStore(queries)
	databaseStatus := provision.NewSQLDatabaseStatusStore(db, queries)
	phase6Status := provision.NewSQLPhase6StatusStore(db)
	river.AddWorker(workers, provision.NewCreateSiteWorker(agent, siteStatus))
	river.AddWorker(workers, provision.NewCreateDatabaseWorker(agent, databaseStatus))
	river.AddWorker(workers, provision.NewIssueCertWorker(agent, siteStatus))
	river.AddWorker(workers, provision.NewCreateBackupWorker(agent, phase6Status))
	river.AddWorker(workers, provision.NewRestoreBackupWorker(agent, phase6Status))
	river.AddWorker(workers, provision.NewConfigureWebmailWorker(agent, phase6Status))
	river.AddWorker(workers, provision.NewConfigureDNSZoneWorker(agent, phase6Status))
	river.AddWorker(workers, provision.NewReconcileSystemWorker(agent, phase6Status))

	return river.NewClient(riverdatabasesql.New(db), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 1},
		},
		Workers: workers,
	})
}

func newHTTPServer(cfg config.PanelRuntimeConfig, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    cfg.HTTPSAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}
