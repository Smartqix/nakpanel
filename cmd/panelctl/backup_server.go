package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nakroteck/nakpanel/internal/backup"
	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/operator"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
)

func runBackupServer(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: panelctl backup-server key|destination|run|list ...")
	}
	switch args[0] {
	case "key":
		if len(args) < 2 {
			return errors.New("usage: panelctl backup-server key init [--force] | key status")
		}
		switch args[1] {
		case "init":
			set := flag.NewFlagSet("backup-server key init", flag.ContinueOnError)
			set.SetOutput(stderr)
			force := set.Bool("force", false, "replace an existing key (old archives stay readable only with the old key)")
			if err := set.Parse(args[2:]); err != nil {
				return err
			}
			encoded, fingerprint, err := service.BackupKeyInit(ctx, *force)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Backup archive key created (fingerprint %s).\n", fingerprint)
			fmt.Fprintln(stdout, "Store this key OFFLINE now - it is shown exactly once and archives")
			fmt.Fprintln(stdout, "cannot be restored without it:")
			fmt.Fprintln(stdout, encoded)
			return nil
		case "status":
			fingerprint, ok := service.BackupKeyStatus(ctx)
			if !ok {
				fmt.Fprintln(stdout, "No backup archive key is configured.")
				return nil
			}
			fmt.Fprintf(stdout, "Backup archive key present (fingerprint %s).\n", fingerprint)
			return nil
		default:
			return errors.New("usage: panelctl backup-server key init [--force] | key status")
		}
	case "destination":
		return runBackupDestination(ctx, service, args[1:], stdout, stderr)
	case "run":
		set := flag.NewFlagSet("backup-server run", flag.ContinueOnError)
		set.SetOutput(stderr)
		destination := set.String("destination", "", "destination name")
		wait := set.Bool("wait", false, "wait for the backup to finish")
		timeout := set.Duration("timeout", 2*time.Hour, "wait timeout")
		if err := set.Parse(args[1:]); err != nil {
			return err
		}
		if *destination == "" {
			return errors.New("--destination is required")
		}
		id, err := service.RunServerBackup(ctx, *destination)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Server backup %d queued for destination %s.\n", id, *destination)
		if !*wait {
			return nil
		}
		item, err := service.WaitServerBackup(ctx, id, *timeout)
		if err != nil {
			return err
		}
		if item.Status != "active" {
			return fmt.Errorf("server backup %d finished with status %s: %s", id, item.Status, item.LastError)
		}
		fmt.Fprintf(stdout, "Server backup %d completed: %s (%d bytes, sha256 %s, verified).\n",
			id, item.ArchiveName, item.SizeBytes, item.ChecksumSHA256)
		return nil
	case "list":
		items, err := service.ListServerBackups(ctx, 50)
		if err != nil {
			return err
		}
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tDESTINATION\tSTATUS\tARCHIVE\tSIZE\tVERIFIED\tCREATED")
		for _, item := range items {
			verified := "no"
			if item.VerifiedAt != nil {
				verified = "yes"
			}
			fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%d\t%s\t%s\n", item.ID, item.DestinationName,
				item.Status, item.ArchiveName, item.SizeBytes, verified, item.CreatedAt.Format(time.RFC3339))
		}
		return writer.Flush()
	default:
		return fmt.Errorf("unknown backup-server command %q", args[0])
	}
}

func runBackupDestination(ctx context.Context, service *operator.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: panelctl backup-server destination add|list|remove|test ...")
	}
	switch args[0] {
	case "add", "update":
		set := flag.NewFlagSet("backup-server destination add", flag.ContinueOnError)
		set.SetOutput(stderr)
		name := set.String("name", "", "destination name")
		kind := set.String("kind", "local", "destination kind: local, sftp, or s3")
		schedule := set.String("schedule", "0 2 * * *", "cron schedule")
		retentionCount := set.Int("retention-count", 7, "archives to keep")
		retentionDays := set.Int("retention-days", 30, "age cap in days (0 disables)")
		settingsFile := set.String("settings-file", "", "JSON settings file")
		settingsInline := set.String("settings", "", "JSON settings")
		credentialFile := set.String("credential-file", "", "JSON credential file (sftp/s3)")
		notify := set.String("notify", "", "failure notification email (default: all admins)")
		skipMail := set.Bool("skip-mail-data", false, "exclude Stalwart mail data")
		disabled := set.Bool("disabled", false, "create disabled (no scheduled runs)")
		if err := set.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return errors.New("--name is required")
		}
		settings := json.RawMessage(`{}`)
		if *settingsFile != "" {
			data, err := os.ReadFile(*settingsFile)
			if err != nil {
				return err
			}
			settings = json.RawMessage(data)
		} else if *settingsInline != "" {
			settings = json.RawMessage(*settingsInline)
		}
		var credential []byte
		if *credentialFile != "" {
			data, err := os.ReadFile(*credentialFile)
			if err != nil {
				return err
			}
			credential = data
		}
		item, err := service.SaveBackupDestination(ctx, serveradmin.SaveBackupDestinationParams{
			Name:            *name,
			Kind:            *kind,
			Enabled:         !*disabled,
			Settings:        settings,
			Credential:      credential,
			ScheduleCron:    *schedule,
			RetentionCount:  *retentionCount,
			RetentionDays:   *retentionDays,
			IncludeMailData: !*skipMail,
			NotifyEmail:     *notify,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Backup destination %s (%s) saved; schedule %q, retention %d/%dd.\n",
			item.Name, item.Kind, item.ScheduleCron, item.RetentionCount, item.RetentionDays)
		return nil
	case "list":
		items, err := service.ListBackupDestinations(ctx)
		if err != nil {
			return err
		}
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "NAME\tKIND\tENABLED\tSCHEDULE\tRETAIN\tLAST SUCCESS\tLAST ERROR")
		for _, item := range items {
			lastSuccess := "-"
			if item.LastSucceededAt != nil {
				lastSuccess = item.LastSucceededAt.Format(time.RFC3339)
			}
			fmt.Fprintf(writer, "%s\t%s\t%t\t%s\t%d/%dd\t%s\t%s\n", item.Name, item.Kind, item.Enabled,
				item.ScheduleCron, item.RetentionCount, item.RetentionDays, lastSuccess, item.LastError)
		}
		return writer.Flush()
	case "remove":
		if len(args) != 3 || args[2] != "--yes" {
			return errors.New("usage: panelctl backup-server destination remove NAME --yes")
		}
		if err := service.DeleteBackupDestination(ctx, args[1]); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Backup destination %s removed.\n", args[1])
		return nil
	case "test":
		if len(args) != 2 {
			return errors.New("usage: panelctl backup-server destination test NAME")
		}
		result, err := service.TestBackupDestination(ctx, args[1])
		if err != nil {
			return err
		}
		if result.ObservedHostKey != "" {
			fmt.Fprintf(stdout, "Observed SSH host key: %s\n", result.ObservedHostKey)
		}
		if !result.OK {
			return fmt.Errorf("destination test failed: %s", result.Detail)
		}
		fmt.Fprintln(stdout, "Destination test passed (write, read back, delete).")
		return nil
	default:
		return fmt.Errorf("unknown destination command %q", args[0])
	}
}

// runRestoreServer performs full disaster recovery. It is dispatched before
// operator.Open because it drops and recreates the panel database.
func runRestoreServer(ctx context.Context, actor string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("restore-server", flag.ContinueOnError)
	set.SetOutput(stderr)
	archivePath := set.String("archive", "", "path to the .nkbk archive")
	keyFile := set.String("backup-key-file", "", "file containing the nkbk1- archive key")
	allowSchemaMismatch := set.Bool("allow-schema-mismatch", false, "proceed when the archive schema is older than the installed migrations")
	assumeYes := set.Bool("yes", false, "do not prompt for confirmation")
	jsonOut := set.Bool("json", false, "print a JSON summary")
	skipConverge := set.Bool("skip-converge", false, "skip the post-restore reconcile and health checks")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *archivePath == "" || *keyFile == "" {
		return errors.New("usage: panelctl restore-server --archive FILE --backup-key-file FILE [--yes]")
	}
	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := backup.DecodeKey(strings.TrimSpace(string(keyData)))
	if err != nil {
		return err
	}
	if _, err := os.Stat(*archivePath); err != nil {
		return err
	}
	openArchive := func() (io.ReadCloser, error) { return os.Open(*archivePath) }

	// Preview before destroying anything.
	source, err := openArchive()
	if err != nil {
		return err
	}
	manifest, err := backup.ReadManifest(source, key)
	source.Close()
	if err != nil {
		return fmt.Errorf("read archive manifest: %w", err)
	}
	fmt.Fprintf(stderr, "Archive: host %s, created %s, panel %s, schema %d, %d tenant databases, mail data: %t\n",
		manifest.Hostname, manifest.CreatedAt.Format(time.RFC3339), manifest.PanelVersion,
		manifest.GooseVersion, len(manifest.TenantDatabases), manifest.IncludeMailData)
	if !*assumeYes {
		fmt.Fprint(stdout, "This DESTROYS the current panel database and state. Type 'restore' to continue: ")
		var reply string
		fmt.Fscanln(stdin, &reply)
		if reply != "restore" {
			return errors.New("aborted")
		}
	}

	summary, err := backup.RunRestore(ctx, backup.RestoreOptions{
		OpenArchive:         openArchive,
		Key:                 key,
		AllowSchemaMismatch: *allowSchemaMismatch,
		Log: func(format string, args ...any) {
			fmt.Fprintf(stderr, format+"\n", args...)
		},
	})
	if err != nil {
		return err
	}

	if !*skipConverge {
		// The post-restore steps need the panel database over the local
		// socket (peer auth) and the agent socket (peer-UID gated), both of
		// which reject root — so drop to the nakpanel user for them.
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("restore finished but the post-restore step could not start: %w", err)
		}
		databaseURL := strings.TrimSpace(os.Getenv("NAKPANEL_DATABASE_URL"))
		if databaseURL == "" {
			databaseURL = "postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable"
		}
		agentSocket := strings.TrimSpace(os.Getenv("NAKPANEL_AGENT_SOCKET"))
		if agentSocket == "" {
			agentSocket = config.AgentSocket
		}
		secretKeyFile := strings.TrimSpace(os.Getenv("NAKPANEL_SECRET_KEY_FILE"))
		if secretKeyFile == "" {
			secretKeyFile = config.DefaultSecretKeyFile
		}
		post := exec.CommandContext(ctx, "runuser", "-u", "nakpanel", "--", "env",
			"NAKPANEL_DATABASE_URL="+databaseURL,
			"NAKPANEL_AGENT_SOCKET="+agentSocket,
			"NAKPANEL_SECRET_KEY_FILE="+secretKeyFile,
			self, "--actor", actor, "restore-server-post",
			"--archive-host", manifest.Hostname,
			"--entries", fmt.Sprintf("%d", summary.ExtractedEntries))
		post.Stdout = stderr
		post.Stderr = stderr
		if err := post.Run(); err != nil {
			return fmt.Errorf("post-restore convergence failed: %w", err)
		}
	}

	if *jsonOut {
		payload := map[string]any{
			"summary":          summary,
			"schema_mismatch":  summary.SchemaMismatch,
			"services_started": summary.ServicesStarted,
		}
		return json.NewEncoder(stdout).Encode(payload)
	}
	fmt.Fprintf(stdout, "Server restore completed: %d entries extracted, %d MariaDB databases, %d services started.\n",
		summary.ExtractedEntries, len(summary.MariaDBRestored), len(summary.ServicesStarted))
	if summary.SchemaMismatch {
		fmt.Fprintln(stdout, "NOTE: the archive schema is older than the installed migrations; run 'make goose-up' (and river-up) now.")
	}
	return nil
}

// runRestoreServerPost runs as the nakpanel user (spawned by restore-server):
// it recreates MariaDB users from restored credentials, waits for panel
// health, queues reconciliation, and writes the completion audit.
func runRestoreServerPost(ctx context.Context, service *operator.Service, args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("restore-server-post", flag.ContinueOnError)
	set.SetOutput(stderr)
	archiveHost := set.String("archive-host", "", "archive source hostname (audit metadata)")
	entries := set.Int("entries", 0, "extracted entry count (audit metadata)")
	if err := set.Parse(args); err != nil {
		return err
	}
	warnings := []string{}
	fmt.Fprintln(stderr, "step: recreate mariadb users and grants")
	restored, credWarnings, err := service.RestoreMariaDBCredentials(ctx)
	if err != nil {
		return err
	}
	warnings = append(warnings, credWarnings...)

	fmt.Fprintln(stderr, "step: wait for the panel to become healthy")
	if err := waitPanelHealthy(ctx, 120*time.Second); err != nil {
		warnings = append(warnings, err.Error())
	}
	if err := service.AgentPing(ctx); err != nil {
		warnings = append(warnings, fmt.Sprintf("agent ping failed: %v", err))
	}

	fmt.Fprintln(stderr, "step: queue system reconciliation")
	if runID, err := service.ReconcileSystem(ctx); err != nil {
		warnings = append(warnings, fmt.Sprintf("queue reconcile: %v", err))
	} else {
		fmt.Fprintf(stderr, "reconciliation run %d queued\n", runID)
	}
	_ = service.RecordRestoreAudit(ctx, map[string]any{
		"archive_host":     *archiveHost,
		"entries":          *entries,
		"mariadb_restored": len(restored),
		"warnings":         len(warnings),
	})
	for _, warning := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", warning)
	}
	fmt.Fprintf(stdout, "post-restore convergence finished (%d MariaDB users, %d warnings)\n", len(restored), len(warnings))
	return nil
}

func waitPanelHealthy(ctx context.Context, timeout time.Duration) error {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	deadline := time.Now().Add(timeout)
	url := "https://127.0.0.1:7443/healthz"
	for {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.HasPrefix(string(body), "ok") {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("panel did not become healthy at %s within %s", url, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
