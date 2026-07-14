package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nakroteck/nakpanel/internal/agent/ops"
	agentrpc "github.com/nakroteck/nakpanel/internal/agent/rpc"
	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/types"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listener, err := listenUnix(config.AgentSocket, config.PanelUser)
	if err != nil {
		log.Fatalf("listen on agent socket: %v", err)
	}
	defer listener.Close()
	allowedUID, err := resolveAllowedPeerUID()
	if err != nil {
		log.Fatalf("resolve allowed panel uid: %v", err)
	}

	reloader := ops.NewSystemdReloader(ops.SystemdReloaderOptions{AllowedServices: []string{"nginx", "php8.3-fpm", "php8.2-fpm", "bind9", "named.service", "stalwart-mail.service"}})
	siteProvisioner := ops.NewSiteProvisioner(ops.SiteProvisionerOptions{
		Paths:            ops.DefaultSitePathConfig(),
		UserManager:      ops.NewLinuxUserManager(ops.LinuxUserManagerOptions{}),
		OwnershipManager: ops.NewLinuxOwnershipManager(nil),
		DiskQuotaManager: ops.NewLinuxDiskQuotaManager(nil),
		Reloader:         reloader,
	})
	webmailProvisioner := ops.NewWebmailProvisioner(ops.WebmailProvisionerOptions{Reloader: reloader})
	dnsProvisioner := ops.NewDNSProvisioner(ops.DNSProvisionerOptions{Reloader: reloader})
	usageCollector := ops.NewUsageCollector("/home", "/var/log/nginx", os.Getenv("NAKPANEL_MARIADB_DSN"))
	fileManager := ops.NewFileManager(ops.FileManagerOptions{TransferDir: config.FileTransferDir, PanelUser: config.PanelUser})
	accountProvisioner := ops.NewSubscriptionAccountProvisioner(ops.SubscriptionAccountProvisionerOptions{
		UserManager:     ops.NewLinuxUserManager(ops.LinuxUserManagerOptions{}),
		Ownership:       ops.NewLinuxOwnershipManager(nil),
		DiskQuota:       ops.NewLinuxDiskQuotaManager(nil),
		SiteProvisioner: siteProvisioner,
	})
	teardownProvisioner := ops.NewSubscriptionTeardownProvisioner(ops.SubscriptionTeardownOptions{HomeRoot: "/home", Paths: ops.DefaultSitePathConfig()})
	mailProvisioner := ops.NewMailProvisioner(ops.MailProvisionerOptions{
		ManagementURL: os.Getenv("NAKPANEL_STALWART_URL"),
		Reloader:      reloader,
	})
	podmanProvisioner := ops.NewPodmanProvisioner(ops.PodmanProvisionerOptions{})
	dispatcher := agentrpc.NewDispatcher(
		reloader,
		agentrpc.Options{
			AllowedServices: []string{"nginx", "php8.3-fpm", "php8.2-fpm", "bind9", "named.service", "stalwart-mail.service"},
			SiteProvisioner: siteProvisioner,
			DatabaseProvisioner: ops.NewDatabaseProvisioner(map[types.DBEngine]ops.DatabaseEngine{
				types.EngineMariaDB: ops.NewLazyMariaDBEngine(os.Getenv("NAKPANEL_MARIADB_DSN")),
			}),
			CertificateProvisioner: ops.NewCertificateProvisioner(ops.CertificateProvisionerOptions{
				Paths:       ops.DefaultSitePathConfig(),
				Reloader:    reloader,
				NginxTester: ops.NewCommandNginxConfigTester(nil),
				ACMEIssuer: ops.NewACMEHTTP01Issuer(ops.ACMEHTTP01IssuerOptions{
					DirectoryURL:   os.Getenv("NAKPANEL_ACME_DIRECTORY_URL"),
					AccountKeyPath: os.Getenv("NAKPANEL_ACME_ACCOUNT_KEY"),
					Email:          os.Getenv("NAKPANEL_ACME_EMAIL"),
				}),
			}),
			BackupProvisioner: ops.NewBackupProvisioner(ops.BackupProvisionerOptions{
				DatabaseDumper: ops.CommandDatabaseDumper{},
			}),
			DeleteBackupProvisioner: ops.NewDeleteBackupProvisioner(""),
			RestoreProvisioner: ops.NewRestoreProvisioner(ops.RestoreProvisionerOptions{
				DatabaseRestorer: ops.CommandDatabaseRestorer{},
				OwnershipManager: ops.NewLinuxOwnershipManager(nil),
			}),
			WebmailProvisioner: webmailProvisioner,
			DNSProvisioner:     dnsProvisioner,
			ReconciliationProvisioner: ops.NewReconciliationProvisioner(
				siteProvisioner,
				webmailProvisioner,
				dnsProvisioner,
				siteProvisioner,
				ops.CommandDatabaseDriftChecker{},
			),
			HostingStateProvisioner: siteProvisioner,
			UsageCollector:          usageCollector,
			SiteRuntimeProvisioner:  siteProvisioner,
			FileManager:             fileManager,
			SubscriptionAccounts:    accountProvisioner,
			Mail:                    mailProvisioner,
			Applications:            podmanProvisioner,
			SubscriptionTeardown:    teardownProvisioner,
		},
	)
	server := agentrpc.NewServer(dispatcher, agentrpc.WithAllowedPeerUID(allowedUID))

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	log.Printf("nakpanel agent listening on unix socket %s", config.AgentSocket)
	if err := server.Serve(ctx, listener); err != nil {
		log.Fatalf("serve agent socket: %v", err)
	}
}

func resolveAllowedPeerUID() (uint32, error) {
	if raw := strings.TrimSpace(os.Getenv("NAKPANEL_AGENT_ALLOWED_UID")); raw != "" {
		uid, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse NAKPANEL_AGENT_ALLOWED_UID: %w", err)
		}
		return uint32(uid), nil
	}
	panelUser, err := user.Lookup(config.PanelUser)
	if err != nil {
		return 0, fmt.Errorf("lookup user %q: %w", config.PanelUser, err)
	}
	uid, err := strconv.ParseUint(panelUser.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse user id %q: %w", panelUser.Uid, err)
	}
	return uint32(uid), nil
}

func listenUnix(socketPath, groupName string) (net.Listener, error) {
	gid := -1
	if groupName != "" {
		group, err := user.LookupGroup(groupName)
		if err != nil {
			return nil, fmt.Errorf("lookup group %q: %w", groupName, err)
		}
		parsedGID, err := strconv.Atoi(group.Gid)
		if err != nil {
			return nil, fmt.Errorf("parse group id %q: %w", group.Gid, err)
		}
		gid = parsedGID
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if gid >= 0 {
		if err := os.Chown(filepath.Dir(socketPath), 0, gid); err != nil {
			return nil, fmt.Errorf("chown socket directory: %w", err)
		}
	}
	if err := os.Chmod(filepath.Dir(socketPath), 0o750); err != nil {
		return nil, fmt.Errorf("chmod socket directory: %w", err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(socketPath, 0o660); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}

	if gid >= 0 {
		if err := os.Chown(socketPath, 0, gid); err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("chown socket: %w", err)
		}
	}

	return listener, nil
}
