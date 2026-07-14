package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/config"
	"github.com/nakroteck/nakpanel/internal/control/agentclient"
	"github.com/nakroteck/nakpanel/internal/control/operator"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"golang.org/x/term"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "panelctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	actor, args, err := extractValueFlag(args, "--actor", defaultActor())
	if err != nil {
		return err
	}
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("a command is required")
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printUsage(stdout)
		return nil
	}
	databaseURL := strings.TrimSpace(os.Getenv("NAKPANEL_DATABASE_URL"))
	if databaseURL == "" {
		databaseURL = config.DefaultDatabaseURL
	}
	agentSocket := strings.TrimSpace(os.Getenv("NAKPANEL_AGENT_SOCKET"))
	if agentSocket == "" {
		agentSocket = config.AgentSocket
	}
	if len(args) == 2 && args[0] == "agent" && args[1] == "ping" {
		client := agentclient.New(agentSocket)
		response, err := client.Ping(ctx)
		if err != nil {
			return err
		}
		if !response.OK {
			return errors.New(response.Error)
		}
		fmt.Fprintln(stdout, "agent connected")
		return nil
	}
	service, err := operator.Open(ctx, operator.Options{DatabaseURL: databaseURL, AgentSocket: agentSocket, ActorLabel: actor})
	if err != nil {
		return err
	}
	defer service.Close()

	switch args[0] {
	case "create-admin":
		return runCreateAdmin(ctx, service, args[1:], stdin, stdout, stderr)
	case "user":
		return runUser(ctx, service, args[1:], stdin, stdout, stderr)
	case "session":
		return runSession(ctx, service, args[1:], stdin, stdout, stderr)
	case "site":
		return runSite(ctx, service, args[1:], stdout, stderr)
	case "ssl":
		return runSSL(ctx, service, args[1:], stdin, stdout, stderr)
	case "backup":
		return runBackup(ctx, service, args[1:], stdout, stderr)
	case "restore":
		return runRestore(ctx, service, args[1:], stdin, stdout, stderr)
	case "plan":
		return runPlan(ctx, service, args[1:], stdout, stderr)
	case "mail":
		return runMail(ctx, service, args[1:], stdin, stdout, stderr)
	case "subscription":
		return runSubscription(ctx, service, args[1:], stdout, stderr)
	case "api-key":
		return runAPIKey(ctx, service, args[1:], stdin, stdout, stderr)
	case "reconcile":
		if len(args) != 2 || args[1] != "--system" {
			return errors.New("usage: panelctl reconcile --system")
		}
		id, err := service.ReconcileSystem(ctx)
		if err == nil {
			fmt.Fprintf(stdout, "System reconciliation queued (run %d).\n", id)
		}
		return err
	case "agent":
		if len(args) != 2 || args[1] != "ping" {
			return errors.New("usage: panelctl agent ping")
		}
		if err := service.AgentPing(ctx); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "agent connected")
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runCreateAdmin(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	set.SetOutput(stderr)
	email := set.String("email", "", "administrator email")
	password := set.String("password", "", "administrator password")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *password == "" {
		value, err := hiddenPassword(stdin, stdout)
		if err != nil {
			return err
		}
		*password = value
	}
	id, err := service.CreateAdmin(ctx, *email, *password)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Administrator %s created (user %d).\n", strings.ToLower(strings.TrimSpace(*email)), id)
	return nil
}

func runUser(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 1 && args[0] == "list" {
		items, err := service.ListUsers(ctx)
		if err != nil {
			return err
		}
		w := table(stdout)
		fmt.Fprintln(w, "ID\tEMAIL\tROLE\tSTATUS\tLOGIN")
		for _, item := range items {
			login := "enabled"
			if item.LoginDisabled {
				login = "disabled"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", item.ID, item.Email, item.Role, item.Status, login)
		}
		return w.Flush()
	}
	if len(args) < 2 || (args[0] != "suspend" && args[0] != "unsuspend") {
		return errors.New("usage: panelctl user list | user suspend|unsuspend <email> [--yes]")
	}
	yes, rest := extractBoolFlag(args[1:], "--yes")
	if len(rest) != 1 {
		return errors.New("user email is required")
	}
	suspended := args[0] == "suspend"
	if suspended {
		if err := confirm(stdin, stdout, yes, "Suspend "+rest[0]+" and queue hosted-service convergence?"); err != nil {
			return err
		}
	}
	if err := service.SetUserSuspended(ctx, rest[0], suspended); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "User %s %s.\n", rest[0], map[bool]string{true: "suspended", false: "activated"}[suspended])
	return nil
}

func runSession(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: panelctl session list|revoke|revoke-user")
	}
	switch args[0] {
	case "list":
		set := flag.NewFlagSet("session list", flag.ContinueOnError)
		set.SetOutput(stderr)
		email := set.String("user", "", "filter by email")
		if err := set.Parse(args[1:]); err != nil {
			return err
		}
		items, err := service.ListSessions(ctx, *email)
		if err != nil {
			return err
		}
		now := time.Now()
		w := table(stdout)
		fmt.Fprintln(w, "ID\tUSER\tCREATED\tEXPIRES\tSTATE")
		for _, item := range items {
			state := "active"
			if !item.ExpiresAt.After(now) {
				state = "expired"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", item.ID, item.Email, item.CreatedAt.UTC().Format(time.RFC3339), item.ExpiresAt.UTC().Format(time.RFC3339), state)
		}
		return w.Flush()
	case "revoke":
		yes, rest := extractBoolFlag(args[1:], "--yes")
		if len(rest) != 1 {
			return errors.New("session id is required")
		}
		id, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil || id <= 0 {
			return errors.New("session id must be a positive integer")
		}
		if err = confirm(stdin, stdout, yes, fmt.Sprintf("Revoke session %d?", id)); err != nil {
			return err
		}
		if err = service.RevokeSession(ctx, id); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Session %d revoked.\n", id)
		return nil
	case "revoke-user":
		yes, rest := extractBoolFlag(args[1:], "--yes")
		if len(rest) != 1 {
			return errors.New("user email is required")
		}
		if err := confirm(stdin, stdout, yes, "Revoke all sessions for "+rest[0]+"?"); err != nil {
			return err
		}
		count, err := service.RevokeUserSessions(ctx, rest[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%d session(s) revoked for %s.\n", count, rest[0])
		return nil
	default:
		return fmt.Errorf("unknown session command %q", args[0])
	}
}

func runSite(ctx context.Context, service *operator.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && args[0] == "list" {
		return printSites(ctx, service, "", stdout)
	}
	if len(args) != 2 {
		return errors.New("usage: panelctl site list | site show|reconcile <domain>")
	}
	switch args[0] {
	case "show":
		return printSites(ctx, service, args[1], stdout)
	case "reconcile":
		id, err := service.ReconcileSite(ctx, args[1])
		if err == nil {
			fmt.Fprintf(stdout, "Site reconciliation queued (run %d).\n", id)
		}
		return err
	default:
		return fmt.Errorf("unknown site command %q", args[0])
	}
}

func printSites(ctx context.Context, service *operator.Service, domain string, stdout io.Writer) error {
	items, err := service.ListSites(ctx, domain)
	if err != nil {
		return err
	}
	if domain != "" && len(items) == 0 {
		return errors.New("site not found")
	}
	w := table(stdout)
	fmt.Fprintln(w, "ID\tDOMAIN\tUSER\tPHP\tSTATUS\tSUBSCRIPTION\tTLS")
	for _, item := range items {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%s/%s\n", item.ID, item.Domain, item.Username, item.PHPVersion, item.Status, item.SubscriptionID, item.TLSIssuer, item.TLSStatus)
	}
	return w.Flush()
}

func runSSL(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: panelctl ssl renew|set-custom <domain>")
	}
	domain := args[1]
	switch args[0] {
	case "renew":
		yes, rest := extractBoolFlag(args[1:], "--yes")
		if len(rest) != 1 {
			return errors.New("usage: panelctl ssl renew <domain> [--yes]")
		}
		sites, err := service.ListSites(ctx, domain)
		if err != nil || len(sites) != 1 {
			if err != nil {
				return err
			}
			return errors.New("site not found")
		}
		replaceCustom := sites[0].TLSIssuer == "custom"
		if replaceCustom {
			if err := confirm(stdin, stdout, yes, "Replace the custom certificate for "+domain+" with ACME?"); err != nil {
				return err
			}
		}
		id, err := service.RenewSSL(ctx, domain, replaceCustom)
		if err == nil {
			fmt.Fprintf(stdout, "ACME certificate queued for %s (site %d).\n", domain, id)
		}
		return err
	case "set-custom":
		set := flag.NewFlagSet("ssl set-custom", flag.ContinueOnError)
		set.SetOutput(stderr)
		certPath := set.String("cert", "", "leaf certificate PEM")
		keyPath := set.String("key", "", "private key PEM")
		chainPath := set.String("chain", "", "intermediate chain PEM")
		yes := set.Bool("yes", false, "confirm replacement")
		if err := set.Parse(args[2:]); err != nil {
			return err
		}
		if *certPath == "" || *keyPath == "" {
			return errors.New("--cert and --key are required")
		}
		sites, err := service.ListSites(ctx, domain)
		if err != nil || len(sites) != 1 {
			if err != nil {
				return err
			}
			return errors.New("site not found")
		}
		if sites[0].TLSStatus != "none" {
			if err := confirm(stdin, stdout, *yes, "Replace the existing certificate for "+domain+"?"); err != nil {
				return err
			}
		}
		bundle, err := operator.ReadBundle(*certPath, *keyPath, *chainPath)
		if err != nil {
			return err
		}
		jobID, err := service.SetCustomSSL(ctx, domain, bundle)
		if err == nil {
			fmt.Fprintf(stdout, "Custom certificate queued for %s (job %d).\n", domain, jobID)
		}
		return err
	default:
		return fmt.Errorf("unknown ssl command %q", args[0])
	}
}

func runBackup(ctx context.Context, service *operator.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: panelctl backup create <domain> | backup list [domain]")
	}
	switch args[0] {
	case "create":
		if len(args) != 2 {
			return errors.New("backup domain is required")
		}
		id, err := service.CreateBackup(ctx, args[1])
		if err == nil {
			fmt.Fprintf(stdout, "Backup queued (backup %d).\n", id)
		}
		return err
	case "list":
		if len(args) > 2 {
			return errors.New("usage: panelctl backup list [domain]")
		}
		domain := ""
		if len(args) == 2 {
			domain = args[1]
		}
		items, err := service.ListBackups(ctx, domain)
		if err != nil {
			return err
		}
		w := table(stdout)
		fmt.Fprintln(w, "ID\tDOMAIN\tSTATUS\tSIZE\tSUBSCRIPTION\tCREATED")
		for _, item := range items {
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%s\n", item.ID, item.Domain, item.Status, item.SizeBytes, item.SubscriptionID, item.CreatedAt.UTC().Format(time.RFC3339))
		}
		return w.Flush()
	default:
		return fmt.Errorf("unknown backup command %q", args[0])
	}
}

func runRestore(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	yes, rest := extractBoolFlag(args, "--yes")
	if len(rest) != 1 {
		return errors.New("usage: panelctl restore <backup-id> [--yes]")
	}
	id, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil || id <= 0 {
		return errors.New("backup id must be a positive integer")
	}
	if err = confirm(stdin, stdout, yes, fmt.Sprintf("Restore backup %d over its current site data?", id)); err != nil {
		return err
	}
	restoreID, err := service.RestoreBackup(ctx, id)
	if err == nil {
		fmt.Fprintf(stdout, "Restore queued (restore %d).\n", restoreID)
	}
	return err
}

func runPlan(ctx context.Context, service *operator.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 || args[0] != "list" {
		return errors.New("usage: panelctl plan list")
	}
	items, err := service.ListPlans(ctx)
	if err != nil {
		return err
	}
	w := table(stdout)
	fmt.Fprintln(w, "ID\tNAME\tPROVIDER\tACTIVE\tREVISION")
	for _, item := range items {
		fmt.Fprintf(w, "%d\t%s\t%s\t%t\t%d\n", item.ID, item.Name, item.Provider, item.Active, item.Revision)
	}
	return w.Flush()
}

func runSubscription(ctx context.Context, service *operator.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "list" {
		return errors.New("usage: panelctl subscription list [--customer <email>]")
	}
	set := flag.NewFlagSet("subscription list", flag.ContinueOnError)
	set.SetOutput(stderr)
	customer := set.String("customer", "", "customer email")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	items, err := service.ListSubscriptions(ctx, *customer)
	if err != nil {
		return err
	}
	w := table(stdout)
	fmt.Fprintln(w, "ID\tNAME\tCUSTOMER\tPLAN\tSTATUS\tMODE")
	for _, item := range items {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", item.ID, item.Name, item.Customer, item.Plan, item.Status, item.Mode)
	}
	return w.Flush()
}

func runMail(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	usage := errors.New("usage: panelctl mail enable DOMAIN | add ADDRESS | list DOMAIN | del ADDRESS | alias add|del ADDRESS | relay set|clear | settings")
	if len(args) == 0 {
		return usage
	}
	switch args[0] {
	case "enable":
		set := flag.NewFlagSet("mail enable", flag.ContinueOnError)
		set.SetOutput(stderr)
		subscription := set.Int64("subscription", 0, "subscription id (resolved from the site when omitted)")
		dkim := set.Bool("dkim", true, "generate and publish a DKIM key")
		dmarc := set.String("dmarc", "quarantine", "DMARC policy: none, quarantine, or reject")
		if len(args) < 2 {
			return errors.New("usage: panelctl mail enable DOMAIN [--subscription N] [--dkim=false] [--dmarc POLICY]")
		}
		if err := set.Parse(args[2:]); err != nil {
			return err
		}
		id, err := service.EnableMailDomain(ctx, args[1], *subscription, *dkim, *dmarc)
		if err == nil {
			fmt.Fprintf(stdout, "Mail enabled for %s (mail domain %d); Stalwart and DNS convergence queued.\n", args[1], id)
		}
		return err
	case "add":
		set := flag.NewFlagSet("mail add", flag.ContinueOnError)
		set.SetOutput(stderr)
		quota := set.Int("quota-mb", 0, "mailbox quota in MB (0 uses the plan default)")
		password := set.String("password", "", "mailbox password (generated and printed when omitted)")
		if len(args) < 2 {
			return errors.New("usage: panelctl mail add ADDRESS [--quota-mb N] [--password PASSWORD]")
		}
		if err := set.Parse(args[2:]); err != nil {
			return err
		}
		id, generated, err := service.AddMailbox(ctx, args[1], *quota, *password)
		if err != nil {
			return err
		}
		if generated != "" {
			fmt.Fprintf(stdout, "Mailbox %s created (id %d). Generated password: %s\n", strings.ToLower(args[1]), id, generated)
		} else {
			fmt.Fprintf(stdout, "Mailbox %s saved (id %d).\n", strings.ToLower(args[1]), id)
		}
		return nil
	case "list":
		if len(args) != 2 {
			return errors.New("usage: panelctl mail list DOMAIN")
		}
		status, err := service.MailDomainStatus(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Domain %s: enabled=%t dkim=%t dmarc=%s status=%s", status.Domain, status.Enabled, status.DKIM, status.DMARCPolicy, status.Status)
		if status.LastError != "" {
			fmt.Fprintf(stdout, " (%s)", status.LastError)
		}
		fmt.Fprintln(stdout)
		mailboxes, aliases, err := service.ListMailboxes(ctx, args[1])
		if err != nil {
			return err
		}
		w := table(stdout)
		fmt.Fprintln(w, "TYPE\tADDRESS\tQUOTA\tDETAIL")
		for _, item := range mailboxes {
			quota := "unlimited"
			if item.QuotaMB > 0 {
				quota = fmt.Sprintf("%d MB", item.QuotaMB)
			}
			state := "enabled"
			if !item.Enabled {
				state = "disabled"
			}
			fmt.Fprintf(w, "mailbox\t%s\t%s\t%s\n", item.Address, quota, state)
		}
		for _, item := range aliases {
			fmt.Fprintf(w, "alias\t%s\t-\t-> %s\n", item.Address, item.Destinations)
		}
		return w.Flush()
	case "del":
		yes, rest := extractBoolFlag(args[1:], "--yes")
		if len(rest) != 1 {
			return errors.New("usage: panelctl mail del ADDRESS [--yes]")
		}
		if err := confirm(stdin, stdout, yes, "Delete mailbox "+rest[0]+" and stop accepting its mail?"); err != nil {
			return err
		}
		if err := service.DeleteMailbox(ctx, rest[0]); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Mailbox %s deleted.\n", strings.ToLower(rest[0]))
		return nil
	case "alias":
		if len(args) < 3 {
			return errors.New("usage: panelctl mail alias add ADDRESS --to DEST[,DEST...] | alias del ADDRESS [--yes]")
		}
		switch args[1] {
		case "add":
			set := flag.NewFlagSet("mail alias add", flag.ContinueOnError)
			set.SetOutput(stderr)
			to := set.String("to", "", "comma-separated destination mailboxes")
			if err := set.Parse(args[3:]); err != nil {
				return err
			}
			var destinations []string
			for _, destination := range strings.Split(*to, ",") {
				if destination = strings.TrimSpace(destination); destination != "" {
					destinations = append(destinations, destination)
				}
			}
			id, err := service.AddMailAlias(ctx, args[2], destinations)
			if err == nil {
				fmt.Fprintf(stdout, "Alias %s saved (id %d).\n", strings.ToLower(args[2]), id)
			}
			return err
		case "del":
			yes, rest := extractBoolFlag(args[2:], "--yes")
			if len(rest) != 1 {
				return errors.New("usage: panelctl mail alias del ADDRESS [--yes]")
			}
			if err := confirm(stdin, stdout, yes, "Delete alias "+rest[0]+"?"); err != nil {
				return err
			}
			if err := service.DeleteMailAlias(ctx, rest[0]); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Alias %s deleted.\n", strings.ToLower(rest[0]))
			return nil
		default:
			return usage
		}
	case "relay":
		if len(args) < 2 {
			return errors.New("usage: panelctl mail relay set --host HOST [--port N] [--username U] [--password P] | relay clear")
		}
		switch args[1] {
		case "set":
			set := flag.NewFlagSet("mail relay set", flag.ContinueOnError)
			set.SetOutput(stderr)
			host := set.String("host", "", "smarthost address")
			port := set.Int("port", 587, "smarthost port")
			username := set.String("username", "", "smarthost username")
			password := set.String("password", "", "smarthost password")
			if err := set.Parse(args[2:]); err != nil {
				return err
			}
			if strings.TrimSpace(*host) == "" {
				return errors.New("--host is required")
			}
			_, err := service.UpdateMailSettings(ctx, func(settings *controlquota.MailSettings) {
				settings.SmarthostHost, settings.SmarthostPort = *host, *port
				settings.SmarthostUsername, settings.SmarthostPassword = *username, *password
			})
			if err == nil {
				fmt.Fprintf(stdout, "Outbound mail now relays through %s:%d; Stalwart reconfiguration queued.\n", *host, *port)
			}
			return err
		case "clear":
			_, err := service.UpdateMailSettings(ctx, func(settings *controlquota.MailSettings) {
				settings.SmarthostHost, settings.SmarthostUsername, settings.SmarthostPassword = "", "", ""
				settings.SmarthostPort = 587
			})
			if err == nil {
				fmt.Fprintln(stdout, "Smarthost cleared; outbound mail delivers directly again.")
			}
			return err
		default:
			return usage
		}
	case "settings":
		set := flag.NewFlagSet("mail settings", flag.ContinueOnError)
		set.SetOutput(stderr)
		hostname := set.String("hostname", "", "mail EHLO hostname")
		rateLimit := set.String("rate-limit", "", "per-domain outbound rate limit, e.g. 200/1h")
		threshold := set.Int("alert-threshold", 0, "queued-message count that raises a spike alert")
		if err := set.Parse(args[1:]); err != nil {
			return err
		}
		if *hostname == "" && *rateLimit == "" && *threshold == 0 {
			settings, err := service.MailSettings(ctx)
			if err != nil {
				return err
			}
			relay := settings.SmarthostHost
			if relay == "" {
				relay = "direct delivery"
			} else {
				relay = fmt.Sprintf("%s:%d", settings.SmarthostHost, settings.SmarthostPort)
			}
			fmt.Fprintf(stdout, "hostname=%s outbound=%s rate-limit=%s alert-threshold=%d\n", settings.MailHostname, relay, settings.OutboundRateLimit, settings.QueueAlertThreshold)
			return nil
		}
		_, err := service.UpdateMailSettings(ctx, func(settings *controlquota.MailSettings) {
			if *hostname != "" {
				settings.MailHostname = *hostname
			}
			if *rateLimit != "" {
				settings.OutboundRateLimit = *rateLimit
			}
			if *threshold != 0 {
				settings.QueueAlertThreshold = *threshold
			}
		})
		if err == nil {
			fmt.Fprintln(stdout, "Mail settings updated; Stalwart reconfiguration queued.")
		}
		return err
	default:
		return usage
	}
}

func confirm(stdin io.Reader, stdout io.Writer, yes bool, prompt string) error {
	if yes {
		return nil
	}
	file, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return errors.New("confirmation requires an interactive terminal or --yes")
	}
	fmt.Fprintf(stdout, "%s [y/N] ", prompt)
	answer, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(answer)) != "y" && strings.ToLower(strings.TrimSpace(answer)) != "yes" {
		return errors.New("cancelled")
	}
	return nil
}

func hiddenPassword(stdin io.Reader, stdout io.Writer) (string, error) {
	file, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", errors.New("--password is required for non-interactive use")
	}
	fmt.Fprint(stdout, "Password: ")
	password, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(stdout)
	return string(password), err
}

func defaultActor() string {
	if actor := strings.TrimSpace(os.Getenv("SUDO_USER")); actor != "" && actor != "root" {
		return actor
	}
	if current, err := user.Current(); err == nil && strings.TrimSpace(current.Username) != "" {
		return current.Username
	}
	if actor := strings.TrimSpace(os.Getenv("USER")); actor != "" {
		return actor
	}
	return "unknown-operator"
}

func extractValueFlag(args []string, name, fallback string) (string, []string, error) {
	value := fallback
	result := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("%s requires a value", name)
			}
			value = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(args[i], name+"=") {
			value = strings.TrimPrefix(args[i], name+"=")
			continue
		}
		result = append(result, args[i])
	}
	if strings.TrimSpace(value) == "" {
		return "", nil, fmt.Errorf("%s must not be empty", name)
	}
	return value, result, nil
}

func extractBoolFlag(args []string, name string) (bool, []string) {
	result := make([]string, 0, len(args))
	found := false
	for _, arg := range args {
		if arg == name {
			found = true
			continue
		}
		result = append(result, arg)
	}
	return found, result
}

func table(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0) }

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: panelctl [--actor LABEL] COMMAND

Commands:
  create-admin --email EMAIL [--password PASSWORD]
  user list | user suspend|unsuspend EMAIL [--yes]
  session list [--user EMAIL] | session revoke ID --yes | session revoke-user EMAIL --yes
  site list | site show DOMAIN | site reconcile DOMAIN
  ssl renew DOMAIN [--yes] | ssl set-custom DOMAIN --cert FILE --key FILE [--chain FILE] [--yes]
  backup create DOMAIN | backup list [DOMAIN] | restore BACKUP-ID --yes
  plan list | subscription list [--customer EMAIL]
  api-key create --name NAME [--cidrs CIDR,...] [--rate-limit N] [--expires DURATION|RFC3339]
  api-key list | api-key revoke PREFIX --yes
  mail enable DOMAIN [--dkim=false] [--dmarc POLICY] | mail add ADDRESS [--quota-mb N]
  mail list DOMAIN | mail del ADDRESS --yes | mail alias add ADDRESS --to DEST[,DEST...]
  mail relay set --host HOST [--port N] | mail relay clear | mail settings [--rate-limit R]
  reconcile --system | agent ping`)
}

func runAPIKey(ctx context.Context, service *operator.Service, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: panelctl api-key create|list|revoke")
	}
	switch args[0] {
	case "create":
		set := flag.NewFlagSet("api-key create", flag.ContinueOnError)
		set.SetOutput(stderr)
		name := set.String("name", "", "API key name")
		cidrsRaw := set.String("cidrs", "", "comma-separated CIDR allowlist")
		rate := set.Int("rate-limit", 120, "requests per minute")
		expiresRaw := set.String("expires", "", "duration or RFC3339 expiry")
		if err := set.Parse(args[1:]); err != nil {
			return err
		}
		var expires time.Time
		if value := strings.TrimSpace(*expiresRaw); value != "" {
			if duration, err := time.ParseDuration(value); err == nil {
				expires = time.Now().Add(duration)
			} else if expires, err = time.Parse(time.RFC3339, value); err != nil {
				return errors.New("expires must be a duration or RFC3339 timestamp")
			}
		}
		var cidrs []string
		for _, value := range strings.Split(*cidrsRaw, ",") {
			if value = strings.TrimSpace(value); value != "" {
				cidrs = append(cidrs, value)
			}
		}
		key, raw, err := service.CreateAPIKey(ctx, *name, cidrs, *rate, expires)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "API key %s created with prefix %s. This value is shown once:\n%s\n", key.Name, key.Prefix, raw)
		return nil
	case "list":
		if len(args) != 1 {
			return errors.New("usage: panelctl api-key list")
		}
		items, err := service.ListAPIKeys(ctx)
		if err != nil {
			return err
		}
		w := table(stdout)
		fmt.Fprintln(w, "PREFIX\tNAME\tSCOPE\tRATE/MIN\tEXPIRES\tSTATE")
		for _, item := range items {
			state := "active"
			if !item.RevokedAt.IsZero() {
				state = "revoked"
			} else if !item.ExpiresAt.IsZero() && !item.ExpiresAt.After(time.Now()) {
				state = "expired"
			}
			expires := "never"
			if !item.ExpiresAt.IsZero() {
				expires = item.ExpiresAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n", item.Prefix, item.Name, item.Scope, item.RateLimitPerMinute, expires, state)
		}
		return w.Flush()
	case "revoke":
		yes, rest := extractBoolFlag(args[1:], "--yes")
		if len(rest) != 1 {
			return errors.New("API key prefix is required")
		}
		if err := confirm(stdin, stdout, yes, "Revoke API key "+rest[0]+"?"); err != nil {
			return err
		}
		if err := service.RevokeAPIKey(ctx, rest[0]); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "API key %s revoked.\n", rest[0])
		return nil
	default:
		return fmt.Errorf("unknown api-key command %q", args[0])
	}
}
