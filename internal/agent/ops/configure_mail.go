package ops

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

// MailProvisioner renders Stalwart's entire configuration from panel intent —
// the same deterministic template → atomic write → reload pattern nginx and
// BIND use. Mailboxes and aliases never pass through here: Stalwart reads
// them live from the panel's Postgres via its SQL directory.
type MailProvisionerOptions struct {
	ConfigPath      string
	DKIMDir         string
	DataDir         string
	PgPasswordPath  string
	AdminSecretPath string
	TLSCertPath     string
	TLSKeyPath      string
	DatabaseHost    string
	DatabasePort    int
	DatabaseName    string
	DatabaseUser    string
	ManagementURL   string
	Service         string
	Reloader        SiteServiceReloader
	Runner          CommandRunner
	HTTPClient      *http.Client
}

type MailProvisioner struct {
	configPath      string
	dkimDir         string
	dataDir         string
	pgPasswordPath  string
	adminSecretPath string
	tlsCertPath     string
	tlsKeyPath      string
	databaseHost    string
	databasePort    int
	databaseName    string
	databaseUser    string
	managementURL   string
	service         string
	reloader        SiteServiceReloader
	runner          CommandRunner
	httpClient      *http.Client
}

const (
	// DKIMSelector is fixed so re-running domain enablement never rotates
	// published keys.
	DKIMSelector = "nak1"

	defaultStalwartManagementURL = "http://127.0.0.1:8446"
)

var outboundRateLimitRE = regexp.MustCompile(`^[0-9]{1,9}/[0-9]{1,4}[smhd]$`)

func NewMailProvisioner(opts MailProvisionerOptions) *MailProvisioner {
	p := &MailProvisioner{
		configPath:      opts.ConfigPath,
		dkimDir:         opts.DKIMDir,
		dataDir:         opts.DataDir,
		pgPasswordPath:  opts.PgPasswordPath,
		adminSecretPath: opts.AdminSecretPath,
		tlsCertPath:     opts.TLSCertPath,
		tlsKeyPath:      opts.TLSKeyPath,
		databaseHost:    opts.DatabaseHost,
		databasePort:    opts.DatabasePort,
		databaseName:    opts.DatabaseName,
		databaseUser:    opts.DatabaseUser,
		managementURL:   strings.TrimRight(opts.ManagementURL, "/"),
		service:         opts.Service,
		reloader:        opts.Reloader,
		runner:          opts.Runner,
		httpClient:      opts.HTTPClient,
	}
	if p.runner == nil {
		p.runner = ExecRunner{}
	}
	if p.configPath == "" {
		p.configPath = "/etc/stalwart/config.toml"
	}
	if p.dkimDir == "" {
		p.dkimDir = "/var/lib/nakpanel/dkim"
	}
	if p.dataDir == "" {
		p.dataDir = "/var/lib/stalwart/data"
	}
	if p.pgPasswordPath == "" {
		p.pgPasswordPath = "/etc/stalwart/pg-password"
	}
	if p.adminSecretPath == "" {
		p.adminSecretPath = "/etc/stalwart/admin-secret"
	}
	if p.tlsCertPath == "" {
		p.tlsCertPath = "/etc/stalwart/tls/cert.pem"
	}
	if p.tlsKeyPath == "" {
		p.tlsKeyPath = "/etc/stalwart/tls/key.pem"
	}
	if p.databaseHost == "" {
		p.databaseHost = "127.0.0.1"
	}
	if p.databasePort == 0 {
		p.databasePort = 5432
	}
	if p.databaseName == "" {
		p.databaseName = "nakpanel"
	}
	if p.databaseUser == "" {
		p.databaseUser = "stalwart_directory"
	}
	if p.managementURL == "" {
		p.managementURL = defaultStalwartManagementURL
	}
	if p.service == "" {
		p.service = "stalwart-mail.service"
	}
	if p.httpClient == nil {
		p.httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return p
}

func (p *MailProvisioner) ConfigureMail(ctx context.Context, req types.ConfigureMailReq) (_ types.ConfigureMailResult, err error) {
	normalized, err := normalizeConfigureMailRequest(req)
	if err != nil {
		return types.ConfigureMailResult{}, err
	}
	result := types.ConfigureMailResult{ConfigPath: p.configPath}
	for _, domain := range normalized.Domains {
		if !domain.DKIM {
			continue
		}
		record, err := p.ensureDKIMKey(domain.Domain)
		if err != nil {
			return types.ConfigureMailResult{}, err
		}
		result.DKIM = append(result.DKIM, types.MailDomainDKIM{
			MailDomainID: domain.MailDomainID, Domain: domain.Domain,
			Selector: DKIMSelector, Record: record,
		})
	}
	rendered := []byte(p.renderConfig(normalized))
	// Stalwart normalizes and rewrites its config file at boot, so the file
	// itself cannot witness idempotency. The sidecar holds the last rendered
	// intent: when it is unchanged the running (Stalwart-normalized) config
	// already encodes this intent and a disruptive restart is skipped — but a
	// stopped service must still converge to running.
	sidecarPath := p.configPath + ".nakpanel-intent"
	if current, readErr := os.ReadFile(sidecarPath); readErr == nil && string(current) == string(rendered) {
		if p.reloader != nil && !p.serviceActive(ctx) {
			if err := p.reloader.ReloadService(ctx, p.service); err != nil {
				return types.ConfigureMailResult{}, fmt.Errorf("start stalwart: %w", err)
			}
		}
		return result, nil
	}
	snapshots, err := snapshotFiles([]string{p.configPath, sidecarPath})
	if err != nil {
		return types.ConfigureMailResult{}, err
	}
	reloadAttempted := false
	defer func() {
		if err == nil {
			return
		}
		_ = restoreSnapshots(snapshots)
		if reloadAttempted && p.reloader != nil {
			_ = p.reloader.ReloadService(context.Background(), p.service)
		}
	}()
	if err = writeFileAtomic(p.configPath, rendered, 0o600); err != nil {
		return types.ConfigureMailResult{}, fmt.Errorf("write stalwart config: %w", err)
	}
	if err = writeFileAtomic(sidecarPath, rendered, 0o600); err != nil {
		return types.ConfigureMailResult{}, fmt.Errorf("write stalwart intent sidecar: %w", err)
	}
	if p.reloader != nil {
		reloadAttempted = true
		if err = p.reloader.ReloadService(ctx, p.service); err != nil {
			return types.ConfigureMailResult{}, fmt.Errorf("reload stalwart: %w", err)
		}
	}
	result.Changed = true
	return result, nil
}

func (p *MailProvisioner) serviceActive(ctx context.Context) bool {
	output, err := p.runner.Run(ctx, "systemctl", "is-active", p.service)
	return err == nil && strings.TrimSpace(string(output)) == "active"
}

func normalizeConfigureMailRequest(req types.ConfigureMailReq) (types.ConfigureMailReq, error) {
	req.Hostname = site.NormalizeDomain(req.Hostname)
	if err := site.ValidateDomain(req.Hostname); err != nil {
		return types.ConfigureMailReq{}, fmt.Errorf("invalid mail hostname: %w", err)
	}
	seen := make(map[string]bool, len(req.Domains))
	domains := make([]types.MailDomainConfig, 0, len(req.Domains))
	for _, domain := range req.Domains {
		domain.Domain = site.NormalizeDomain(domain.Domain)
		if domain.MailDomainID <= 0 {
			return types.ConfigureMailReq{}, errors.New("mail domain id is required")
		}
		if err := site.ValidateDomain(domain.Domain); err != nil {
			return types.ConfigureMailReq{}, err
		}
		if seen[domain.Domain] {
			continue
		}
		seen[domain.Domain] = true
		domains = append(domains, domain)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })
	req.Domains = domains
	req.OutboundRateLimit = strings.TrimSpace(req.OutboundRateLimit)
	if req.OutboundRateLimit != "" && !outboundRateLimitRE.MatchString(req.OutboundRateLimit) {
		return types.ConfigureMailReq{}, fmt.Errorf("invalid outbound rate limit %q", req.OutboundRateLimit)
	}
	if req.Smarthost != nil {
		host := strings.TrimSpace(req.Smarthost.Host)
		if site.ValidateDomain(site.NormalizeDomain(host)) != nil && net.ParseIP(host) == nil {
			return types.ConfigureMailReq{}, fmt.Errorf("invalid smarthost host %q", host)
		}
		req.Smarthost.Host = host
		if req.Smarthost.Port < 1 || req.Smarthost.Port > 65535 {
			return types.ConfigureMailReq{}, errors.New("invalid smarthost port")
		}
		for _, value := range []string{req.Smarthost.Username, req.Smarthost.Password} {
			for _, r := range value {
				if r < 0x20 || r > 0x7e {
					return types.ConfigureMailReq{}, errors.New("smarthost credentials must be printable ASCII")
				}
			}
		}
	}
	return req, nil
}

// ensureDKIMKey generates an RSA-2048 keypair for the domain on first use and
// reuses it forever after: re-running domain enablement never churns keys.
// The private key is written 0600 in a 0700 directory and never leaves the
// host; only the public TXT record value is returned.
func (p *MailProvisioner) ensureDKIMKey(domain string) (string, error) {
	dir := filepath.Join(p.dkimDir, domain)
	keyPath := filepath.Join(dir, DKIMSelector+".key")
	data, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key, genErr := rsa.GenerateKey(rand.Reader, 2048)
		if genErr != nil {
			return "", genErr
		}
		der, genErr := x509.MarshalPKCS8PrivateKey(key)
		if genErr != nil {
			return "", genErr
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if genErr = os.MkdirAll(dir, 0o700); genErr != nil {
			return "", genErr
		}
		if genErr = os.Chmod(dir, 0o700); genErr != nil {
			return "", genErr
		}
		if genErr = writeFileAtomic(keyPath, data, 0o600); genErr != nil {
			return "", genErr
		}
	} else if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("dkim key for %s is not PEM", domain)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse dkim key for %s: %w", domain, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("dkim key for %s is not RSA", domain)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return "v=DKIM1; h=sha256; k=rsa; p=" + base64.StdEncoding.EncodeToString(spki), nil
}

// renderConfig emits the complete Stalwart v0.11 configuration. Every key is
// declared local so this file — not Stalwart's internal settings store — is
// the single source of truth, matching the panel's config-generation
// invariant. Same intent renders byte-identical output.
func (p *MailProvisioner) renderConfig(req types.ConfigureMailReq) string {
	var b strings.Builder
	b.WriteString("# Managed by nakpanel (configure_mail). Do not edit: regenerated from panel intent.\n\n")
	b.WriteString("[config]\n")
	b.WriteString(`local-keys = ["store.*", "directory.*", "tracer.*", "!server.blocked-ip.*", "!server.allowed-ip.*", "server.*", "certificate.*", "config.local-keys.*", "authentication.fallback-admin.*", "storage.*", "lookup.*", "signature.*", "auth.*", "session.*", "queue.*", "remote.*", "report.*"]` + "\n\n")

	fmt.Fprintf(&b, "[server]\nhostname = %s\n\n", tomlString(req.Hostname))
	b.WriteString(`[server.listener."smtp"]
bind = ["[::]:25"]
protocol = "smtp"

[server.listener."submission"]
bind = ["[::]:587"]
protocol = "smtp"

[server.listener."submissions"]
bind = ["[::]:465"]
protocol = "smtp"
tls.implicit = true

[server.listener."imap"]
bind = ["[::]:143"]
protocol = "imap"

[server.listener."imaptls"]
bind = ["[::]:993"]
protocol = "imap"
tls.implicit = true

[server.listener."management"]
bind = ["127.0.0.1:8446"]
protocol = "http"

`)
	fmt.Fprintf(&b, "[storage]\ndata = \"rocksdb\"\nfts = \"rocksdb\"\nblob = \"rocksdb\"\nlookup = \"rocksdb\"\ndirectory = \"nakpanel\"\n\n")
	fmt.Fprintf(&b, "[store.\"rocksdb\"]\ntype = \"rocksdb\"\npath = %s\ncompression = \"lz4\"\n\n", tomlString(p.dataDir))
	fmt.Fprintf(&b, "[store.\"nakpanel\"]\ntype = \"postgresql\"\nhost = %s\nport = %d\ndatabase = %s\nuser = %s\npassword = %s\ntimeout = \"15s\"\n\n",
		tomlString(p.databaseHost), p.databasePort, tomlString(p.databaseName), tomlString(p.databaseUser), tomlString("%{file:"+p.pgPasswordPath+"}%"))
	b.WriteString(`[store."nakpanel".query]
name = "SELECT name, type, secret, description, quota FROM stalwart_accounts WHERE name = $1"
recipients = "SELECT name FROM stalwart_emails WHERE address = $1 ORDER BY name ASC"
emails = "SELECT address FROM stalwart_emails WHERE name = $1 ORDER BY type DESC, address ASC"

[directory."nakpanel"]
type = "sql"
store = "nakpanel"

[directory."nakpanel".columns]
class = "type"
secret = "secret"
description = "description"
quota = "quota"

[directory."nakpanel".cache]
ttl.positive = "30s"
ttl.negative = "5s"

`)
	fmt.Fprintf(&b, "[certificate.\"default\"]\ndefault = true\ncert = %s\nprivate-key = %s\n\n",
		tomlString("%{file:"+p.tlsCertPath+"}%"), tomlString("%{file:"+p.tlsKeyPath+"}%"))
	fmt.Fprintf(&b, "[authentication.fallback-admin]\nuser = \"admin\"\nsecret = %s\n\n", tomlString("%{file:"+p.adminSecretPath+"}%"))
	b.WriteString("[tracer.\"stdout\"]\ntype = \"stdout\"\nlevel = \"info\"\nansi = false\nenable = true\n\n")

	// Inbound routing is driven straight from panel intent: a recipient
	// domain is local exactly when it is an enabled row in mail_domains.
	next := "false"
	if req.Smarthost != nil {
		next = "\"'smarthost'\""
	}
	fmt.Fprintf(&b, "[queue.outbound]\nnext-hop = [ { if = \"sql_query('nakpanel', 'SELECT EXISTS(SELECT 1 FROM stalwart_domains WHERE name = $1)', rcpt_domain)\", then = \"'local'\" },\n             { else = %s } ]\n\n", next)
	if req.Smarthost != nil {
		// Relay certificates are accepted unverified in v1 so self-hosted
		// relays with private CAs work; pinning/verification is a documented
		// follow-up in docs/MAIL.md.
		fmt.Fprintf(&b, "[remote.\"smarthost\"]\naddress = %s\nport = %d\nprotocol = \"smtp\"\ntls.implicit = %t\ntls.allow-invalid-certs = true\n", tomlString(req.Smarthost.Host), req.Smarthost.Port, req.Smarthost.Port == 465)
		if req.Smarthost.Username != "" {
			fmt.Fprintf(&b, "auth.username = %s\nauth.secret = %s\n", tomlString(req.Smarthost.Username), tomlString(req.Smarthost.Password))
		}
		b.WriteString("\n")
	}
	if req.OutboundRateLimit != "" {
		// A compromised site must not become a spam cannon: cap queued
		// deliveries per sender domain. Stalwart defers (not drops) the
		// excess, which the queue sweep alerts on.
		fmt.Fprintf(&b, "[queue.limiter.outbound.\"sender-domain\"]\nkey = [\"sender_domain\"]\nrate = %s\nenable = true\n\n", tomlString(req.OutboundRateLimit))
	}

	b.WriteString("[auth.dkim]\nsign = [ { if = \"listener != 'smtp'\", then = \"['rsa-' + sender_domain]\" },\n         { else = false } ]\n\n")
	for _, domain := range req.Domains {
		if !domain.DKIM {
			continue
		}
		keyPath := filepath.Join(p.dkimDir, domain.Domain, DKIMSelector+".key")
		fmt.Fprintf(&b, "[signature.\"rsa-%s\"]\nprivate-key = %s\ndomain = %s\nselector = %s\nheaders = [\"From\", \"To\", \"Cc\", \"Date\", \"Subject\", \"Message-ID\", \"Organization\", \"MIME-Version\", \"Content-Type\", \"References\", \"In-Reply-To\", \"List-Id\"]\nalgorithm = \"rsa-sha256\"\ncanonicalization = \"relaxed/relaxed\"\nreport = false\n\n",
			domain.Domain, tomlString("%{file:"+keyPath+"}%"), tomlString(domain.Domain), tomlString(DKIMSelector))
	}
	return b.String()
}

func tomlString(value string) string {
	return strconv.Quote(value)
}

// CollectMailQueue reports Stalwart's outbound queue backlog per sender
// domain through the loopback management API, so the control plane can raise
// spike alerts without the agent exposing anything new.
func (p *MailProvisioner) CollectMailQueue(ctx context.Context) (types.CollectMailQueueResult, error) {
	secret, err := os.ReadFile(p.adminSecretPath)
	if err != nil {
		return types.CollectMailQueueResult{}, fmt.Errorf("read stalwart admin secret: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.managementURL+"/api/queue/messages?values=1&limit=1000", nil)
	if err != nil {
		return types.CollectMailQueueResult{}, err
	}
	request.SetBasicAuth("admin", strings.TrimSpace(string(secret)))
	response, err := p.httpClient.Do(request)
	if err != nil {
		return types.CollectMailQueueResult{}, fmt.Errorf("query stalwart queue: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return types.CollectMailQueueResult{}, err
	}
	if response.StatusCode != http.StatusOK {
		return types.CollectMailQueueResult{}, fmt.Errorf("stalwart queue query failed: status %d", response.StatusCode)
	}
	var payload struct {
		Data struct {
			Items []struct {
				ReturnPath string `json:"return_path"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return types.CollectMailQueueResult{}, fmt.Errorf("decode stalwart queue: %w", err)
	}
	result := types.CollectMailQueueResult{TotalQueued: len(payload.Data.Items), SenderDomains: map[string]int{}}
	for _, item := range payload.Data.Items {
		if _, domain, ok := strings.Cut(item.ReturnPath, "@"); ok && domain != "" {
			result.SenderDomains[strings.ToLower(domain)]++
		}
	}
	return result, nil
}

func (p *MailProvisioner) MailStatus(ctx context.Context) (types.MailServerStatus, error) {
	status := types.MailServerStatus{State: "unknown", TotalQueued: -1, CheckedAt: time.Now().UTC()}
	state, stateErr := p.runner.Run(ctx, "systemctl", "show", "--property=ActiveState", "--value", p.service)
	if stateErr == nil {
		status.State = strings.TrimSpace(string(state))
	} else {
		status.LastError = "service status unavailable"
	}
	if version, err := p.runner.Run(ctx, "stalwart-mail", "--version"); err == nil {
		status.Version = strings.TrimSpace(string(version))
	}
	if listeners, err := p.runner.Run(ctx, "ss", "-ltnH"); err == nil {
		wanted := map[int]bool{25: true, 143: true, 465: true, 587: true, 993: true}
		seen := map[int]bool{}
		for _, field := range strings.Fields(string(listeners)) {
			_, portText, err := net.SplitHostPort(field)
			if err != nil {
				if index := strings.LastIndex(field, ":"); index >= 0 {
					portText = field[index+1:]
				}
			}
			port, _ := strconv.Atoi(portText)
			if wanted[port] && !seen[port] {
				seen[port] = true
				status.Listeners = append(status.Listeners, port)
			}
		}
		sort.Ints(status.Listeners)
	}
	if status.State == "active" {
		queue, err := p.CollectMailQueue(ctx)
		if err != nil {
			if status.LastError == "" {
				status.LastError = "mail queue unavailable"
			}
		} else {
			status.TotalQueued = queue.TotalQueued
		}
	}
	return status, nil
}
