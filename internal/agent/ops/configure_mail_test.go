package ops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

// staticStateRunner answers every `systemctl is-active` probe with one state.
type staticStateRunner struct{ state string }

func (r staticStateRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.state + "\n"), nil
}

func testMailProvisioner(t *testing.T, reloader SiteServiceReloader) *MailProvisioner {
	t.Helper()
	root := t.TempDir()
	return NewMailProvisioner(MailProvisionerOptions{
		ConfigPath:      filepath.Join(root, "etc", "config.toml"),
		DKIMDir:         filepath.Join(root, "dkim"),
		DataDir:         filepath.Join(root, "data"),
		PgPasswordPath:  filepath.Join(root, "etc", "pg-password"),
		AdminSecretPath: filepath.Join(root, "etc", "admin-secret"),
		TLSCertPath:     filepath.Join(root, "tls", "cert.pem"),
		TLSKeyPath:      filepath.Join(root, "tls", "key.pem"),
		Reloader:        reloader,
		Runner:          staticStateRunner{state: "active"},
	})
}

func TestConfigureMailIsIdempotentAndKeepsDKIMKeys(t *testing.T) {
	t.Parallel()
	reloader := &recordingPhase6Reloader{}
	p := testMailProvisioner(t, reloader)
	req := types.ConfigureMailReq{
		Hostname: "mail.node.test",
		Domains: []types.MailDomainConfig{
			{MailDomainID: 2, Domain: "zeta.test", DKIM: false},
			{MailDomainID: 1, Domain: "alpha.test", DKIM: true},
		},
		OutboundRateLimit: "200/1h",
	}
	first, err := p.ConfigureMail(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || len(reloader.services) != 1 || reloader.services[0] != "stalwart-mail.service" {
		t.Fatalf("first run must write config and reload stalwart: changed=%v services=%v", first.Changed, reloader.services)
	}
	if len(first.DKIM) != 1 || first.DKIM[0].Domain != "alpha.test" || first.DKIM[0].Selector != DKIMSelector {
		t.Fatalf("dkim result = %+v", first.DKIM)
	}
	if !strings.HasPrefix(first.DKIM[0].Record, "v=DKIM1; h=sha256; k=rsa; p=") {
		t.Fatalf("dkim record = %q", first.DKIM[0].Record)
	}
	configBytes, err := os.ReadFile(p.configPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(p.dkimDir, "alpha.test", DKIMSelector+".key")
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("dkim private key must be 0600: %v %v", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Dir(keyPath)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dkim key directory must be 0700: %v %v", info.Mode(), err)
	}
	if info, err := os.Stat(p.configPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stalwart config must be 0600: %v %v", info.Mode(), err)
	}

	second, err := p.ConfigureMail(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || len(reloader.services) != 1 {
		t.Fatalf("unchanged intent must not rewrite or reload: changed=%v services=%v", second.Changed, reloader.services)
	}
	if second.DKIM[0].Record != first.DKIM[0].Record {
		t.Fatal("re-running configure_mail rotated the DKIM key")
	}
	afterKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterKey) != string(keyBytes) {
		t.Fatal("dkim private key bytes changed on re-run")
	}
	afterConfig, err := os.ReadFile(p.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterConfig) != string(configBytes) {
		t.Fatal("config render is not byte-identical for identical intent")
	}
}

func TestConfigureMailRendersExpectedSections(t *testing.T) {
	t.Parallel()
	p := testMailProvisioner(t, &recordingPhase6Reloader{})
	req, err := normalizeConfigureMailRequest(types.ConfigureMailReq{
		Hostname: "mail.node.test",
		Domains:  []types.MailDomainConfig{{MailDomainID: 1, Domain: "alpha.test", DKIM: true}},
		Smarthost: &types.MailSmarthostConfig{
			Host: "relay.example.test", Port: 587, Username: "relay-user", Password: "relay-pass",
		},
		OutboundRateLimit: "100/1h",
	})
	if err != nil {
		t.Fatal(err)
	}
	rendered := p.renderConfig(req)
	for _, want := range []string{
		`hostname = "mail.node.test"`,
		`directory = "nakpanel"`,
		`type = "postgresql"`,
		`name = "SELECT name, type, secret, description, quota FROM stalwart_accounts WHERE name = $1"`,
		`recipients = "SELECT name FROM stalwart_emails WHERE address = $1 ORDER BY name ASC"`,
		`sql_query('nakpanel', 'SELECT EXISTS(SELECT 1 FROM stalwart_domains WHERE name = $1)', rcpt_domain)`,
		`else = "'smarthost'"`,
		`[remote."smarthost"]`,
		`auth.username = "relay-user"`,
		`[queue.limiter.outbound."sender-domain"]`,
		`rate = "100/1h"`,
		`[signature."rsa-alpha.test"]`,
		`selector = "nak1"`,
		`[authentication.fallback-admin]`,
		`local-keys = ["store.*"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config is missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "PRIVATE KEY") {
		t.Fatal("rendered config must reference DKIM keys via file macros, never inline them")
	}
}

func TestConfigureMailValidatesInput(t *testing.T) {
	t.Parallel()
	p := testMailProvisioner(t, &recordingPhase6Reloader{})
	for name, req := range map[string]types.ConfigureMailReq{
		"missing hostname": {Domains: []types.MailDomainConfig{{MailDomainID: 1, Domain: "a.test"}}},
		"bad domain":       {Hostname: "mail.node.test", Domains: []types.MailDomainConfig{{MailDomainID: 1, Domain: "not a domain"}}},
		"missing id":       {Hostname: "mail.node.test", Domains: []types.MailDomainConfig{{Domain: "a.test"}}},
		"bad rate":         {Hostname: "mail.node.test", OutboundRateLimit: "lots"},
		"bad smarthost":    {Hostname: "mail.node.test", Smarthost: &types.MailSmarthostConfig{Host: "relay.test", Port: 0}},
		"binary secret":    {Hostname: "mail.node.test", Smarthost: &types.MailSmarthostConfig{Host: "relay.test", Port: 587, Username: "u", Password: "a\nb"}},
	} {
		if _, err := p.ConfigureMail(context.Background(), req); err == nil {
			t.Fatalf("%s: invalid request was accepted", name)
		}
	}
	if _, err := os.Stat(p.configPath); !os.IsNotExist(err) {
		t.Fatal("invalid requests must not write config")
	}
}

func TestConfigureMailStartsStoppedServiceOnUnchangedConfig(t *testing.T) {
	t.Parallel()
	reloader := &recordingPhase6Reloader{}
	p := testMailProvisioner(t, reloader)
	req := types.ConfigureMailReq{Hostname: "mail.node.test"}
	if _, err := p.ConfigureMail(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	p.runner = staticStateRunner{state: "inactive"}
	result, err := p.ConfigureMail(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || len(reloader.services) != 2 {
		t.Fatalf("unchanged config with a stopped service must start it: changed=%v reloads=%v", result.Changed, reloader.services)
	}
}

func TestConfigureMailRestoresConfigWhenReloadFails(t *testing.T) {
	t.Parallel()
	reloader := &recordingPhase6Reloader{}
	p := testMailProvisioner(t, reloader)
	req := types.ConfigureMailReq{Hostname: "mail.node.test"}
	if _, err := p.ConfigureMail(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p.configPath)
	if err != nil {
		t.Fatal(err)
	}
	reloader.err = context.DeadlineExceeded
	req.OutboundRateLimit = "9/1h"
	if _, err := p.ConfigureMail(context.Background(), req); err == nil {
		t.Fatal("reload failure must fail the operation")
	}
	after, err := os.ReadFile(p.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed reload must restore the previous config")
	}
}

func TestCollectMailQueueAggregatesSenderDomains(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "hunter2" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/queue/messages" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"items":[
			{"return_path":"wp@compromised.test"},
			{"return_path":"wp@compromised.test"},
			{"return_path":"alice@calm.test"},
			{"return_path":""}
		],"status":true}}`))
	}))
	defer server.Close()
	root := t.TempDir()
	secretPath := filepath.Join(root, "admin-secret")
	if err := os.WriteFile(secretPath, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewMailProvisioner(MailProvisionerOptions{
		AdminSecretPath: secretPath,
		ManagementURL:   server.URL,
	})
	result, err := p.CollectMailQueue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalQueued != 4 || result.SenderDomains["compromised.test"] != 2 || result.SenderDomains["calm.test"] != 1 {
		t.Fatalf("queue aggregation = %+v", result)
	}
}

func TestRenderTXTValueSplitsLongRecords(t *testing.T) {
	t.Parallel()
	if got := renderTXTValue("v=spf1 mx ~all"); got != `"v=spf1 mx ~all"` {
		t.Fatalf("short TXT = %s", got)
	}
	long := strings.Repeat("a", 600)
	rendered := renderTXTValue(long)
	var rebuilt strings.Builder
	for _, chunk := range strings.Split(rendered, `" "`) {
		chunk = strings.Trim(chunk, `"`)
		if len(chunk) > 255 {
			t.Fatalf("chunk exceeds 255 octets: %d", len(chunk))
		}
		rebuilt.WriteString(chunk)
	}
	if rebuilt.String() != long {
		t.Fatal("chunked TXT does not reassemble to the original value")
	}
}
