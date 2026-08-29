package provision

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type mailConvergenceAgentStub struct {
	requests []types.ConfigureMailReq
}

func (s *mailConvergenceAgentStub) ConfigureMail(_ context.Context, req types.ConfigureMailReq) (types.Response, error) {
	s.requests = append(s.requests, req)
	data, _ := json.Marshal(types.ConfigureMailResult{ConfigPath: "/etc/stalwart/config.toml"})
	return types.Response{OK: true, Data: data}, nil
}

func TestConfigureMailWorkerClearsLastHostedDomain(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT mail_hostname`).
		WillReturnRows(sqlmock.NewRows([]string{
			"mail_hostname", "smarthost_host", "smarthost_port", "smarthost_username",
			"smarthost_password", "outbound_rate_limit", "queue_alert_threshold",
		}).AddRow("", "", 587, "", "", "", 25))
	mock.ExpectQuery(`FROM mail_domains domain`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "subscription_id", "domain", "enabled", "lifecycle_active",
			"delete_requested", "dkim_enabled", "dmarc_policy",
		}))

	agent := &mailConvergenceAgentStub{}
	worker := NewConfigureMailWorker(db, agent)
	worker.phase6 = &SQLPhase6Repository{}
	err = worker.Work(context.Background(), &river.Job[controlquota.ConfigureMailArgs]{
		Args: controlquota.NewConfigureMailArgs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.requests) != 1 {
		t.Fatalf("mail convergence requests = %d, want 1", len(agent.requests))
	}
	request := agent.requests[0]
	if request.Hostname != "mail.localhost.localdomain" || len(request.Domains) != 0 {
		t.Fatalf("empty mail convergence request = %+v", request)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEffectiveMailDomainEnabledHonorsLifecycleAndEntitlement(t *testing.T) {
	domain := mailDomainRow{Enabled: true, LifecycleActive: true}
	var policy types.HostingPolicy
	policy.Permissions.Mail = true
	policy.Mail.Enabled = true
	if !effectiveMailDomainEnabled(domain, policy) {
		t.Fatal("active entitled mail domain was disabled")
	}
	domain.LifecycleActive = false
	if effectiveMailDomainEnabled(domain, policy) {
		t.Fatal("suspended mail domain remained effective")
	}
	domain.LifecycleActive = true
	policy.Permissions.Mail = false
	if effectiveMailDomainEnabled(domain, policy) {
		t.Fatal("revoked mail entitlement remained effective")
	}
}
