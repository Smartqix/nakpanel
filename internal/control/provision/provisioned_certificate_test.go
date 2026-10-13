package provision

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"testing"
	"time"
)

type fakeCertificateSetup struct {
	state          ProvisionedCertificateState
	err, enableErr error
	enabled        int64
}

func (s *fakeCertificateSetup) PrepareProvisionedCertificate(context.Context, IssueCertArgs) (ProvisionedCertificateState, error) {
	return s.state, s.err
}
func (s *fakeCertificateSetup) EnableProvisionedHTTPS(_ context.Context, id int64) error {
	s.enabled = id
	return s.enableErr
}

func TestProvisionedCertificateWaitsWithoutCallingAgentOrFailingTLS(t *testing.T) {
	agent := &fakeAgentCertificateClient{}
	status := &recordingTLSStatusStore{}
	setup := &fakeCertificateSetup{}
	worker := NewIssueCertWorker(agent, status).WithProvisioningSetup(setup)
	err := worker.Work(context.Background(), &river.Job[IssueCertArgs]{JobRow: &rivertype.JobRow{CreatedAt: time.Now()}, Args: IssueCertArgs{SiteID: 7, AfterProvisioning: true}})
	var snooze *river.JobSnoozeError
	if !errors.As(err, &snooze) || agent.req.SiteID != 0 || status.failedID != 0 {
		t.Fatalf("err=%v agent=%#v status=%#v", err, agent.req, status)
	}
}
func TestProvisionedCertificateResumesHTTPSWithoutOrderingAnotherCertificate(t *testing.T) {
	agent := &fakeAgentCertificateClient{}
	status := &recordingTLSStatusStore{}
	setup := &fakeCertificateSetup{state: ProvisionedCertificateState{Ready: true, Installed: true, Args: IssueCertArgs{SiteID: 7}}}
	err := NewIssueCertWorker(agent, status).WithProvisioningSetup(setup).Work(context.Background(), &river.Job[IssueCertArgs]{JobRow: &rivertype.JobRow{CreatedAt: time.Now()}, Args: IssueCertArgs{SiteID: 7, AfterProvisioning: true}})
	if err != nil || agent.req.SiteID != 0 || setup.enabled != 7 {
		t.Fatalf("err=%v agent=%#v enabled=%d", err, agent.req, setup.enabled)
	}
}
func TestProvisionedCertificateInstallsBeforeEnablingHTTPS(t *testing.T) {
	args := IssueCertArgs{SiteID: 7, Domain: "example.test", Issuer: types.CertIssuerACME, AfterProvisioning: true}
	data, _ := json.Marshal(types.IssueCertResult{Domain: args.Domain, Issuer: args.Issuer, CertPath: "/cert.pem", KeyPath: "/key.pem", ExpiresAt: time.Now().Add(time.Hour)})
	agent := &fakeAgentCertificateClient{resp: types.Response{OK: true, Data: data}}
	status := &recordingTLSStatusStore{}
	setup := &fakeCertificateSetup{state: ProvisionedCertificateState{Ready: true, Args: args}}
	err := NewIssueCertWorker(agent, status).WithProvisioningSetup(setup).Work(context.Background(), &river.Job[IssueCertArgs]{JobRow: &rivertype.JobRow{CreatedAt: time.Now()}, Args: args})
	if err != nil || status.activeID != 7 || setup.enabled != 7 || !agent.req.ReuseExisting {
		t.Fatalf("err=%v agent=%#v status=%#v enabled=%d", err, agent.req, status, setup.enabled)
	}
}
func TestProvisionedCertificateChallengeDelayKeepsPendingAndStopsAtDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		created := time.Now()
		if expired {
			created = created.Add(-16 * time.Minute)
		}
		args := IssueCertArgs{SiteID: 7, AfterProvisioning: true}
		agent := &fakeAgentCertificateClient{resp: types.Response{ErrorCode: types.ErrorACMEChallengePending, Error: "Waiting for public DNS"}}
		status := &recordingTLSStatusStore{}
		setup := &fakeCertificateSetup{state: ProvisionedCertificateState{Ready: true, Args: args}}
		err := NewIssueCertWorker(agent, status).WithProvisioningSetup(setup).Work(context.Background(), &river.Job[IssueCertArgs]{JobRow: &rivertype.JobRow{CreatedAt: created}, Args: args})
		var snooze *river.JobSnoozeError
		if expired {
			if err == nil || status.failedID != 7 {
				t.Fatalf("unbounded pending err=%v status=%#v", err, status)
			}
		} else if !errors.As(err, &snooze) || status.failedID != 0 {
			t.Fatalf("transient delay err=%v status=%#v", err, status)
		}
	}
}
