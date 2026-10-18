package provision

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (m *Manager) MailClientSettings(ctx context.Context, actor auth.SessionUser, subscriptionID int64) (types.MailClientProfile, error) {
	if subscriptionID <= 0 {
		return types.MailClientProfile{}, ErrForbidden
	}
	if err := m.canManageSubscription(ctx, actor, subscriptionID); err != nil {
		return types.MailClientProfile{}, err
	}
	store, ok := m.quotaStore.(interface {
		MailClientHostname(context.Context) (string, error)
	})
	if !ok || m.mailAgent == nil {
		return types.MailClientProfile{}, errors.New("mail connection settings unavailable")
	}
	hostname, err := store.MailClientHostname(ctx)
	if err != nil {
		return types.MailClientProfile{}, errors.New("mail connection settings unavailable")
	}
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if site.ValidateDomain(hostname) != nil || net.ParseIP(hostname) != nil {
		return types.MailClientProfile{}, errors.New("mail hostname is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	status, err := m.mailAgent.MailStatus(ctx)
	if err != nil {
		return types.MailClientProfile{}, errors.New("mail service could not be checked")
	}
	profile := types.MailClientProfile{Hostname: hostname, CheckedAt: time.Now().UTC()}
	if status.State != "active" {
		return profile, nil
	}
	probe := m.mailClientProbe
	if probe == nil {
		probe = probeMailClientTLS
	}
	for _, endpoint := range []struct {
		port  int
		ready *bool
	}{{993, &profile.IMAPTLS}, {465, &profile.SMTPTLS}, {587, &profile.SMTPSTARTTLS}} {
		if slices.Contains(status.Listeners, endpoint.port) {
			*endpoint.ready = probe(ctx, hostname, endpoint.port) == nil
		}
	}
	return profile, nil
}

func probeMailClientTLS(ctx context.Context, hostname string, port int) error {
	if port != 993 && port != 465 && port != 587 {
		return errors.New("unsupported mail endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	// Only local managed services are probed; the hostname is used for TLS identity.
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	config := &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}
	if port == 587 {
		client, err := smtp.NewClient(conn, hostname)
		if err != nil {
			return err
		}
		defer client.Close()
		if err = client.StartTLS(config); err != nil {
			return err
		}
		return nil
	}
	return tls.Client(conn, config).HandshakeContext(ctx)
}
