package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
)

// MailSettings is the node-wide mail delivery configuration (single row):
// EHLO hostname, optional outbound smarthost, the per-tenant outbound rate
// limit, and the queue-backlog alert threshold.
type MailSettings struct {
	MailHostname        string
	SmarthostHost       string
	SmarthostPort       int
	SmarthostUsername   string
	SmarthostPassword   string
	OutboundRateLimit   string
	QueueAlertThreshold int
}

var mailRateLimitRE = regexp.MustCompile(`^[0-9]{1,9}/[0-9]{1,4}[smhd]$`)

func ReadMailSettings(ctx context.Context, db *sql.DB) (MailSettings, error) {
	var settings MailSettings
	err := db.QueryRowContext(ctx, `SELECT mail_hostname,smarthost_host,smarthost_port,smarthost_username,smarthost_password,outbound_rate_limit,queue_alert_threshold FROM mail_settings WHERE id`).Scan(
		&settings.MailHostname, &settings.SmarthostHost, &settings.SmarthostPort,
		&settings.SmarthostUsername, &settings.SmarthostPassword,
		&settings.OutboundRateLimit, &settings.QueueAlertThreshold,
	)
	return settings, err
}

func (s *SQLStore) MailSettings(ctx context.Context) (MailSettings, error) {
	return ReadMailSettings(ctx, s.db)
}

// UpdateMailSettings persists the node mail settings and queues a Stalwart
// reconfiguration. The smarthost password is stored so the agent can render
// it into Stalwart's root-only config; it is never returned by list APIs.
func (s *SQLStore) UpdateMailSettings(ctx context.Context, settings MailSettings) error {
	settings.MailHostname = site.NormalizeDomain(settings.MailHostname)
	if settings.MailHostname != "" && site.ValidateDomain(settings.MailHostname) != nil {
		return errors.New("invalid mail hostname")
	}
	settings.SmarthostHost = strings.TrimSpace(settings.SmarthostHost)
	if settings.SmarthostHost != "" {
		if site.ValidateDomain(site.NormalizeDomain(settings.SmarthostHost)) != nil && net.ParseIP(settings.SmarthostHost) == nil {
			return fmt.Errorf("invalid smarthost host %q", settings.SmarthostHost)
		}
		if settings.SmarthostPort < 1 || settings.SmarthostPort > 65535 {
			return errors.New("invalid smarthost port")
		}
	}
	settings.OutboundRateLimit = strings.TrimSpace(settings.OutboundRateLimit)
	if settings.OutboundRateLimit != "" && !mailRateLimitRE.MatchString(settings.OutboundRateLimit) {
		return fmt.Errorf("invalid outbound rate limit %q (use forms like 200/1h)", settings.OutboundRateLimit)
	}
	if settings.QueueAlertThreshold < 1 {
		return errors.New("queue alert threshold must be at least 1")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE mail_settings SET mail_hostname=$1,smarthost_host=$2,smarthost_port=$3,smarthost_username=$4,smarthost_password=$5,outbound_rate_limit=$6,queue_alert_threshold=$7,updated_at=now() WHERE id`,
		settings.MailHostname, settings.SmarthostHost, settings.SmarthostPort,
		settings.SmarthostUsername, settings.SmarthostPassword,
		settings.OutboundRateLimit, settings.QueueAlertThreshold); err != nil {
		return err
	}
	if s.river != nil {
		if _, err = s.river.InsertTx(ctx, tx, NewConfigureMailArgs(), nil); err != nil {
			return err
		}
	}
	return tx.Commit()
}
