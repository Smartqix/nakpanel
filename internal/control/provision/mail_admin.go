package provision

import (
	"context"
	"errors"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type mailSettingsStore interface {
	MailSettings(context.Context) (controlquota.MailSettings, error)
	UpdateMailSettings(context.Context, controlquota.MailSettings) error
}

func (m *Manager) mailSettingsStore() (mailSettingsStore, error) {
	store, ok := m.quotaStore.(mailSettingsStore)
	if !ok {
		return nil, errors.New("mail settings are not configured")
	}
	return store, nil
}

func (m *Manager) MailSettings(ctx context.Context, actor auth.SessionUser) (types.MailSettingsView, error) {
	if actor.Role != auth.RoleAdmin {
		return types.MailSettingsView{}, ErrForbidden
	}
	store, err := m.mailSettingsStore()
	if err != nil {
		return types.MailSettingsView{}, err
	}
	settings, err := store.MailSettings(ctx)
	if err != nil {
		return types.MailSettingsView{}, err
	}
	return mailSettingsView(settings), nil
}

func (m *Manager) UpdateMailSettings(ctx context.Context, actor auth.SessionUser, update types.MailSettingsUpdate) (types.MailSettingsView, error) {
	if actor.Role != auth.RoleAdmin {
		return types.MailSettingsView{}, ErrForbidden
	}
	store, err := m.mailSettingsStore()
	if err != nil {
		return types.MailSettingsView{}, err
	}
	settings, err := store.MailSettings(ctx)
	if err != nil {
		return types.MailSettingsView{}, err
	}
	if update.ClearSmarthost {
		settings.SmarthostHost = ""
		settings.SmarthostPort = 587
		settings.SmarthostUsername = ""
		settings.SmarthostPassword = ""
	} else {
		if settings.SmarthostHost != "" && strings.TrimSpace(update.SmarthostHost) == "" {
			return types.MailSettingsView{}, errors.New("use Clear relay to remove the configured smarthost")
		}
		settings.SmarthostHost = update.SmarthostHost
		settings.SmarthostPort = update.SmarthostPort
		settings.SmarthostUsername = update.SmarthostUsername
		if update.SmarthostPassword != "" {
			settings.SmarthostPassword = update.SmarthostPassword
		}
	}
	settings.MailHostname = update.MailHostname
	settings.OutboundRateLimit = update.OutboundRateLimit
	settings.QueueAlertThreshold = update.QueueAlertThreshold
	if err := store.UpdateMailSettings(ctx, settings); err != nil {
		return types.MailSettingsView{}, err
	}
	return mailSettingsView(settings), nil
}

func (m *Manager) ReconfigureMail(ctx context.Context, actor auth.SessionUser) error {
	if actor.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	store, err := m.mailSettingsStore()
	if err != nil {
		return err
	}
	settings, err := store.MailSettings(ctx)
	if err != nil {
		return err
	}
	return store.UpdateMailSettings(ctx, settings)
}

func (m *Manager) MailServerStatus(ctx context.Context, actor auth.SessionUser) (types.MailServerStatus, error) {
	if actor.Role != auth.RoleAdmin {
		return types.MailServerStatus{}, ErrForbidden
	}
	if m.mailAgent == nil {
		return types.MailServerStatus{}, errors.New("mail agent is not configured")
	}
	return m.mailAgent.MailStatus(ctx)
}

func (m *Manager) RestartMail(ctx context.Context, actor auth.SessionUser) error {
	if actor.Role != auth.RoleAdmin {
		return ErrForbidden
	}
	if m.mailAgent == nil {
		return errors.New("mail agent is not configured")
	}
	response, err := m.mailAgent.ReloadService(ctx, "stalwart-mail.service")
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	return nil
}

func mailSettingsView(settings controlquota.MailSettings) types.MailSettingsView {
	return types.MailSettingsView{
		MailHostname: settings.MailHostname, SmarthostHost: settings.SmarthostHost,
		SmarthostPort: settings.SmarthostPort, SmarthostUsername: settings.SmarthostUsername,
		SmarthostConfigured: settings.SmarthostHost != "",
		OutboundRateLimit:   settings.OutboundRateLimit, QueueAlertThreshold: settings.QueueAlertThreshold,
	}
}
