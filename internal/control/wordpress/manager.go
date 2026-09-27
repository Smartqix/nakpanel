package wordpress

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	adminUserPattern  = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,60}$`)
	targetSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

type Manager struct {
	store       ManagerStore
	access      AccessPolicy
	provisioner Provisioner
}

func NewManager(store ManagerStore, access AccessPolicy, provisioner Provisioner) *Manager {
	return &Manager{store: store, access: access, provisioner: provisioner}
}

func (m *Manager) PreflightNewSite(ctx context.Context, actor auth.SessionUser, subscriptionID int64) error {
	if m == nil || m.store == nil || m.access == nil || subscriptionID <= 0 {
		return ErrNotFound
	}
	allowed, err := m.access.CanManageSubscription(ctx, actor, subscriptionID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrNotFound
	}
	return m.store.PreflightNewSite(ctx, subscriptionID)
}

func (m *Manager) authorize(ctx context.Context, actor auth.SessionUser, siteID int64) (SiteIdentity, error) {
	if m == nil || m.store == nil || m.access == nil || siteID <= 0 {
		return SiteIdentity{}, ErrNotFound
	}
	identity, err := m.store.SiteIdentity(ctx, siteID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return SiteIdentity{}, ErrNotFound
		}
		return SiteIdentity{}, err
	}
	allowed, err := m.access.CanManageDomain(ctx, actor, identity.Domain)
	if err != nil {
		return SiteIdentity{}, err
	}
	if !allowed {
		return SiteIdentity{}, ErrNotFound
	}
	return identity, nil
}

func (m *Manager) Workspace(ctx context.Context, actor auth.SessionUser, siteID int64) (Workspace, error) {
	identity, err := m.authorize(ctx, actor, siteID)
	if err != nil {
		return Workspace{}, err
	}
	workspace, err := m.store.Workspace(ctx, identity.SiteID)
	if err != nil {
		return Workspace{}, err
	}
	workspace.Site = identity
	return workspace, nil
}

func (m *Manager) Install(ctx context.Context, actor auth.SessionUser, siteID int64, input InstallInput) (Instance, Operation, error) {
	identity, err := m.authorize(ctx, actor, siteID)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	input, err = normalizeInstall(input)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	instance, operation, err := m.store.ReserveInstall(ctx, actor.ID, identity, input)
	if err != nil {
		return Instance{}, Operation{}, err
	}
	if m.provisioner == nil {
		err = errors.New("WordPress provisioning is unavailable")
		_ = m.store.FailReservation(ctx, instance.ID, operation.ID, err)
		return instance, operation, err
	}
	suffix, err := randomSuffix()
	if err != nil {
		_ = m.store.FailReservation(ctx, instance.ID, operation.ID, err)
		return instance, operation, err
	}
	databaseName := fmt.Sprintf("wp_s%d_%s", siteID, suffix)
	databaseUser := fmt.Sprintf("wp_u%d_%s", siteID, suffix)
	databaseID, err := m.provisioner.CreateDatabaseForSubscription(ctx, actor, identity.SubscriptionID, types.CreateDatabaseReq{
		SubscriptionID: identity.SubscriptionID, SiteID: identity.SiteID, Engine: types.EngineMariaDB,
		DBName: databaseName, DBUser: databaseUser,
	})
	if err != nil {
		_ = m.store.FailReservation(ctx, instance.ID, operation.ID, err)
		return instance, operation, err
	}
	if err = m.store.CompleteInstallReservation(ctx, instance.ID, operation.ID, databaseID, input.AdminPassword); err != nil {
		_ = m.store.FailReservation(ctx, instance.ID, operation.ID, err)
		return instance, operation, err
	}
	instance.DatabaseID = databaseID
	return instance, operation, nil
}

func (m *Manager) QueueOperation(ctx context.Context, actor auth.SessionUser, siteID int64, input OperationInput) (Operation, error) {
	identity, err := m.authorize(ctx, actor, siteID)
	if err != nil {
		return Operation{}, err
	}
	input, err = normalizeOperation(input)
	if err != nil {
		return Operation{}, err
	}
	instance, operation, err := m.store.ReserveOperation(ctx, actor.ID, identity, input)
	if err != nil {
		return Operation{}, err
	}
	if input.Action != types.WordPressActionUpdate {
		return operation, nil
	}
	if m.provisioner == nil {
		err = errors.New("WordPress backup provisioning is unavailable")
		_ = m.store.FailReservation(ctx, instance.ID, operation.ID, err)
		return operation, err
	}
	backupID, err := m.provisioner.CreateBackupForSubscription(ctx, actor, identity.SubscriptionID, types.CreateBackupReq{
		SubscriptionID: identity.SubscriptionID, Domain: identity.Domain, Username: identity.Username,
	})
	if err != nil {
		_ = m.store.FailReservation(ctx, instance.ID, operation.ID, err)
		return operation, err
	}
	if err = m.store.AttachBackupAndEnqueue(ctx, operation.ID, backupID); err != nil {
		_ = m.store.FailReservation(ctx, instance.ID, operation.ID, err)
		return operation, err
	}
	operation.BackupID = backupID
	operation.Status = "waiting_backup"
	return operation, nil
}

func (m *Manager) Detach(ctx context.Context, actor auth.SessionUser, siteID int64) error {
	identity, err := m.authorize(ctx, actor, siteID)
	if err != nil {
		return err
	}
	return m.store.Detach(ctx, actor.ID, identity)
}

func (m *Manager) Uninstall(ctx context.Context, actor auth.SessionUser, siteID int64, input UninstallInput) (Operation, error) {
	identity, err := m.authorize(ctx, actor, siteID)
	if err != nil {
		return Operation{}, err
	}
	input, err = normalizeUninstall(identity.Domain, input)
	if err != nil {
		return Operation{}, err
	}
	instance, operation, err := m.store.ReserveUninstall(ctx, actor, identity, input)
	if err != nil {
		return Operation{}, err
	}
	if !input.CreateBackup {
		return operation, nil
	}
	if m.provisioner == nil {
		err = errors.New("WordPress backup provisioning is unavailable")
		_ = m.store.FailUninstallReservation(ctx, instance.ID, operation.ID, err)
		return operation, err
	}
	backupID, err := m.provisioner.CreateBackupForSubscription(ctx, actor, identity.SubscriptionID, types.CreateBackupReq{
		SubscriptionID: identity.SubscriptionID,
		Domain:         identity.Domain,
		Username:       identity.Username,
	})
	if err != nil {
		_ = m.store.FailUninstallReservation(ctx, instance.ID, operation.ID, err)
		return operation, err
	}
	if err = m.store.AttachBackupAndEnqueue(ctx, operation.ID, backupID); err != nil {
		_ = m.store.FailUninstallReservation(ctx, instance.ID, operation.ID, err)
		return operation, err
	}
	operation.BackupID, operation.Status = backupID, "waiting_backup"
	return operation, nil
}

func normalizeUninstall(domain string, input UninstallInput) (UninstallInput, error) {
	input.ConfirmDomain = strings.TrimSpace(input.ConfirmDomain)
	if domain == "" || input.ConfirmDomain != domain || strings.ToLower(domain) != domain ||
		strings.ContainsAny(input.ConfirmDomain, "/:@?#\\\x00\r\n") ||
		(input.DeleteDatabase && !input.CreateBackup) {
		return input, ErrInvalidInput
	}
	return input, nil
}

func normalizeInstall(input InstallInput) (InstallInput, error) {
	input.Title = strings.TrimSpace(input.Title)
	input.AdminUser = strings.TrimSpace(input.AdminUser)
	input.AdminEmail = strings.TrimSpace(input.AdminEmail)
	input.Version = strings.TrimSpace(input.Version)
	if input.Version == "" {
		input.Version = "latest"
	}
	address, err := mail.ParseAddress(input.AdminEmail)
	if input.Title == "" || len(input.Title) > 200 || strings.ContainsAny(input.Title, "\x00\r\n") ||
		!adminUserPattern.MatchString(input.AdminUser) || err != nil || address.Address != input.AdminEmail ||
		len(input.AdminPassword) < 12 || len(input.AdminPassword) > 256 {
		return input, ErrInvalidInput
	}
	return input, nil
}

// ValidateInstallInput is shared by the standalone installer and the
// website-creation flow so malformed credentials never create an empty site.
func ValidateInstallInput(input InstallInput) (InstallInput, error) {
	return normalizeInstall(input)
}

func normalizeOperation(input OperationInput) (OperationInput, error) {
	input.TargetSlug = strings.ToLower(strings.TrimSpace(input.TargetSlug))
	input.RequestedVersion = strings.TrimSpace(input.RequestedVersion)
	switch input.Action {
	case types.WordPressActionInstall:
		if input.TargetType != "" || input.TargetSlug != "" || input.RequestedVersion != "" || input.AdminPassword != "" || input.Maintenance {
			return input, ErrInvalidInput
		}
	case types.WordPressActionDiscover, types.WordPressActionRefresh, types.WordPressActionVerify, types.WordPressActionHarden:
		if input.TargetType != "" || input.TargetSlug != "" || input.RequestedVersion != "" || input.AdminPassword != "" || input.Maintenance {
			return input, ErrInvalidInput
		}
	case types.WordPressActionMaintenance:
		if input.TargetType != "" || input.TargetSlug != "" || input.RequestedVersion != "" || input.AdminPassword != "" {
			return input, ErrInvalidInput
		}
	case types.WordPressActionUpdate:
		if input.RequestedVersion != "" || input.AdminPassword != "" || input.Maintenance {
			return input, ErrInvalidInput
		}
		if input.TargetType != types.WordPressTargetCore && input.TargetType != types.WordPressTargetPlugin &&
			input.TargetType != types.WordPressTargetTheme && input.TargetType != types.WordPressTargetAll {
			return input, ErrInvalidInput
		}
		if (input.TargetType == types.WordPressTargetPlugin || input.TargetType == types.WordPressTargetTheme) && !targetSlugPattern.MatchString(input.TargetSlug) {
			return input, ErrInvalidInput
		}
		if (input.TargetType == types.WordPressTargetCore || input.TargetType == types.WordPressTargetAll) && input.TargetSlug != "" {
			return input, ErrInvalidInput
		}
	case types.WordPressActionPasswordReset:
		if input.TargetType != "" || input.TargetSlug != "" || input.RequestedVersion != "" || input.Maintenance ||
			len(input.AdminPassword) < 12 || len(input.AdminPassword) > 256 {
			return input, ErrInvalidInput
		}
	default:
		return input, ErrInvalidInput
	}
	return input, nil
}

func randomSuffix() (string, error) {
	buffer := make([]byte, 4)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
