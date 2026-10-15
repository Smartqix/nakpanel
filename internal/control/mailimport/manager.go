package mailimport

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ErrNotFound  = errors.New("mail import not found")
	ErrForbidden = errors.New("mail imports require a provider account")
	ErrInactive  = errors.New("the destination mailbox and its subscription must be active with mail enabled")
)

type Mailbox struct {
	ID, SubscriptionID int64
	Address            string
	Active             bool
}
type AccessPolicy interface {
	CanManageSubscription(context.Context, auth.SessionUser, int64) (bool, error)
}
type Store interface {
	Mailbox(context.Context, int64) (Mailbox, error)
	Preview(context.Context, auth.SessionUser, types.MailImportRequest) (types.MailImportPreview, error)
	Load(context.Context, string) (types.MailImport, error)
	Start(context.Context, auth.SessionUser, string) (types.MailImport, error)
}
type Manager struct {
	store  Store
	access AccessPolicy
	engine *Engine
}

func NewManager(s Store, a AccessPolicy) *Manager { return &Manager{store: s, access: a} }
func (m *Manager) SetEngine(engine *Engine)       { m.engine = engine }
func (m *Manager) authorize(ctx context.Context, actor auth.SessionUser, id int64) (Mailbox, error) {
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		return Mailbox{}, ErrForbidden
	}
	if m == nil || m.store == nil || m.access == nil || id <= 0 {
		return Mailbox{}, ErrNotFound
	}
	box, err := m.store.Mailbox(ctx, id)
	if err != nil {
		return box, err
	}
	allowed, err := m.access.CanManageSubscription(ctx, actor, box.SubscriptionID)
	if err != nil {
		return box, err
	}
	if !allowed {
		return Mailbox{}, ErrNotFound
	}
	return box, nil
}
func (m *Manager) Preview(ctx context.Context, actor auth.SessionUser, req types.MailImportRequest) (types.MailImportPreview, error) {
	box, err := m.authorize(ctx, actor, req.MailboxID)
	if err != nil {
		return types.MailImportPreview{}, err
	}
	if !box.Active {
		return types.MailImportPreview{}, ErrInactive
	}
	req.SourceHost = strings.ToLower(strings.TrimSpace(req.SourceHost))
	switch req.SourceKind {
	case "imap":
		if req.SourcePort == 0 {
			req.SourcePort = 993
		}
		if req.SourcePort != 993 {
			return types.MailImportPreview{}, errors.New("source IMAP requires TLS on port 993")
		}
		if site.ValidateDomain(req.SourceHost) != nil || net.ParseIP(req.SourceHost) != nil || strings.TrimSpace(req.SourceUser) == "" {
			return types.MailImportPreview{}, errors.New("a valid source IMAP hostname and username are required")
		}
	case "maildir":
		if !validStagingID(req.StagingID) || len(req.ManifestSHA256) != 64 {
			return types.MailImportPreview{}, errors.New("a staged Maildir archive is required")
		}
	default:
		return types.MailImportPreview{}, errors.New("unsupported mail import source")
	}
	if (req.TargetSecretID == "" && req.TargetPassword == "") || req.SourceKind == "imap" && req.SourceSecretID == "" && req.SourcePassword == "" {
		return types.MailImportPreview{}, errors.New("mail import credentials are required")
	}
	preview, err := m.store.Preview(ctx, actor, req)
	if err != nil {
		return preview, err
	}
	if m.engine != nil {
		if err = m.engine.Prepare(ctx, preview.ID); err != nil {
			_, _ = m.Cancel(ctx, actor, preview.ID)
			return types.MailImportPreview{}, err
		}
	}
	if store, ok := m.store.(workspaceStore); ok {
		preview.Folders, err = store.Folders(ctx, preview.ID)
		if err != nil {
			return types.MailImportPreview{}, err
		}
	}
	return preview, nil
}
func validStagingID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef-", c) {
			return false
		}
	}
	return true
}
func (m *Manager) Status(ctx context.Context, actor auth.SessionUser, id string) (types.MailImport, error) {
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		return types.MailImport{}, ErrForbidden
	}
	if m == nil || m.store == nil {
		return types.MailImport{}, ErrNotFound
	}
	item, err := m.store.Load(ctx, id)
	if err != nil {
		return item, err
	}
	_, err = m.authorize(ctx, actor, item.MailboxID)
	if err != nil {
		return types.MailImport{}, err
	}
	return item, nil
}
func (m *Manager) Start(ctx context.Context, actor auth.SessionUser, id string) (types.MailImport, error) {
	item, err := m.Status(ctx, actor, id)
	if err != nil {
		return item, err
	}
	box, err := m.authorize(ctx, actor, item.MailboxID)
	if err != nil {
		return types.MailImport{}, err
	}
	if !box.Active {
		return types.MailImport{}, ErrInactive
	}
	return m.store.Start(ctx, actor, id)
}

type ImportArgs struct {
	ImportID string `json:"import_id"`
	Revision int64  `json:"revision"`
}

func (ImportArgs) Kind() string { return "mail_import" }
