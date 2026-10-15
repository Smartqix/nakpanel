package mailimport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type workspaceStore interface {
	SiteSubscription(context.Context, int64) (int64, error)
	Workspace(context.Context, int64, string) (types.MailImportWorkspace, error)
	Folders(context.Context, string) ([]types.MailImportFolder, error)
}

func (m *Manager) Workspace(ctx context.Context, actor auth.SessionUser, siteID int64, importID string) (types.MailImportWorkspace, error) {
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		return types.MailImportWorkspace{}, ErrForbidden
	}
	store, ok := m.store.(workspaceStore)
	if !ok {
		return types.MailImportWorkspace{}, errors.New("mail import workspace unavailable")
	}
	sub, err := store.SiteSubscription(ctx, siteID)
	if err != nil {
		return types.MailImportWorkspace{}, err
	}
	allowed, err := m.access.CanManageSubscription(ctx, actor, sub)
	if err != nil {
		return types.MailImportWorkspace{}, err
	}
	if !allowed {
		return types.MailImportWorkspace{}, ErrNotFound
	}
	return store.Workspace(ctx, siteID, importID)
}
func (s *SQLStore) SiteSubscription(ctx context.Context, id int64) (int64, error) {
	var sub int64
	err := s.db.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE id=$1 AND desired_status<>'removing'`, id).Scan(&sub)
	if err != nil {
		return 0, ErrNotFound
	}
	return sub, nil
}
func (s *SQLStore) Folders(ctx context.Context, id string) ([]types.MailImportFolder, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.id,f.source_name,f.target_name,count(m.id),COALESCE(sum(m.byte_size),0),f.approved FROM mail_import_folders f LEFT JOIN mail_import_messages m ON m.folder_id=f.id WHERE f.import_id=$1 GROUP BY f.id ORDER BY f.source_name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.MailImportFolder{}
	for rows.Next() {
		var f types.MailImportFolder
		if err = rows.Scan(&f.ID, &f.Source, &f.Target, &f.Messages, &f.Bytes, &f.Approved); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
func (s *SQLStore) Workspace(ctx context.Context, siteID int64, id string) (types.MailImportWorkspace, error) {
	v := types.MailImportWorkspace{SiteID: siteID, Mailboxes: []types.MailImportMailbox{}, Imports: []types.MailImport{}}
	if err := s.db.QueryRowContext(ctx, `SELECT subscription_id,domain FROM sites WHERE id=$1`, siteID).Scan(&v.SubscriptionID, &v.Domain); err != nil {
		return v, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT mb.id,mb.local_part||'@'||md.domain,mb.enabled AND md.enabled AND md.effective_enabled FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.site_id=$1 ORDER BY mb.local_part`, siteID)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var box types.MailImportMailbox
		if err = rows.Scan(&box.ID, &box.Address, &box.Active); err != nil {
			rows.Close()
			return v, err
		}
		v.Mailboxes = append(v.Mailboxes, box)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT i.id FROM mail_imports i JOIN mailboxes mb ON mb.id=i.mailbox_id JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.site_id=$1 ORDER BY i.created_at DESC LIMIT 50`, siteID)
	if err != nil {
		return v, err
	}
	ids := []string{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return v, err
		}
		ids = append(ids, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	for _, key := range ids {
		item, err := s.Load(ctx, key)
		if err != nil {
			return v, err
		}
		v.Imports = append(v.Imports, item)
		if key == id {
			copy := item
			v.Selected = &copy
		}
	}
	if id != "" {
		if v.Selected == nil {
			return v, ErrNotFound
		}
		v.Folders, err = s.Folders(ctx, id)
		if err != nil {
			return v, err
		}
	}
	return v, nil
}
func (m *Manager) Stage(ctx context.Context, actor auth.SessionUser, siteID int64, input io.Reader) (types.StageMaildirResult, error) {
	workspace, err := m.Workspace(ctx, actor, siteID, "")
	if err != nil {
		return types.StageMaildirResult{}, err
	}
	active := false
	for _, box := range workspace.Mailboxes {
		active = active || box.Active
	}
	if !active {
		return types.StageMaildirResult{}, ErrInactive
	}
	if m.engine == nil {
		return types.StageMaildirResult{}, errors.New("mail import staging is unavailable")
	}
	factory, ok := m.engine.Factory.(*RuntimeFactory)
	if !ok || factory.Agent == nil {
		return types.StageMaildirResult{}, errors.New("mail import staging is unavailable")
	}
	root := "/var/lib/nakpanel/mail-import-uploads"
	if err = os.MkdirAll(root, 0700); err != nil {
		return types.StageMaildirResult{}, err
	}
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return types.StageMaildirResult{}, err
	}
	raw := hex.EncodeToString(b)
	id := raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
	path := filepath.Join(root, id+".tar")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return types.StageMaildirResult{}, err
	}
	defer os.Remove(path)
	n, err := io.Copy(file, io.LimitReader(input, (128<<20)+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || n > 128<<20 {
		return types.StageMaildirResult{}, errors.New("Maildir archive must be at most 128 MiB")
	}
	var result types.StageMaildirResult
	err = callAgent(ctx, factory.Agent, types.OpStageMaildir, types.StageMaildirReq{SubscriptionID: workspace.SubscriptionID, UploadID: id}, &result)
	return result, err
}
