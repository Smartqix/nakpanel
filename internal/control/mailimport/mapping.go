package mailimport

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func validTargetFolder(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func (m *Manager) MapFolders(ctx context.Context, actor auth.SessionUser, id string, mappings []types.MailImportMapping) error {
	if _, err := m.Status(ctx, actor, id); err != nil {
		return err
	}
	store, ok := m.store.(interface {
		MapFolders(context.Context, auth.SessionUser, string, []types.MailImportMapping) error
	})
	if !ok {
		return errors.New("folder mapping is unavailable")
	}
	return store.MapFolders(ctx, actor, id, mappings)
}
func (s *SQLStore) MapFolders(ctx context.Context, actor auth.SessionUser, id string, mappings []types.MailImportMapping) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	item, err := scanImport(tx.QueryRowContext(ctx, importSQL+` FOR UPDATE`, id))
	if err != nil {
		return err
	}
	if err = authorizeTx(ctx, tx, actor, item.SubscriptionID); err != nil {
		return err
	}
	if item.State != "preview" {
		return errors.New("folder mappings can only change before import starts")
	}
	var expected int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM mail_import_folders WHERE import_id=$1`, id).Scan(&expected); err != nil {
		return err
	}
	if len(mappings) != expected {
		return errors.New("review every source folder before starting")
	}
	names := map[string]bool{}
	ids := map[int64]bool{}
	for _, mapping := range mappings {
		name := strings.TrimSpace(mapping.Target)
		if mapping.FolderID <= 0 || ids[mapping.FolderID] || !validTargetFolder(name) {
			return errors.New("invalid destination folder mapping")
		}
		ids[mapping.FolderID] = true
		if mapping.Include {
			key := strings.ToLower(name)
			if names[key] {
				return errors.New("each source folder needs a distinct destination")
			}
			names[key] = true
		}
		result, err := tx.ExecContext(ctx, `UPDATE mail_import_folders SET target_name=$3,approved=$4 WHERE import_id=$1 AND id=$2`, id, mapping.FolderID, name, mapping.Include)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return ErrNotFound
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mail_import_messages SET state=CASE WHEN $2 THEN 'pending' ELSE 'excluded' END WHERE folder_id=$1`, mapping.FolderID, mapping.Include); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *SQLStore) FolderTargets(ctx context.Context, id string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source_name,target_name FROM mail_import_folders WHERE import_id=$1 AND approved`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var source, target string
		if err = rows.Scan(&source, &target); err != nil {
			return nil, err
		}
		out[source] = target
	}
	return out, rows.Err()
}
