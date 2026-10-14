package provision

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func (s *SiteRemovalService) removeCancelledCertificateStaging(ctx context.Context, scope string, args []any) error {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT args->>'staging_path' FROM river_job
WHERE kind='install_custom_cert' AND state='cancelled' AND `+scope+`
AND NOT EXISTS (SELECT 1 FROM river_job live WHERE live.kind='install_custom_cert'
AND live.args->>'staging_path'=river_job.args->>'staging_path'
AND live.state IN ('available','pending','scheduled','retryable','running'))`, args...)
	if err != nil {
		return err
	}
	paths := []string{}
	for rows.Next() {
		var path sql.NullString
		if err = rows.Scan(&path); err != nil {
			rows.Close()
			return err
		}
		if path.Valid && path.String != "" {
			paths = append(paths, path.String)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(paths) == 0 {
		return err
	}
	root := s.options.TLSStagingDirectory
	if root == "" {
		root = DefaultCustomTLSStagingDir
	}
	for _, path := range paths {
		if err = removePrivateCertificateStaging(root, path); err != nil {
			return err
		}
	}
	return nil
}

func removePrivateCertificateStaging(root, path string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return errors.New("invalid certificate staging directory")
	}
	path = filepath.Clean(path)
	name := filepath.Base(path)
	if filepath.Dir(path) != root || !strings.HasPrefix(name, "custom-") || !strings.HasSuffix(name, ".json") {
		return errors.New("cancelled certificate upload is outside private staging")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("could not inspect cancelled certificate upload")
	}
	directory, err := os.Lstat(root)
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0077 != 0 || !stagingOwnedByCurrentUser(directory) ||
		!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !stagingOwnedByCurrentUser(info) {
		return errors.New("cancelled certificate upload must use private owned staging")
	}
	// The private directory is panel-owned; no tenant can swap its entries.
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return errors.New("could not remove cancelled certificate upload")
	}
	return nil
}
