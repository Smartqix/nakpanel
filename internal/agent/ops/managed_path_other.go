//go:build !linux

package ops

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func ensureManagedDirectory(root, target string, mode os.FileMode) error {
	if err := os.MkdirAll(root, mode); err != nil {
		return err
	}
	if err := ensureNoSymlinkComponents(root, root); err != nil {
		return err
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("managed directory escapes its root")
	}
	if rel == "." {
		return nil
	}
	if err := ensureNoSymlinkComponents(root, filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.MkdirAll(target, mode); err != nil {
		return err
	}
	return ensureNoSymlinkComponents(root, target)
}

func secureDirectoryAnchor(path string, uid, gid int, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("directory anchor must be a real directory")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}

func secureHostedPath(root, target string, info fs.FileInfo, gid int) error {
	current, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 {
		return errors.New("hosted path changed during permission update")
	}
	if err := os.Chown(target, -1, gid); err != nil {
		return err
	}
	mode := info.Mode().Perm() & 0o700
	if info.IsDir() {
		mode |= 0o2050
	} else if info.Mode().IsRegular() {
		if filepath.Base(target) != "wp-config.php" {
			mode |= 0o040
		}
	} else {
		return errors.New("hosted tree contains an unsupported file type")
	}
	return os.Chmod(target, mode)
}
