//go:build linux

package ops

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func ensureManagedDirectory(root, target string, mode os.FileMode) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create managed root: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed root must be a real directory")
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("managed directory escapes its root")
	}
	if rel == "." {
		return nil
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open managed root: %w", err)
	}
	defer unix.Close(rootFD)

	parentFD := rootFD
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("managed directory contains an unsafe component")
		}
		if err := unix.Mkdirat(parentFD, component, uint32(mode.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create managed directory %q: %w", component, err)
		}
		nextFD, err := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("open managed directory %q: %w", component, err)
		}
		if parentFD != rootFD {
			_ = unix.Close(parentFD)
		}
		parentFD = nextFD
	}
	if parentFD != rootFD {
		defer unix.Close(parentFD)
	}
	return nil
}

func secureDirectoryAnchor(path string, uid, gid int, mode os.FileMode) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open directory anchor %q: %w", path, err)
	}
	defer unix.Close(fd)
	if os.Geteuid() == 0 {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return fmt.Errorf("chown directory anchor %q: %w", path, err)
		}
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("chmod directory anchor %q: %w", path, err)
	}
	return nil
}

func secureHostedPath(root, target string, info fs.FileInfo, gid int) error {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("hosted path escapes its root")
	}
	if rel == "" {
		rel = "."
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open hosted root: %w", err)
	}
	defer unix.Close(rootFD)
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK)
	if info.IsDir() {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   flags,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return fmt.Errorf("open hosted path without symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), target)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("wrap hosted path descriptor")
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) {
		return errors.New("hosted path changed during permission update")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if err := unix.Fchown(fd, int(stat.Uid), gid); err != nil {
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
	return unix.Fchmod(fd, uint32(mode))
}
