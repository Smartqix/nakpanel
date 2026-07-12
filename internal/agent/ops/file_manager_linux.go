//go:build linux

package ops

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func verifyManagedPath(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open file manager root: %w", err)
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return fmt.Errorf("resolve managed path: %w", err)
	}
	return unix.Close(fd)
}
