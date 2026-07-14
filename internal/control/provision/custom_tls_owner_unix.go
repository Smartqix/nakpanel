//go:build unix

package provision

import (
	"errors"
	"os"
	"syscall"
)

func setStagingFileOwner(dir, path string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("staging directory ownership is unavailable")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}
