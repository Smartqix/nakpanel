//go:build linux

package ops

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func assumeFileSystemIdentity(id siteIdentity) (func(), error) {
	if os.Geteuid() != 0 {
		return func() {}, nil
	}
	runtime.LockOSThread()
	oldGID, _, errno := unix.RawSyscall(unix.SYS_SETFSGID, ^uintptr(0), 0, 0)
	if errno != 0 {
		runtime.UnlockOSThread()
		return nil, errno
	}
	oldUID, _, errno := unix.RawSyscall(unix.SYS_SETFSUID, ^uintptr(0), 0, 0)
	if errno != 0 {
		runtime.UnlockOSThread()
		return nil, errno
	}
	if err := unix.Setfsgid(id.gid); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	if err := unix.Setfsuid(id.uid); err != nil {
		_ = unix.Setfsgid(int(oldGID))
		runtime.UnlockOSThread()
		return nil, err
	}
	currentUID, _, errno := unix.RawSyscall(unix.SYS_SETFSUID, ^uintptr(0), 0, 0)
	if errno != 0 || int(currentUID) != id.uid {
		_ = unix.Setfsuid(int(oldUID))
		_ = unix.Setfsgid(int(oldGID))
		runtime.UnlockOSThread()
		if errno != 0 {
			return nil, errno
		}
		return nil, errors.New("could not assume tenant filesystem identity")
	}
	return func() {
		_ = unix.Setfsuid(int(oldUID))
		_ = unix.Setfsgid(int(oldGID))
		runtime.UnlockOSThread()
	}, nil
}
