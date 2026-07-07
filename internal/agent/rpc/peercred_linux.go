//go:build linux

package rpc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(conn net.Conn) (uint32, bool, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false, nil
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, true, fmt.Errorf("get syscall conn: %w", err)
	}
	var uid uint32
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = ucred.Uid
	}); err != nil {
		return 0, true, fmt.Errorf("control unix conn: %w", err)
	}
	if controlErr != nil {
		return 0, true, fmt.Errorf("get peer credentials: %w", controlErr)
	}
	return uid, true, nil
}
