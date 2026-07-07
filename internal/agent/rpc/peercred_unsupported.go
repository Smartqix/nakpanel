//go:build !linux

package rpc

import "net"

func peerUID(conn net.Conn) (uint32, bool, error) {
	return 0, false, nil
}
