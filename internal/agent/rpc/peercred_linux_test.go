//go:build linux

package rpc

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPeerUIDReadsUnixPeerUIDLinux(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	type result struct {
		uid uint32
		ok  bool
		err error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer conn.Close()
		uid, ok, err := peerUID(conn)
		done <- result{uid: uid, ok: ok, err: err}
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	defer client.Close()

	got := <-done
	if got.err != nil {
		t.Fatalf("peerUID returned error: %v", got.err)
	}
	if !got.ok {
		t.Fatal("peerUID did not report credentials for unix connection")
	}
	if got.uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid = %d, want %d", got.uid, os.Getuid())
	}
}

func TestServerRejectsWrongPeerUIDLinux(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := NewServer(NewDispatcher(&fakeReloader{}, Options{}), WithAllowedPeerUID(uint32(os.Getuid()+1)))
	go func() {
		_ = server.Serve(ctx, listener)
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if _, err := client.Write([]byte(`{"op":"ping","id":"01JPHASE900000000000000099","data":{}}` + "\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, `"ok":false`) || !strings.Contains(line, "unauthorized peer") {
		t.Fatalf("response line = %q", line)
	}
}
