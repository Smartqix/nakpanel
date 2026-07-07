package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenUnixCreatesSocketWithMode0660(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "nakagent-main-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	socketPath := filepath.Join(dir, "agent.sock")

	listener, err := listenUnix(socketPath, "")
	if err != nil {
		t.Fatalf("listenUnix returned error: %v", err)
	}
	defer listener.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode().Type()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket: mode=%s", socketPath, info.Mode())
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %o, want 0660", info.Mode().Perm())
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial socket: %v", err)
	}
	_ = conn.Close()
}

func TestResolveAllowedPeerUIDFromEnv(t *testing.T) {
	t.Setenv("NAKPANEL_AGENT_ALLOWED_UID", "1234")

	uid, err := resolveAllowedPeerUID()
	if err != nil {
		t.Fatalf("resolveAllowedPeerUID returned error: %v", err)
	}
	if uid != 1234 {
		t.Fatalf("uid = %d, want 1234", uid)
	}
}

func TestResolveAllowedPeerUIDRejectsInvalidEnv(t *testing.T) {
	t.Setenv("NAKPANEL_AGENT_ALLOWED_UID", "not-a-uid")

	if _, err := resolveAllowedPeerUID(); err == nil {
		t.Fatal("resolveAllowedPeerUID returned nil error for invalid env")
	}
}
