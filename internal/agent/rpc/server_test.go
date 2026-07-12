package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestHandleConnDecodesRequestAndWritesResponse(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dispatcher := NewDispatcher(&fakeReloader{}, Options{})

	done := make(chan error, 1)
	go func() {
		done <- HandleConn(context.Background(), serverSide, dispatcher)
	}()

	if _, err := clientSide.Write([]byte(`{"op":"ping","id":"01JPHASE200000000000000007","data":{}}` + "\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	var resp types.Response
	if err := json.NewDecoder(clientSide).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("response OK = false, error = %q", resp.Error)
	}
	if err := <-done; err != nil {
		t.Fatalf("HandleConn returned error: %v", err)
	}
}

func TestHandleConnRejectsInvalidJSON(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dispatcher := NewDispatcher(&fakeReloader{}, Options{})

	done := make(chan error, 1)
	go func() {
		done <- HandleConn(context.Background(), serverSide, dispatcher)
	}()

	if _, err := clientSide.Write([]byte(`not-json` + "\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	line, err := bufio.NewReader(clientSide).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, `"ok":false`) || !strings.Contains(line, "invalid request json") {
		t.Fatalf("response line = %q", line)
	}
	if err := <-done; err != nil {
		t.Fatalf("HandleConn returned error: %v", err)
	}
}

func TestHandleConnRejectsUnknownEnvelopeFields(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dispatcher := NewDispatcher(&fakeReloader{}, Options{})

	done := make(chan error, 1)
	go func() {
		done <- HandleConn(context.Background(), serverSide, dispatcher)
	}()

	if _, err := clientSide.Write([]byte(`{"op":"ping","id":"01JPHASE200000000000000010","data":{},"command":"id"}` + "\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	line, err := bufio.NewReader(clientSide).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, `"ok":false`) || !strings.Contains(line, "unknown field") {
		t.Fatalf("response line = %q", line)
	}
	if err := <-done; err != nil {
		t.Fatalf("HandleConn returned error: %v", err)
	}
}

func TestHandleConnRejectsMultipleJSONValues(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dispatcher := NewDispatcher(&fakeReloader{}, Options{})

	done := make(chan error, 1)
	go func() {
		done <- HandleConn(context.Background(), serverSide, dispatcher)
	}()

	if _, err := clientSide.Write([]byte(`{"op":"ping","id":"01JPHASE200000000000000012","data":{}} {"op":"ping"}` + "\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	line, err := bufio.NewReader(clientSide).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, `"ok":false`) || !strings.Contains(line, "multiple json values") {
		t.Fatalf("response line = %q", line)
	}
	if err := <-done; err != nil {
		t.Fatalf("HandleConn returned error: %v", err)
	}
}

func TestHandleConnRejectsOversizedRequest(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	dispatcher := NewDispatcher(&fakeReloader{}, Options{})

	done := make(chan error, 1)
	go func() {
		done <- HandleConn(context.Background(), serverSide, dispatcher)
	}()

	oversized := strings.Repeat("a", MaxRequestBytes+1)
	writeDone := make(chan struct{})
	go func() {
		_, _ = clientSide.Write([]byte(`{"op":"ping","id":"01JPHASE200000000000000011","data":{"blob":"` + oversized + `"}}` + "\n"))
		close(writeDone)
	}()

	line, err := bufio.NewReader(clientSide).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(line, `"ok":false`) || !strings.Contains(line, "request too large") {
		t.Fatalf("response line = %q", line)
	}
	if err := <-done; err != nil {
		t.Fatalf("HandleConn returned error: %v", err)
	}
	<-writeDone
}

func TestAllowedPeerUIDMatchesOnlyConfiguredUID(t *testing.T) {
	if !allowedPeerUIDMatches(1001, 1001) {
		t.Fatal("matching uid was rejected")
	}
	if allowedPeerUIDMatches(1002, 1001) {
		t.Fatal("different uid was allowed")
	}
	if allowedPeerUIDMatches(1001, -1) {
		t.Fatal("disabled policy allowed explicit match")
	}
}

func TestAuthorizePeerFailsClosedWhenCredentialsUnavailable(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	server := NewServer(NewDispatcher(&fakeReloader{}, Options{}), WithAllowedPeerUID(1001))
	if err := server.authorizePeer(serverSide); err == nil || !strings.Contains(err.Error(), "credentials are unavailable") {
		t.Fatalf("authorizePeer error = %v, want unavailable credentials", err)
	}
}
