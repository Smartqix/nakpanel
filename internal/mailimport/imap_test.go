package mailimport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type fixtureSession struct {
	imapserver.Session
	conn *imapserver.Conn
	drop *atomic.Bool
}

func (s fixtureSession) Append(mailbox string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	data, err := s.Session.Append(mailbox, r, options)
	if err == nil && s.drop != nil && s.drop.CompareAndSwap(true, false) {
		_ = s.conn.NetConn().Close()
	}
	return data, err
}

func (s fixtureSession) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	data, err := s.Session.Select(name, options)
	if err == nil {
		data.PermanentFlags = append(data.PermanentFlags, imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft)
	}
	return data, err
}
func fixture(t *testing.T) (IMAPConfig, int) {
	return fixtureWithDrop(t, false)
}
func fixtureWithDrop(t *testing.T, dropReply bool) (IMAPConfig, int) {
	t.Helper()
	https := httptest.NewTLSServer(nil)
	cert := https.TLS.Certificates[0]
	leaf := https.Certificate()
	https.Close()
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := imapmemserver.New()
	user := imapmemserver.NewUser("test", "password")
	_ = user.Create("INBOX", nil)
	backend.AddUser(user)
	drop := &atomic.Bool{}
	drop.Store(dropReply)
	server := imapserver.New(&imapserver.Options{NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
		return fixtureSession{backend.NewSession(), conn, drop}, nil, nil
	}, Caps: imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}})
	go server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	t.Cleanup(func() { _ = server.Close() })
	return IMAPConfig{Host: "127.0.0.1", Username: "test", Password: "password", RootCAs: pool, AllowNetworks: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, listener.Addr().(*net.TCPAddr).Port
}
func TestIMAPTLSRequired(t *testing.T) {
	_, err := DialIMAP(context.Background(), IMAPConfig{Host: "mail.example.com", Port: 143})
	if err == nil {
		t.Fatal("accepted plaintext port")
	}
	if allowedIP(netip.MustParseAddr("169.254.169.254"), nil) {
		t.Fatal("metadata address permitted")
	}
}
func TestWrongCertificateRejected(t *testing.T) {
	cfg, port := fixture(t)
	cfg.RootCAs = nil
	_, err := dialIMAP(context.Background(), cfg, port)
	if err == nil {
		t.Fatal("accepted untrusted certificate")
	}
}
func TestPreservesDatesFlagsAndBytes(t *testing.T) {
	cfg, port := fixture(t)
	client, err := dialIMAP(context.Background(), cfg, port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	body := []byte("From: source@example.com\r\nSubject: preserved\r\n\r\nBody\r\n")
	date := time.Date(2024, 3, 2, 11, 22, 33, 0, time.UTC)
	msg := Message{Identity: MessageIdentity{Folder: "INBOX", UIDValidity: 1, UID: 1}, Body: body, Flags: []string{`\Seen`, `\Flagged`, `\Deleted`}, InternalDate: date}
	receipt, err := client.Append(context.Background(), msg, "npimport_01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Read(context.Background(), MessageIdentity{Folder: "INBOX", UIDValidity: receipt.UIDValidity, UID: receipt.UID})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, body) || !got.InternalDate.Equal(date) || len(got.Flags) < 3 {
		t.Fatalf("content changed: %+v", got)
	}
}
func TestDistinctIdenticalMessages(t *testing.T) {
	cfg, port := fixture(t)
	client, err := dialIMAP(context.Background(), cfg, port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	msg := Message{Identity: MessageIdentity{Folder: "INBOX"}, Body: []byte("Subject: duplicate\r\n\r\nsame\r\n"), InternalDate: time.Now().UTC()}
	for i := 0; i < 2; i++ {
		if _, err = client.Append(context.Background(), msg, "npimport_0123456789012345678901234567890"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	folders, err := client.Discover(context.Background())
	if err != nil || len(folders) != 1 || len(folders[0].Messages) != 2 {
		t.Fatalf("distinct messages collapsed: %+v %v", folders, err)
	}
}
func TestUIDValidityChange(t *testing.T) {
	cfg, port := fixture(t)
	client, err := dialIMAP(context.Background(), cfg, port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Read(context.Background(), MessageIdentity{Folder: "INBOX", UIDValidity: 999, UID: 1})
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("got %v", err)
	}
}
func TestAppendReplyLost(t *testing.T) {
	cfg, port := fixtureWithDrop(t, true)
	client, err := dialIMAP(context.Background(), cfg, port)
	if err != nil {
		t.Fatal(err)
	}
	token := ReceiptToken("import", "message")
	_, err = client.Append(context.Background(), Message{Identity: MessageIdentity{Folder: "INBOX"}, Body: []byte("Subject: persisted\r\n\r\nretained\r\n"), InternalDate: time.Now()}, token)
	client.Close()
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("lost acknowledgement: %v", err)
	}
	client, err = dialIMAP(context.Background(), cfg, port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	receipts, err := client.FindReceipt(context.Background(), "INBOX", token)
	if err != nil || len(receipts) != 1 {
		t.Fatalf("lost reply cannot be reconciled: %+v %v", receipts, err)
	}
}
