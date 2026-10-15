package mailimport

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestStalwartCompatibility(t *testing.T) {
	host := os.Getenv("NAKPANEL_TEST_IMAP_HOST")
	if host == "" {
		t.Skip("requires isolated Stalwart fixture")
	}
	password, err := os.ReadFile(os.Getenv("NAKPANEL_TEST_IMAP_PASSWORD_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := DialIMAP(ctx, IMAPConfig{Host: host, Username: os.Getenv("NAKPANEL_TEST_IMAP_USER"), Password: string(password)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	folder := "Import QA/" + time.Now().UTC().Format("20060102T150405.000000000")
	if err = c.EnsureFolder(ctx, folder); err != nil {
		t.Fatal(err)
	}
	body := []byte("From: fixture@example.com\r\nSubject: Stalwart import preservation\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=qa\r\n\r\n--qa\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMail import fixture\r\n--qa\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=test.bin\r\n\r\nAAECAwQFBgc=\r\n--qa--\r\n")
	date := time.Date(2020, 2, 3, 4, 5, 6, 0, time.UTC)
	for i, key := range []string{"first", "second"} {
		token := ReceiptToken(folder, key)
		msg := Message{Identity: MessageIdentity{Folder: folder}, Body: body, Flags: []string{`\Seen`, `\Flagged`, `\Answered`, `\Deleted`}, InternalDate: date}
		r, err := c.Append(ctx, msg, token)
		if err != nil {
			t.Fatal(err)
		}
		found, err := c.FindReceipt(ctx, folder, token)
		if err != nil || len(found) != 1 || found[0] != r {
			t.Fatalf("receipt mismatch %+v %v", found, err)
		}
		got, err := c.Read(ctx, MessageIdentity{Folder: folder, UID: r.UID, UIDValidity: r.UIDValidity})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Body, body) || !got.InternalDate.Equal(date) {
			t.Fatal("Stalwart changed message bytes/date")
		}
		for _, flag := range msg.Flags {
			seen := false
			for _, actual := range got.Flags {
				seen = seen || actual == flag
			}
			if !seen {
				t.Fatalf("missing preserved flag %s", flag)
			}
		}
		t.Logf("message %d: content, attachment, date, flags and persistent receipt verified", i+1)
	}
}
