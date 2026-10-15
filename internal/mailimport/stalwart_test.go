package mailimport

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
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
	if remaining, err := c.AvailableBytes(ctx); err != nil || remaining <= 0 {
		t.Fatalf("destination quota preflight failed: %d %v", remaining, err)
	}
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
	c.Close()
	reopened, err := DialIMAP(ctx, IMAPConfig{Host: host, Username: os.Getenv("NAKPANEL_TEST_IMAP_USER"), Password: string(password)})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	subscribed, err := reopened.client.List("", folder, &imap.ListOptions{SelectSubscribed: true}).Collect()
	if err != nil || len(subscribed) != 1 {
		t.Fatalf("imported folder is absent from subscribed webmail folders: %d %v", len(subscribed), err)
	}
	if receipts, err := reopened.FindReceipt(ctx, folder, ReceiptToken(folder, "first")); err != nil || len(receipts) != 1 {
		t.Fatalf("receipt did not survive a fresh connection: %d %v", len(receipts), err)
	}
	folders, err := reopened.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundSent := false
	for _, entry := range folders {
		foundSent = foundSent || entry.SpecialUse == `\Sent`
	}
	if !foundSent {
		t.Fatal("source discovery lost the Sent folder role")
	}
	for _, entry := range folders {
		if entry.SpecialUse == `\Sent` {
			if err := reopened.EnsureFolderWithRole(ctx, entry.Name, entry.SpecialUse); err != nil {
				t.Fatal(err)
			}
		}
	}
}
