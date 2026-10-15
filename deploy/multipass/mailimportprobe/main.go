package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	transport "github.com/nakroteck/nakpanel/internal/mailimport"
)

type credential struct{ Host, Username, Password string }
type snapshot struct {
	Messages int            `json:"messages"`
	Counts   map[string]int `json:"counts"`
}

func body() []byte {
	return []byte("From: migration@example.test\r\nTo: fixture@example.test\r\nSubject: Native mail import fixture\r\nMessage-ID: <same-id@fixture.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n--fixture\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPreserve every distinct copy.\r\n--fixture\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=fixture.bin\r\n\r\nAAECAwQFBgcICQ==\r\n--fixture--\r\n")
}
func key(folder string, msg transport.Message) string {
	flags := []string{}
	for _, flag := range msg.Flags {
		if !strings.HasPrefix(strings.ToLower(flag), "npimport_") {
			flags = append(flags, strings.ToLower(flag))
		}
	}
	sort.Strings(flags)
	return folder + "|" + transport.ContentHash(msg.Body) + "|" + strconv.FormatInt(msg.InternalDate.Unix(), 10) + "|" + strings.Join(flags, ",")
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: mailimportprobe snapshot|seed|tar|tar-snapshot"))
	}
	if os.Args[1] == "tar" || os.Args[1] == "tar-snapshot" {
		files := []struct {
			name, folder string
			flags        []string
		}{{"cur/1704164645.1:2,S", "INBOX", []string{`\Seen`}}, {"new/1704164645.2", "INBOX", nil}, {".Projects.Work/cur/1704164645.3:2,FT", "Projects/Work", []string{`\Flagged`, `\Deleted`}}}
		if os.Args[1] == "tar-snapshot" {
			s := snapshot{Counts: map[string]int{}}
			for _, file := range files {
				s.Messages++
				s.Counts[key(file.folder, transport.Message{Body: body(), Flags: file.flags, InternalDate: time.Unix(1704164645, 0)})]++
			}
			if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
				fail(err)
			}
			return
		}
		writer := tar.NewWriter(os.Stdout)
		for _, file := range files {
			data := body()
			if err := writer.WriteHeader(&tar.Header{Name: file.name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(data)), ModTime: time.Unix(1704164645, 0)}); err != nil {
				fail(err)
			}
			if _, err := writer.Write(data); err != nil {
				fail(err)
			}
		}
		if err := writer.Close(); err != nil {
			fail(err)
		}
		return
	}
	file := os.Getenv("NAKPANEL_MAIL_VERIFY_CREDENTIAL_FILE")
	info, err := os.Stat(file)
	if err != nil {
		fail(fmt.Errorf("credential file unavailable"))
	}
	if info.Mode().Perm()&0077 != 0 {
		fail(fmt.Errorf("credential file must be private"))
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		fail(err)
	}
	var creds credential
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&creds); err != nil {
		fail(fmt.Errorf("invalid credential file"))
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := transport.DialIMAP(ctx, transport.IMAPConfig{Host: creds.Host, Username: creds.Username, Password: creds.Password})
	creds.Password = ""
	if err != nil {
		fail(err)
	}
	defer client.Close()
	if os.Args[1] == "seed" {
		count := 2
		if len(os.Args) > 2 {
			count, err = strconv.Atoi(os.Args[2])
			if err != nil || count < 1 || count > 1000 {
				fail(fmt.Errorf("seed count must be 1-1000"))
			}
		}
		folder := "Native fixture"
		if err = client.EnsureFolder(ctx, folder); err != nil {
			fail(err)
		}
		for i := 0; i < count; i++ {
			_, err = client.Append(ctx, transport.Message{Identity: transport.MessageIdentity{Folder: folder}, Body: body(), Flags: []string{`\Seen`, `\Flagged`}, InternalDate: time.Unix(1704164645, 0)}, transport.ReceiptToken(time.Now().String(), strconv.Itoa(i)))
			if err != nil {
				fail(err)
			}
		}
	} else if os.Args[1] != "snapshot" {
		fail(fmt.Errorf("unknown mode"))
	}
	folders, err := client.Discover(ctx)
	if err != nil {
		fail(err)
	}
	s := snapshot{Counts: map[string]int{}}
	for _, folder := range folders {
		for _, entry := range folder.Messages {
			msg, err := client.Read(ctx, entry.Identity)
			if err != nil {
				fail(err)
			}
			s.Messages++
			s.Counts[key(folder.Name, msg)]++
		}
	}
	if err = json.NewEncoder(os.Stdout).Encode(s); err != nil {
		fail(err)
	}
}
