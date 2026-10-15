package mailimport

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ArchiveLimits struct {
	Bytes   int64
	Entries int
}
type MaildirEntry struct {
	Key, Path, Folder, SHA256 string
	Size                      int64
	InternalDate              time.Time
	Flags                     []string
}
type MaildirManifest struct {
	SHA256        string
	Messages      []MaildirEntry
	MetadataFiles int
}

func validArchivePath(name string) bool {
	if name == "" || len(name) > 2048 || strings.ContainsAny(name, "\\\x00\r\n") {
		return false
	}
	return path.Clean(name) == name && filepath.IsLocal(name) && !strings.HasPrefix(name, "/")
}
func maildirLocation(name string) (folder string, message bool, err error) {
	parts := strings.Split(name, "/")
	pos := 0
	folder = "INBOX"
	if strings.HasPrefix(parts[0], ".") {
		if len(parts[0]) < 2 || strings.Contains(parts[0], "..") {
			return "", false, errors.New("invalid Maildir++ folder")
		}
		folder = strings.ReplaceAll(parts[0][1:], ".", "/")
		pos = 1
	}
	if len(parts) <= pos {
		return folder, false, nil
	}
	switch parts[pos] {
	case "cur", "new", "tmp":
		if len(parts) == pos+1 {
			return folder, false, nil
		}
		if len(parts) != pos+2 {
			return "", false, errors.New("nested paths inside Maildir message directories are unsupported")
		}
		return folder, parts[pos] != "tmp", nil
	}
	if len(parts) == pos+1 {
		switch parts[pos] {
		case "maildirfolder", "courierimapuiddb", "courierimapsubscribed", "dovecot-uidlist", "dovecot-keywords", "dovecot.index", "dovecot.index.cache", "dovecot.index.log", "subscriptions":
			return folder, false, nil
		}
	}
	return "", false, errors.New("unsupported Maildir layout; upload Maildir++ cur/new folders or use IMAP")
}
func maildirFlags(name string) ([]string, error) {
	_, raw, ok := strings.Cut(name, ":2,")
	if !ok {
		return nil, nil
	}
	flags := []string{}
	seen := map[rune]bool{}
	for _, flag := range raw {
		if seen[flag] {
			continue
		}
		seen[flag] = true
		v, ok := map[rune]string{'D': `\Draft`, 'F': `\Flagged`, 'R': `\Answered`, 'S': `\Seen`, 'T': `\Deleted`}[flag]
		if !ok {
			return nil, errors.New("unsupported Maildir flag; use IMAP to preserve custom keywords")
		}
		flags = append(flags, v)
	}
	sort.Strings(flags)
	return flags, nil
}
func ExtractMaildir(input io.Reader, root string, limits ArchiveLimits) (MaildirManifest, error) {
	if limits.Bytes <= 0 || limits.Bytes > 1<<30 || limits.Entries <= 0 || limits.Entries > 100000 {
		return MaildirManifest{}, errors.New("invalid Maildir extraction limits")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return MaildirManifest{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		return MaildirManifest{}, errors.New("Maildir staging must be empty")
	}
	buffer := bufio.NewReader(input)
	reader := io.Reader(buffer)
	if magic, _ := buffer.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffer)
		if err != nil {
			return MaildirManifest{}, errors.New("invalid compressed Maildir archive")
		}
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	manifest := MaildirManifest{}
	seen := map[string]bool{}
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return MaildirManifest{}, errors.New("invalid Maildir tar archive")
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !validArchivePath(name) || seen[name] {
			return MaildirManifest{}, errors.New("unsafe or duplicate Maildir archive path")
		}
		seen[name] = true
		count++
		total += h.Size
		if count > limits.Entries || h.Size < 0 || total > limits.Bytes {
			return MaildirManifest{}, errors.New("Maildir archive exceeds extraction limits")
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir {
			return MaildirManifest{}, errors.New("Maildir archive links and special files are forbidden")
		}
		folder, message, err := maildirLocation(name)
		if err != nil {
			return MaildirManifest{}, err
		}
		dest := filepath.Join(root, filepath.FromSlash(name))
		if h.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(dest, 0700); err != nil {
				return manifest, err
			}
			continue
		}
		if !message {
			if base := path.Base(name); base == "cur" || base == "new" || base == "tmp" || strings.HasPrefix(base, ".") {
				return manifest, errors.New("Maildir folders must be directories")
			}
			manifest.MetadataFiles++
			continue
		}
		if h.Size > MaxMessageBytes {
			return manifest, errors.New("Maildir message exceeds 64 MiB")
		}
		flags, err := maildirFlags(path.Base(name))
		if err != nil {
			return manifest, err
		}
		if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return manifest, err
		}
		file, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return manifest, err
		}
		hash := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(tr, h.Size+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || n != h.Size {
			return manifest, errors.New("incomplete Maildir message")
		}
		date := h.ModTime.UTC()
		stamp := strings.SplitN(path.Base(name), ".", 2)[0]
		if seconds, err := strconv.ParseInt(stamp, 10, 64); err == nil && seconds > 0 {
			date = time.Unix(seconds, 0).UTC()
		}
		if date.IsZero() {
			date = time.Unix(0, 0).UTC()
		}
		manifest.Messages = append(manifest.Messages, MaildirEntry{Key: name, Path: name, Folder: folder, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: n, InternalDate: date, Flags: flags})
	}
	if len(manifest.Messages) == 0 && !seen["cur"] && !seen["new"] {
		return manifest, errors.New("archive does not contain a Maildir++ mailbox")
	}
	sort.Slice(manifest.Messages, func(i, j int) bool { return manifest.Messages[i].Key < manifest.Messages[j].Key })
	data, _ := json.Marshal(manifest)
	manifest.SHA256 = ContentHash(data)
	data, err = json.Marshal(manifest)
	if err != nil {
		return manifest, err
	}
	if err = os.WriteFile(filepath.Join(root, ".nakpanel-maildir.json"), data, 0600); err != nil {
		return manifest, err
	}
	return manifest, nil
}
func LoadMaildirManifest(root, expected string) (MaildirManifest, error) {
	var manifest MaildirManifest
	f, err := os.Open(filepath.Join(root, ".nakpanel-maildir.json"))
	if err != nil {
		return manifest, errors.New("Maildir staging manifest is unavailable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 32<<20))
	if err != nil || json.Unmarshal(data, &manifest) != nil {
		return manifest, errors.New("invalid Maildir manifest")
	}
	saved := manifest.SHA256
	manifest.SHA256 = ""
	canonical, _ := json.Marshal(manifest)
	manifest.SHA256 = saved
	if saved != ContentHash(canonical) || expected != "" && saved != expected {
		return manifest, ErrSourceChanged
	}
	return manifest, nil
}
func ReadMaildirMessage(root string, manifest MaildirManifest, key string) (Message, error) {
	for _, entry := range manifest.Messages {
		if entry.Key != key {
			continue
		}
		if !validArchivePath(entry.Path) {
			return Message{}, ErrSourceChanged
		}
		f, err := OpenStagedFile(root, entry.Path)
		if err != nil {
			return Message{}, err
		}
		defer f.Close()
		body, err := io.ReadAll(io.LimitReader(f, MaxMessageBytes+1))
		if err != nil || int64(len(body)) != entry.Size || ContentHash(body) != entry.SHA256 {
			return Message{}, ErrSourceChanged
		}
		return Message{Identity: MessageIdentity{Folder: entry.Folder, Key: entry.Key}, Body: body, Flags: entry.Flags, InternalDate: entry.InternalDate, Size: entry.Size}, nil
	}
	return Message{}, errors.New("Maildir message is not in the approved manifest")
}

// Staging is root-owned. Reject links in every component before opening a file.
func OpenStagedFile(root, relative string) (*os.File, error) {
	if !validArchivePath(relative) {
		return nil, ErrSourceChanged
	}
	current := root
	for _, part := range strings.Split(relative, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrSourceChanged
		}
	}
	f, err := os.Open(current)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("invalid staged message")
	}
	return f, nil
}
