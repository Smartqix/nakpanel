package mailimport

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func tarFixture(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, body := range entries {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestMaildirHierarchy(t *testing.T) {
	root := t.TempDir()
	manifest, err := ExtractMaildir(bytes.NewReader(tarFixture(t, map[string]string{"cur/1:2,S": "a", ".Projects.Work/new/2": "b"})), root, ArchiveLimits{Bytes: 1024, Entries: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Messages) != 2 {
		t.Fatal(manifest)
	}
	found := false
	for _, m := range manifest.Messages {
		found = found || m.Folder == "Projects/Work"
	}
	if !found {
		t.Fatal("lost folder hierarchy")
	}
}
func TestMaildirFlags(t *testing.T) {
	flags, err := maildirFlags("123:2,DFRST")
	if err != nil || len(flags) != 5 {
		t.Fatalf("%v %v", flags, err)
	}
	if _, err = maildirFlags("123:2,z"); err == nil {
		t.Fatal("unknown flag silently lost")
	}
}
func TestMaildirIgnoresTmp(t *testing.T) {
	m, err := ExtractMaildir(bytes.NewReader(tarFixture(t, map[string]string{"tmp/not-finished": "partial", "new/1": "complete"})), t.TempDir(), ArchiveLimits{Bytes: 1024, Entries: 10})
	if err != nil || len(m.Messages) != 1 {
		t.Fatalf("%+v %v", m, err)
	}
}
func TestMaildirUnsupportedLayout(t *testing.T) {
	_, err := ExtractMaildir(bytes.NewReader(tarFixture(t, map[string]string{"Mail/inbox/message": "a"})), t.TempDir(), ArchiveLimits{Bytes: 1024, Entries: 10})
	if err == nil {
		t.Fatal("accepted unsupported layout")
	}
}
func TestMaildirArchiveTraversalAndLinks(t *testing.T) {
	for _, name := range []string{"../escaped", "/absolute", "cur/../../escaped", "cur\\escaped"} {
		t.Run(name, func(t *testing.T) {
			_, err := ExtractMaildir(bytes.NewReader(tarFixture(t, map[string]string{name: "a"})), t.TempDir(), ArchiveLimits{Bytes: 1024, Entries: 10})
			if err == nil {
				t.Fatal("accepted unsafe path")
			}
		})
	}
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeFifo} {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		_ = w.WriteHeader(&tar.Header{Name: "cur/link", Linkname: "/etc/passwd", Typeflag: kind})
		_ = w.Close()
		if _, err := ExtractMaildir(bytes.NewReader(b.Bytes()), t.TempDir(), ArchiveLimits{Bytes: 1024, Entries: 10}); err == nil {
			t.Fatalf("accepted link/device %c", kind)
		}
	}
}
func TestMaildirExpansionLimit(t *testing.T) {
	_, err := ExtractMaildir(bytes.NewReader(tarFixture(t, map[string]string{"new/1": "too long"})), t.TempDir(), ArchiveLimits{Bytes: 3, Entries: 10})
	if err == nil {
		t.Fatal("ignored byte limit")
	}
}
func TestMaildirChangedSourceManifest(t *testing.T) {
	root := t.TempDir()
	m, err := ExtractMaildir(bytes.NewReader(tarFixture(t, map[string]string{"new/1": "original"})), root, ArchiveLimits{Bytes: 1024, Entries: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "new/1"), []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadMaildirMessage(root, m, m.Messages[0].Key); err == nil {
		t.Fatal("changed content accepted")
	}
}
func FuzzMaildirPath(f *testing.F) {
	for _, s := range []string{"cur/1", "../x", ".Sent/new/2", "a\\b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if validArchivePath(s) && (!filepath.IsLocal(s) || bytes.ContainsAny([]byte(s), "\\\x00")) {
			t.Fatalf("unsafe accepted %q", s)
		}
	})
}
