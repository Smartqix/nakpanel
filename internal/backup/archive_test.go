package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestArchiveRoundTrip(t *testing.T) {
	key := testKey(t)
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "sub", "file.txt"), []byte("tree-content"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file.txt", filepath.Join(tree, "sub", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, "skipme", ".local", "share", "containers"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "skipme", ".local", "share", "containers", "big.img"), []byte("image"), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := Manifest{FormatVersion: 1, CreatedAt: time.Now().UTC(), KeyFingerprint: Fingerprint(key)}
	manifestJSON, _ := json.Marshal(manifest)

	var buf bytes.Buffer
	writer, err := NewArchiveWriter(&buf, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.AddBytes(ManifestName, manifestJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writer.AddBytes(UsersEntryName, []byte(`{"users":[],"groups":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writer.AddTreeMapped(tree, "/etc/fake", serverStyleSkip); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	// Manifest preview must work on a fresh reader.
	parsed, err := ReadManifest(bytes.NewReader(buf.Bytes()), key)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if parsed.KeyFingerprint != Fingerprint(key) {
		t.Fatal("manifest fingerprint mismatch")
	}

	reader, err := NewArchiveReader(bytes.NewReader(buf.Bytes()), key)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	var sawSymlink bool
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(reader)
		names[header.Name] = string(content)
		if header.Name == TreePrefix+"etc/fake/sub/link" {
			sawSymlink = true
			if header.Linkname != "file.txt" {
				t.Fatalf("symlink target %q", header.Linkname)
			}
		}
	}
	if got := names[TreePrefix+"etc/fake/sub/file.txt"]; got != "tree-content" {
		t.Fatalf("tree file content %q", got)
	}
	if !sawSymlink {
		t.Fatal("symlink entry missing")
	}
	for name := range names {
		if filepath.Base(name) == "big.img" {
			t.Fatal("skip predicate did not prune container storage")
		}
	}
	if _, ok := names[ManifestName]; !ok {
		t.Fatal("manifest entry missing")
	}
}

func serverStyleSkip(path string) bool {
	return filepath.Base(filepath.Dir(filepath.Dir(path))) == ".local" ||
		containsSegment(path, "/.local/share/containers")
}

func containsSegment(path, segment string) bool {
	return bytes.Contains([]byte(path), []byte(segment))
}

// TestArchiveFinishDetectsTailCorruption pins the defect that archive/tar's
// zero-block termination plus io.ReadFull's error-nilling hid: a truncated or
// tampered encryption stream reached the caller as a clean io.EOF, so a
// damaged archive verified and restored as if it were intact. Finish() must
// surface the verdict.
func TestArchiveFinishDetectsTailCorruption(t *testing.T) {
	key := testKey(t)
	build := func() []byte {
		var buf bytes.Buffer
		writer, err := NewArchiveWriter(&buf, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.AddBytes(ManifestName, []byte(`{"format_version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		// Enough payload to span multiple AEAD chunks.
		if err := writer.AddBytes("payload.bin", bytes.Repeat([]byte("z"), 3*ChunkSize+11), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	drain := func(data []byte) error {
		reader, err := NewArchiveReader(bytes.NewReader(data), key)
		if err != nil {
			return err
		}
		for {
			_, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, reader); err != nil {
				return err
			}
		}
		return reader.Finish()
	}

	intact := build()
	if err := drain(intact); err != nil {
		t.Fatalf("intact archive rejected: %v", err)
	}

	truncated := intact[:len(intact)-30]
	if err := drain(truncated); err == nil {
		t.Fatal("truncated archive was accepted: Finish() did not surface the integrity failure")
	}

	tampered := append([]byte(nil), intact...)
	tampered[len(tampered)-5] ^= 0xff
	if err := drain(tampered); err == nil {
		t.Fatal("tail-tampered archive was accepted: Finish() did not surface the integrity failure")
	}
}
