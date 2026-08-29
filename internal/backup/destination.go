package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// ObjectInfo describes one stored archive at a destination.
type ObjectInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// Destination is a storage backend for server backup archives. Names are
// bare file names (no separators); implementations scope them under their
// configured directory/prefix.
type Destination interface {
	// Put stores the stream atomically: a partially written object must never
	// be visible under its final name.
	Put(ctx context.Context, name string, r io.Reader, size int64) error
	Open(ctx context.Context, name string) (io.ReadCloser, int64, error)
	List(ctx context.Context) ([]ObjectInfo, error)
	Delete(ctx context.Context, name string) error
	// Probe verifies connectivity and permissions by writing, reading back,
	// and deleting a small canary object.
	Probe(ctx context.Context) error
}

// DestinationKinds enumerates the supported destination kinds.
var DestinationKinds = []string{"local", "sftp", "s3"}

// NewDestination constructs a destination from its kind, its non-secret
// settings JSON, and its decrypted credential bytes (layout depends on kind;
// empty for local).
func NewDestination(kind string, settings json.RawMessage, credential []byte) (Destination, error) {
	switch kind {
	case "local":
		return newLocalDestination(settings)
	case "sftp":
		return newSFTPDestination(settings, credential)
	case "s3":
		return newS3Destination(settings, credential)
	default:
		return nil, fmt.Errorf("backup: unknown destination kind %q", kind)
	}
}

func probeDestination(ctx context.Context, d Destination) error {
	name := fmt.Sprintf(".nakpanel-probe-%d", time.Now().UnixNano())
	payload := []byte("nakpanel destination probe")
	if err := d.Put(ctx, name, newByteReader(payload), int64(len(payload))); err != nil {
		return fmt.Errorf("probe write: %w", err)
	}
	rc, _, err := d.Open(ctx, name)
	if err != nil {
		_ = d.Delete(ctx, name)
		return fmt.Errorf("probe read: %w", err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		_ = d.Delete(ctx, name)
		return fmt.Errorf("probe read: %w", err)
	}
	if string(data) != string(payload) {
		_ = d.Delete(ctx, name)
		return fmt.Errorf("probe read back mismatched content")
	}
	if err := d.Delete(ctx, name); err != nil {
		return fmt.Errorf("probe delete: %w", err)
	}
	return nil
}

func newByteReader(b []byte) io.Reader {
	return &byteReader{data: b}
}

type byteReader struct {
	data []byte
	off  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func validateObjectName(name string) error {
	if name == "" || len(name) > 255 {
		return fmt.Errorf("backup: invalid object name %q", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return fmt.Errorf("backup: invalid object name %q", name)
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("backup: invalid object name %q", name)
	}
	return nil
}
