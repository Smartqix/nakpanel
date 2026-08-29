package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ManifestName is the first entry of every server backup archive so restore
// tooling can stream-preview the archive without extracting it.
const ManifestName = "manifest.json"

// UsersEntryName carries the managed system identities (numeric uid/gid and
// subordinate id ranges) that restore must recreate before extracting trees.
const UsersEntryName = "system/users.json"

// PostgresDumpName is the panel database dump entry.
const PostgresDumpName = "postgres/nakpanel.dump"

// MariaDBPrefix prefixes per-tenant-database dump entries.
const MariaDBPrefix = "mariadb/"

// TreePrefix prefixes verbatim filesystem trees; the remainder of the entry
// name is the absolute path without its leading slash.
const TreePrefix = "files/"

// Manifest describes an archive's contents and provenance.
type Manifest struct {
	FormatVersion    int       `json:"format_version"`
	CreatedAt        time.Time `json:"created_at"`
	Hostname         string    `json:"hostname"`
	PanelVersion     string    `json:"panel_version,omitempty"`
	GooseVersion     int64     `json:"goose_version,omitempty"`
	KeyFingerprint   string    `json:"key_fingerprint"`
	TenantDatabases  []string  `json:"tenant_databases,omitempty"`
	Trees            []string  `json:"trees,omitempty"`
	SystemdUnits     []string  `json:"systemd_units,omitempty"`
	IncludeMailData  bool      `json:"include_mail_data"`
	StalwartPausedMS int64     `json:"stalwart_paused_ms,omitempty"`
	Excluded         []string  `json:"excluded,omitempty"`
}

// SystemIdentity is the users.json payload.
type SystemIdentity struct {
	Users  []SystemUser  `json:"users"`
	Groups []SystemGroup `json:"groups"`
}

type SystemUser struct {
	Name       string   `json:"name"`
	UID        int      `json:"uid"`
	GID        int      `json:"gid"`
	Home       string   `json:"home"`
	Shell      string   `json:"shell"`
	Groups     []string `json:"groups,omitempty"`
	SubUIDBase int      `json:"subuid_base,omitempty"`
	SubUIDSize int      `json:"subuid_size,omitempty"`
	SubGIDBase int      `json:"subgid_base,omitempty"`
	SubGIDSize int      `json:"subgid_size,omitempty"`
}

type SystemGroup struct {
	Name string `json:"name"`
	GID  int    `json:"gid"`
}

// ArchiveWriter streams an encrypted, gzip-compressed tar archive.
type ArchiveWriter struct {
	tw      *tar.Writer
	gz      *gzip.Writer
	enc     *StreamWriter
	entries int
}

// NewArchiveWriter layers tar -> gzip -> encryption onto dst.
func NewArchiveWriter(dst io.Writer, key []byte) (*ArchiveWriter, error) {
	enc, err := NewStreamWriter(dst, key)
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(enc)
	return &ArchiveWriter{tw: tar.NewWriter(gz), gz: gz, enc: enc}, nil
}

// Entries returns the number of entries written so far.
func (w *ArchiveWriter) Entries() int { return w.entries }

// AddBytes writes an in-memory entry.
func (w *ArchiveWriter) AddBytes(name string, data []byte, mode int64) error {
	header := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}
	if err := w.tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := w.tw.Write(data); err != nil {
		return err
	}
	w.entries++
	return nil
}

// AddFileFrom streams a filesystem file into the archive under name.
func (w *ArchiveWriter) AddFileFrom(name, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	header := &tar.Header{
		Name:    name,
		Mode:    int64(info.Mode().Perm()),
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := w.tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := io.Copy(w.tw, file); err != nil {
		return err
	}
	w.entries++
	return nil
}

// AddTree walks root and stores every directory, regular file, and symlink
// under TreePrefix + the absolute path (without leading slash). Sockets,
// devices, and fifos are skipped. Missing roots are skipped silently so one
// inventory list serves installs with optional components.
func (w *ArchiveWriter) AddTree(root string) error {
	return w.AddTreeMapped(root, root, nil)
}

// AddTreeMapped walks root but stores entries as if the tree lived at asRoot
// (used to archive a paused-service copy under its original path). skip, when
// non-nil, prunes matching paths (and their subtrees for directories).
func (w *ArchiveWriter) AddTreeMapped(root, asRoot string, skip func(string) bool) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return w.addTreeEntry(root, asRoot, info)
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// A file vanishing mid-walk is routine on a live system.
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		mapped := asRoot + strings.TrimPrefix(path, root)
		if skip != nil && skip(mapped) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		return w.addTreeEntry(path, mapped, info)
	})
}

func (w *ArchiveWriter) addTreeEntry(path, asPath string, info fs.FileInfo) error {
	var linkTarget string
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		linkTarget = target
	} else if !info.Mode().IsRegular() && !info.IsDir() {
		return nil
	}
	header, err := tar.FileInfoHeader(info, linkTarget)
	if err != nil {
		return err
	}
	header.Name = TreePrefix + strings.TrimPrefix(asPath, "/")
	if info.IsDir() {
		header.Name += "/"
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		header.Uid = int(stat.Uid)
		header.Gid = int(stat.Gid)
	}
	header.Uname = ""
	header.Gname = ""
	if err := w.tw.WriteHeader(header); err != nil {
		return err
	}
	if info.Mode().IsRegular() && info.Size() > 0 {
		file, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("file vanished during archive: %s", path)
			}
			return err
		}
		defer file.Close()
		if _, err := io.CopyN(w.tw, file, header.Size); err != nil {
			return fmt.Errorf("archive %s: %w", path, err)
		}
	}
	w.entries++
	return nil
}

// Close flushes tar, gzip, and the encryption stream, in that order.
func (w *ArchiveWriter) Close() error {
	if err := w.tw.Close(); err != nil {
		return err
	}
	if err := w.gz.Close(); err != nil {
		return err
	}
	return w.enc.Close()
}

// ArchiveReader decrypts and decompresses an archive for sequential reading.
type ArchiveReader struct {
	tr *tar.Reader
	gz *gzip.Reader
}

func NewArchiveReader(src io.Reader, key []byte) (*ArchiveReader, error) {
	dec, err := NewStreamReader(src, key)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(dec)
	if err != nil {
		if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrTruncated) {
			return nil, err
		}
		return nil, fmt.Errorf("backup: archive is not gzip: %w", err)
	}
	return &ArchiveReader{tr: tar.NewReader(gz), gz: gz}, nil
}

func (r *ArchiveReader) Next() (*tar.Header, error) { return r.tr.Next() }

func (r *ArchiveReader) Read(p []byte) (int, error) { return r.tr.Read(p) }

// Finish MUST be called after the tar stream reaches io.EOF. archive/tar stops
// at its two zero blocks and reads no further, and io.ReadFull nils out an
// error whenever it still got a full block — so a corrupt or truncated
// encryption stream surfaces to the tar reader as a clean EOF. Draining the
// decompressor here forces the remaining AEAD chunks, the gzip CRC/ISIZE
// trailer, and the stream's final-chunk and trailing-byte checks to run, and
// reports their verdict. Without it, a tail-corrupted archive verifies and
// restores as if it were intact.
func (r *ArchiveReader) Finish() error {
	if _, err := io.Copy(io.Discard, r.gz); err != nil {
		return fmt.Errorf("archive did not terminate cleanly: %w", err)
	}
	return nil
}

// ReadManifest reads and decodes the archive's leading manifest entry.
func ReadManifest(src io.Reader, key []byte) (Manifest, error) {
	var manifest Manifest
	reader, err := NewArchiveReader(src, key)
	if err != nil {
		return manifest, err
	}
	header, err := reader.Next()
	if err != nil {
		return manifest, err
	}
	if header.Name != ManifestName {
		return manifest, fmt.Errorf("backup: first archive entry is %q, want %q", header.Name, ManifestName)
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, fmt.Errorf("backup: manifest: %w", err)
	}
	if manifest.FormatVersion != 1 {
		return manifest, fmt.Errorf("backup: unsupported archive format version %d", manifest.FormatVersion)
	}
	return manifest, nil
}
