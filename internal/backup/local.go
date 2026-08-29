package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultLocalDir is where local-destination archives are spooled.
const DefaultLocalDir = "/var/lib/nakpanel/server-backups"

type localSettings struct {
	Dir string `json:"dir"`
}

type localDestination struct {
	dir string
}

func newLocalDestination(settings json.RawMessage) (Destination, error) {
	var cfg localSettings
	if len(settings) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(settings)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("backup: local settings: %w", err)
		}
	}
	dir := strings.TrimSpace(cfg.Dir)
	if dir == "" {
		dir = DefaultLocalDir
	}
	if !filepath.IsAbs(dir) {
		return nil, errors.New("backup: local destination dir must be absolute")
	}
	return &localDestination{dir: filepath.Clean(dir)}, nil
}

func (d *localDestination) ensureDir() error {
	return os.MkdirAll(d.dir, 0o700)
}

func (d *localDestination) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if err := validateObjectName(name); err != nil {
		return err
	}
	if err := d.ensureDir(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d.dir, ".part-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(d.dir, name)); err != nil {
		return err
	}
	return syncLocalDir(d.dir)
}

func (d *localDestination) Open(ctx context.Context, name string) (io.ReadCloser, int64, error) {
	if err := validateObjectName(name); err != nil {
		return nil, 0, err
	}
	file, err := os.Open(filepath.Join(d.dir, name))
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, err
	}
	return file, info.Size(), nil
}

func (d *localDestination) List(ctx context.Context) ([]ObjectInfo, error) {
	entries, err := os.ReadDir(d.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []ObjectInfo
	for _, entry := range entries {
		if !entry.Type().IsRegular() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result = append(result, ObjectInfo{Name: entry.Name(), Size: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (d *localDestination) Delete(ctx context.Context, name string) error {
	if err := validateObjectName(name); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(d.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (d *localDestination) Probe(ctx context.Context) error {
	return probeDestination(ctx, d)
}

func syncLocalDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
