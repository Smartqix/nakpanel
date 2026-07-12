package ops

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/nakroteck/nakpanel/internal/types"
)

const (
	defaultFilePageSize = 100
	maxFilePageSize     = 200
	maxDirectoryEntries = 10000
	maxSearchEntries    = 10000
	maxSearchResults    = 200
	maxEditableBytes    = 512 << 10
	maxArchiveEntries   = 10000
	maxExpandedBytes    = int64(2 << 30)
)

var (
	fileManagerUsernameRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	transferTokenRE       = regexp.MustCompile(`^(upload|download)-[a-f0-9]{32}$`)
	errFileConflict       = errors.New("file conflict")
	errFileForbidden      = errors.New("file permission denied")
)

type FileManagerOptions struct {
	HomeRoot    string
	TransferDir string
	PanelUser   string
}

type FileManager struct {
	homeRoot    string
	transferDir string
	panelUser   string
}

type siteIdentity struct {
	username string
	uid      int
	gid      int
	groups   map[uint32]bool
	root     string
}

func NewFileManager(opts FileManagerOptions) *FileManager {
	homeRoot := strings.TrimSpace(opts.HomeRoot)
	if homeRoot == "" {
		homeRoot = "/home"
	}
	transferDir := strings.TrimSpace(opts.TransferDir)
	if transferDir == "" {
		transferDir = "/var/lib/nakpanel/transfers"
	}
	panelUser := strings.TrimSpace(opts.PanelUser)
	if panelUser == "" {
		panelUser = "nakpanel"
	}
	return &FileManager{homeRoot: homeRoot, transferDir: transferDir, panelUser: panelUser}
}

func (m *FileManager) ListFiles(ctx context.Context, req types.FileListReq) (types.FileListResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileListResult{}, err
	}
	rel, err := cleanManagedPath(req.Path, true)
	if err != nil {
		return types.FileListResult{}, err
	}
	dir, err := m.resolve(id, rel, true, true)
	if err != nil {
		return types.FileListResult{}, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return types.FileListResult{}, err
	}
	if !info.IsDir() {
		return types.FileListResult{}, errors.New("path is not a directory")
	}
	if !canAccess(info, id, 0o5) {
		return types.FileListResult{}, errFileForbidden
	}
	items, err := os.ReadDir(dir)
	if err != nil {
		return types.FileListResult{}, err
	}
	if len(items) > maxDirectoryEntries {
		return types.FileListResult{}, fmt.Errorf("directory contains more than %d entries", maxDirectoryEntries)
	}
	entries := make([]types.FileEntry, 0, len(items))
	directories := make([]types.FileEntry, 0)
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return types.FileListResult{}, err
		}
		if !utf8.ValidString(item.Name()) {
			entries = append(entries, types.FileEntry{Name: "Unsupported filename", Kind: types.FileKindFile})
			continue
		}
		itemInfo, err := os.Lstat(filepath.Join(dir, item.Name()))
		if err != nil {
			continue
		}
		itemRel := path.Join(rel, item.Name())
		entry := fileEntry(itemRel, itemInfo, id)
		entry.Renamable = entry.Kind != types.FileKindSymlink && ownedBy(itemInfo, id.uid) && canAccess(info, id, 0o3)
		entry.Deletable = ownedBy(itemInfo, id.uid) && canAccess(info, id, 0o3)
		entries = append(entries, entry)
		if entry.Kind == types.FileKindDirectory && len(directories) < maxFilePageSize {
			directories = append(directories, entry)
		}
	}
	sortFileEntries(entries, req.Sort, req.Order)
	pageNumber := req.Page
	if pageNumber < 1 {
		pageNumber = 1
	}
	perPage := req.PerPage
	if perPage < 1 {
		perPage = defaultFilePageSize
	}
	if perPage > maxFilePageSize {
		perPage = maxFilePageSize
	}
	start := (pageNumber - 1) * perPage
	if start > len(entries) {
		start = len(entries)
	}
	end := start + perPage
	if end > len(entries) {
		end = len(entries)
	}
	return types.FileListResult{Path: rel, Entries: entries[start:end], Directories: directories, Total: len(entries), Page: pageNumber, PerPage: perPage}, nil
}

func (m *FileManager) SearchFiles(ctx context.Context, req types.FileSearchReq) (types.FileSearchResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileSearchResult{}, err
	}
	rel, err := cleanManagedPath(req.Path, true)
	if err != nil {
		return types.FileSearchResult{}, err
	}
	root, err := m.resolve(id, rel, true, true)
	if err != nil {
		return types.FileSearchResult{}, err
	}
	query := strings.ToLower(strings.TrimSpace(req.Query))
	if query == "" || len(query) > 255 {
		return types.FileSearchResult{}, errors.New("search query is required and must not exceed 255 bytes")
	}
	limit := req.Limit
	if limit < 1 || limit > maxSearchResults {
		limit = maxSearchResults
	}
	result := types.FileSearchResult{Entries: make([]types.FileEntry, 0)}
	scanned := 0
	err = filepath.WalkDir(root, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if full == root {
			return nil
		}
		scanned++
		if scanned > maxSearchEntries {
			result.Truncated = true
			return fs.SkipAll
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.Contains(strings.ToLower(entry.Name()), query) {
			return nil
		}
		if len(result.Entries) >= limit {
			result.Truncated = true
			return fs.SkipAll
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		itemRel, err := filepath.Rel(id.root, full)
		if err != nil {
			return nil
		}
		item := fileEntry(filepath.ToSlash(itemRel), info, id)
		if parentInfo, statErr := os.Stat(filepath.Dir(full)); statErr == nil {
			item.Renamable = item.Kind != types.FileKindSymlink && ownedBy(info, id.uid) && canAccess(parentInfo, id, 0o3)
			item.Deletable = ownedBy(info, id.uid) && canAccess(parentInfo, id, 0o3)
		}
		result.Entries = append(result.Entries, item)
		return nil
	})
	if err != nil {
		return types.FileSearchResult{}, err
	}
	sortFileEntries(result.Entries, req.Sort, req.Order)
	return result, nil
}

func (m *FileManager) ReadFile(ctx context.Context, req types.FileReadReq) (types.FileReadResult, error) {
	id, rel, full, info, err := m.regularFile(req.Username, req.Path)
	if err != nil {
		return types.FileReadResult{}, err
	}
	if info.Size() > maxEditableBytes {
		return types.FileReadResult{}, fmt.Errorf("file exceeds the %d byte editor limit", maxEditableBytes)
	}
	if !canAccess(info, id, 0o4) {
		return types.FileReadResult{}, errFileForbidden
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return types.FileReadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return types.FileReadResult{}, err
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return types.FileReadResult{}, errors.New("file is not editable text")
	}
	hash := sha256.Sum256(data)
	return types.FileReadResult{Path: rel, Content: string(data), SHA256: hex.EncodeToString(hash[:]), Mode: uint32(info.Mode().Perm())}, nil
}

func (m *FileManager) WriteFile(ctx context.Context, req types.FileWriteReq) (types.FileMutationResult, error) {
	id, rel, full, info, err := m.regularFile(req.Username, req.Path)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if len(req.Content) > maxEditableBytes || !utf8.ValidString(req.Content) || strings.IndexByte(req.Content, 0) >= 0 {
		return types.FileMutationResult{}, errors.New("file content is not valid editable text")
	}
	if !canAccess(info, id, 0o2) || !ownedBy(info, id.uid) {
		return types.FileMutationResult{}, errFileForbidden
	}
	current, err := os.ReadFile(full)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	hash := sha256.Sum256(current)
	if !strings.EqualFold(strings.TrimSpace(req.ExpectedSHA256), hex.EncodeToString(hash[:])) {
		return types.FileMutationResult{}, fmt.Errorf("%w: file changed since it was opened", errFileConflict)
	}
	if err := writeOwnedFileAtomic(ctx, full, strings.NewReader(req.Content), info.Mode().Perm(), id); err != nil {
		return types.FileMutationResult{}, err
	}
	return types.FileMutationResult{Paths: []string{rel}}, nil
}

func (m *FileManager) CreateEntry(ctx context.Context, req types.FileCreateReq) (types.FileMutationResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	rel, err := cleanManagedPath(req.Path, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	full, err := m.resolve(id, rel, true, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if _, err := os.Lstat(full); err == nil {
		return types.FileMutationResult{}, fmt.Errorf("%w: destination already exists", errFileConflict)
	} else if !os.IsNotExist(err) {
		return types.FileMutationResult{}, err
	}
	parentInfo, err := os.Stat(filepath.Dir(full))
	if err != nil || !canAccess(parentInfo, id, 0o3) {
		return types.FileMutationResult{}, errFileForbidden
	}
	switch req.Kind {
	case types.FileKindFile:
		if err := writeOwnedFileAtomic(ctx, full, strings.NewReader(""), 0o644, id); err != nil {
			return types.FileMutationResult{}, err
		}
	case types.FileKindDirectory:
		if err := os.Mkdir(full, 0o755); err != nil {
			return types.FileMutationResult{}, err
		}
		if err := chownPath(full, id); err != nil {
			_ = os.Remove(full)
			return types.FileMutationResult{}, err
		}
	default:
		return types.FileMutationResult{}, errors.New("entry kind must be file or directory")
	}
	return types.FileMutationResult{Paths: []string{rel}}, nil
}

func (m *FileManager) CopyFiles(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
	return m.copyOrMove(ctx, req, false)
}

func (m *FileManager) MoveFiles(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
	return m.copyOrMove(ctx, req, true)
}

func (m *FileManager) copyOrMove(ctx context.Context, req types.FileBatchReq, move bool) (types.FileMutationResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	destRel, err := cleanManagedPath(req.Destination, true)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	destDir, err := m.resolve(id, destRel, true, true)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	destInfo, err := os.Stat(destDir)
	if err != nil || !destInfo.IsDir() || !canAccess(destInfo, id, 0o3) {
		return types.FileMutationResult{}, errFileForbidden
	}
	paths, err := normalizeManagedPaths(req.Paths)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	changed := make([]string, 0, len(paths))
	for _, rel := range paths {
		if err := ctx.Err(); err != nil {
			return types.FileMutationResult{}, err
		}
		source, err := m.resolve(id, rel, false, false)
		if err != nil {
			return types.FileMutationResult{}, err
		}
		info, err := os.Lstat(source)
		if err != nil {
			return types.FileMutationResult{}, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !ownedBy(info, id.uid) {
			return types.FileMutationResult{}, errFileForbidden
		}
		sourceParent, err := os.Stat(filepath.Dir(source))
		if err != nil || (move && !canAccess(sourceParent, id, 0o3)) {
			return types.FileMutationResult{}, errFileForbidden
		}
		targetName := filepath.Base(source)
		if move && len(paths) == 1 && strings.TrimSpace(req.NewName) != "" {
			cleanName, nameErr := cleanManagedPath(strings.TrimSpace(req.NewName), false)
			if nameErr != nil || strings.Contains(cleanName, "/") {
				return types.FileMutationResult{}, errors.New("invalid rename destination")
			}
			targetName = cleanName
		}
		target := filepath.Join(destDir, targetName)
		targetRel := path.Join(destRel, filepath.Base(source))
		if targetName != filepath.Base(source) {
			targetRel = path.Join(destRel, targetName)
		}
		if sameManagedPath(source, target) {
			return types.FileMutationResult{}, fmt.Errorf("%w: source and destination are the same", errFileConflict)
		}
		if info.IsDir() && pathWithin(source, target) {
			return types.FileMutationResult{}, errors.New("destination cannot be inside the source directory")
		}
		if move {
			if err := movePathAtomic(source, target, req.Overwrite); err != nil {
				return types.FileMutationResult{}, err
			}
		} else {
			stage, err := os.MkdirTemp(destDir, ".nakpanel-copy-")
			if err != nil {
				return types.FileMutationResult{}, err
			}
			stagedTarget := filepath.Join(stage, targetName)
			copyErr := copyTree(ctx, source, stagedTarget, id)
			if copyErr == nil {
				copyErr = publishPathAtomic(stagedTarget, target, req.Overwrite)
			}
			_ = os.RemoveAll(stage)
			if copyErr != nil {
				return types.FileMutationResult{}, copyErr
			}
		}
		changed = append(changed, targetRel)
	}
	return types.FileMutationResult{Paths: changed}, nil
}

func (m *FileManager) DeleteFiles(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	paths, err := normalizeManagedPaths(req.Paths)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	trash, err := os.MkdirTemp(id.root, ".nakpanel-trash-")
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if err := chownPath(trash, id); err != nil {
		_ = os.RemoveAll(trash)
		return types.FileMutationResult{}, err
	}
	type stagedDelete struct{ original, staged, rel string }
	moved := make([]stagedDelete, 0, len(paths))
	rollback := func() {
		for index := len(moved) - 1; index >= 0; index-- {
			_ = os.Rename(moved[index].staged, moved[index].original)
		}
		_ = os.RemoveAll(trash)
	}
	for index, rel := range paths {
		if err := ctx.Err(); err != nil {
			rollback()
			return types.FileMutationResult{}, err
		}
		full, err := m.resolve(id, rel, false, false)
		if err != nil {
			rollback()
			return types.FileMutationResult{}, err
		}
		info, err := os.Lstat(full)
		if err != nil || !ownedBy(info, id.uid) {
			rollback()
			return types.FileMutationResult{}, errFileForbidden
		}
		parentInfo, err := os.Stat(filepath.Dir(full))
		if err != nil || !canAccess(parentInfo, id, 0o3) {
			rollback()
			return types.FileMutationResult{}, errFileForbidden
		}
		staged := filepath.Join(trash, fmt.Sprintf("%04d-%s", index, filepath.Base(full)))
		if err := os.Rename(full, staged); err != nil {
			rollback()
			return types.FileMutationResult{}, err
		}
		moved = append(moved, stagedDelete{original: full, staged: staged, rel: rel})
	}
	if err := os.RemoveAll(trash); err != nil {
		return types.FileMutationResult{}, err
	}
	changed := make([]string, 0, len(moved))
	for _, item := range moved {
		changed = append(changed, item.rel)
	}
	return types.FileMutationResult{Paths: changed}, nil
}

func (m *FileManager) ArchiveFiles(ctx context.Context, req types.FileArchiveReq) (types.FileMutationResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	paths, err := normalizeManagedPaths(req.Paths)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	destRel, err := cleanManagedPath(req.Destination, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if !strings.HasSuffix(strings.ToLower(destRel), ".zip") {
		return types.FileMutationResult{}, errors.New("archive destination must end in .zip")
	}
	destination, err := m.resolve(id, destRel, true, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return types.FileMutationResult{}, fmt.Errorf("%w: archive already exists", errFileConflict)
	}
	parentInfo, err := os.Stat(filepath.Dir(destination))
	if err != nil || !canAccess(parentInfo, id, 0o3) {
		return types.FileMutationResult{}, errFileForbidden
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".nakpanel-archive-*.zip")
	if err != nil {
		return types.FileMutationResult{}, err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := chownOpenFile(tmp, id); err != nil {
		return types.FileMutationResult{}, err
	}
	zw := zip.NewWriter(tmp)
	entries := 0
	for _, rel := range paths {
		source, err := m.resolve(id, rel, false, false)
		if err != nil {
			return types.FileMutationResult{}, err
		}
		sourceInfo, err := os.Lstat(source)
		if err != nil {
			return types.FileMutationResult{}, err
		}
		if sourceInfo.Mode()&os.ModeSymlink != 0 {
			return types.FileMutationResult{}, errFileForbidden
		}
		base := filepath.Dir(source)
		err = filepath.WalkDir(source, func(full string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("archives cannot contain symbolic links")
			}
			entries++
			if entries > maxArchiveEntries {
				return errors.New("archive contains too many entries")
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			required := os.FileMode(0o4)
			if info.IsDir() {
				required = 0o5
			}
			if !canAccess(info, id, required) {
				return errFileForbidden
			}
			name, err := filepath.Rel(base, full)
			if err != nil {
				return err
			}
			name = filepath.ToSlash(name)
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = name
			if info.IsDir() {
				header.Name += "/"
			}
			header.Method = zip.Deflate
			writer, err := zw.CreateHeader(header)
			if err != nil || info.IsDir() {
				return err
			}
			input, err := os.Open(full)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(writer, input)
			closeErr := input.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		})
		if err != nil {
			return types.FileMutationResult{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return types.FileMutationResult{}, err
	}
	if err := tmp.Sync(); err != nil {
		return types.FileMutationResult{}, err
	}
	if err := tmp.Close(); err != nil {
		return types.FileMutationResult{}, err
	}
	if err := os.Rename(tmpName, destination); err != nil {
		return types.FileMutationResult{}, err
	}
	cleanup = false
	return types.FileMutationResult{Paths: []string{destRel}}, nil
}

func (m *FileManager) ExtractArchive(ctx context.Context, req types.FileExtractReq) (types.FileMutationResult, error) {
	id, archiveRel, archivePath, info, err := m.regularFile(req.Username, req.Path)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if !canAccess(info, id, 0o4) {
		return types.FileMutationResult{}, errFileForbidden
	}
	destRel, err := cleanManagedPath(req.Destination, true)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	dest, err := m.resolve(id, destRel, true, true)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		if err := os.Mkdir(dest, 0o755); err != nil {
			return types.FileMutationResult{}, err
		}
		if err := chownPath(dest, id); err != nil {
			_ = os.Remove(dest)
			return types.FileMutationResult{}, err
		}
	} else if err != nil {
		return types.FileMutationResult{}, err
	}
	destInfo, err := os.Stat(dest)
	if err != nil || !canAccess(destInfo, id, 0o3) {
		return types.FileMutationResult{}, errFileForbidden
	}
	stage, err := os.MkdirTemp(dest, ".nakpanel-extract-")
	if err != nil {
		return types.FileMutationResult{}, err
	}
	defer os.RemoveAll(stage)
	if err := chownPath(stage, id); err != nil {
		return types.FileMutationResult{}, err
	}
	lower := strings.ToLower(archiveRel)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		err = extractZIP(ctx, archivePath, stage, id)
	case strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		err = extractTAR(ctx, archivePath, stage, id, strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz"))
	default:
		err = errors.New("unsupported archive format")
	}
	if err != nil {
		return types.FileMutationResult{}, err
	}
	children, err := os.ReadDir(stage)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	for _, child := range children {
		target := filepath.Join(dest, child.Name())
		if _, err := os.Lstat(target); err == nil && !req.Overwrite {
			return types.FileMutationResult{}, fmt.Errorf("%w: %s already exists", errFileConflict, child.Name())
		} else if err != nil && !os.IsNotExist(err) {
			return types.FileMutationResult{}, err
		}
	}
	backup, err := os.MkdirTemp(dest, ".nakpanel-extract-backup-")
	if err != nil {
		return types.FileMutationResult{}, err
	}
	defer os.RemoveAll(backup)
	type publishedEntry struct {
		target, backup string
		hadExisting    bool
	}
	published := make([]publishedEntry, 0, len(children))
	rollback := func() {
		for index := len(published) - 1; index >= 0; index-- {
			entry := published[index]
			_ = os.RemoveAll(entry.target)
			if entry.hadExisting {
				_ = os.Rename(entry.backup, entry.target)
			}
		}
	}
	changed := make([]string, 0, len(children))
	for index, child := range children {
		target := filepath.Join(dest, child.Name())
		entry := publishedEntry{target: target, backup: filepath.Join(backup, fmt.Sprintf("%04d-%s", index, child.Name()))}
		if _, err := os.Lstat(target); err == nil {
			if err := os.Rename(target, entry.backup); err != nil {
				rollback()
				return types.FileMutationResult{}, err
			}
			entry.hadExisting = true
		}
		if err := os.Rename(filepath.Join(stage, child.Name()), target); err != nil {
			if entry.hadExisting {
				_ = os.Rename(entry.backup, target)
			}
			rollback()
			return types.FileMutationResult{}, err
		}
		published = append(published, entry)
		changed = append(changed, path.Join(destRel, child.Name()))
	}
	return types.FileMutationResult{Paths: changed}, nil
}

func (m *FileManager) SetFileMode(ctx context.Context, req types.FileModeReq) (types.FileMutationResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	rel, err := cleanManagedPath(req.Path, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if req.Mode > 0o777 {
		return types.FileMutationResult{}, errors.New("special permission bits are not allowed")
	}
	full, err := m.resolve(id, rel, false, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	info, err := os.Lstat(full)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !ownedBy(info, id.uid) {
		return types.FileMutationResult{}, errFileForbidden
	}
	mode := os.FileMode(req.Mode)
	changed := []string{rel}
	if !req.Recursive || !info.IsDir() {
		return types.FileMutationResult{Paths: changed}, os.Chmod(full, mode)
	}
	count := 0
	err = filepath.WalkDir(full, func(itemPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > maxDirectoryEntries {
			return errors.New("recursive permission change exceeds entry limit")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return os.Chmod(itemPath, mode)
	})
	return types.FileMutationResult{Paths: changed}, err
}

func (m *FileManager) ImportTransfer(ctx context.Context, req types.FileTransferImportReq) (types.FileMutationResult, error) {
	id, err := m.identity(req.Username)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if !transferTokenRE.MatchString(req.TransferToken) || !strings.HasPrefix(req.TransferToken, "upload-") {
		return types.FileMutationResult{}, errors.New("invalid upload transfer token")
	}
	rel, err := cleanManagedPath(req.Destination, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	destination, err := m.resolve(id, rel, true, false)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if _, err := os.Lstat(destination); err == nil && !req.Overwrite {
		return types.FileMutationResult{}, fmt.Errorf("%w: destination already exists", errFileConflict)
	}
	transfer := filepath.Join(m.transferDir, req.TransferToken)
	info, err := os.Lstat(transfer)
	if err != nil || !info.Mode().IsRegular() {
		return types.FileMutationResult{}, errors.New("upload transfer is unavailable")
	}
	input, err := os.Open(transfer)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	defer input.Close()
	if err := writeOwnedFileAtomic(ctx, destination, input, 0o644, id); err != nil {
		return types.FileMutationResult{}, err
	}
	if err := os.Remove(transfer); err != nil && !os.IsNotExist(err) {
		return types.FileMutationResult{}, err
	}
	return types.FileMutationResult{Paths: []string{rel}}, nil
}

func (m *FileManager) ExportTransfer(ctx context.Context, req types.FileTransferExportReq) (types.FileTransferResult, error) {
	id, _, source, info, err := m.regularFile(req.Username, req.Path)
	if err != nil {
		return types.FileTransferResult{}, err
	}
	if !canAccess(info, id, 0o4) {
		return types.FileTransferResult{}, errFileForbidden
	}
	if err := os.MkdirAll(m.transferDir, 0o700); err != nil {
		return types.FileTransferResult{}, err
	}
	token, err := randomTransferToken("download")
	if err != nil {
		return types.FileTransferResult{}, err
	}
	target := filepath.Join(m.transferDir, token)
	input, err := os.Open(source)
	if err != nil {
		return types.FileTransferResult{}, err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return types.FileTransferResult{}, err
	}
	cleanup := true
	defer func() {
		_ = output.Close()
		if cleanup {
			_ = os.Remove(target)
		}
	}()
	if _, err := copyWithContext(ctx, output, input); err != nil {
		return types.FileTransferResult{}, err
	}
	if err := output.Sync(); err != nil {
		return types.FileTransferResult{}, err
	}
	if err := output.Close(); err != nil {
		return types.FileTransferResult{}, err
	}
	if panel, err := user.Lookup(m.panelUser); err == nil && os.Geteuid() == 0 {
		uid, _ := strconv.Atoi(panel.Uid)
		gid, _ := strconv.Atoi(panel.Gid)
		if err := os.Chown(target, uid, gid); err != nil {
			return types.FileTransferResult{}, err
		}
	}
	cleanup = false
	return types.FileTransferResult{TransferToken: token, Name: filepath.Base(source), Size: info.Size(), ModifiedAt: info.ModTime()}, nil
}

func (m *FileManager) identity(username string) (siteIdentity, error) {
	username = strings.TrimSpace(username)
	if !fileManagerUsernameRE.MatchString(username) {
		return siteIdentity{}, fmt.Errorf("unsafe file manager username %q", username)
	}
	account, err := user.Lookup(username)
	if err != nil {
		return siteIdentity{}, fmt.Errorf("lookup site user: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return siteIdentity{}, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return siteIdentity{}, err
	}
	groups := map[uint32]bool{uint32(gid): true}
	if ids, err := account.GroupIds(); err == nil {
		for _, raw := range ids {
			if value, err := strconv.ParseUint(raw, 10, 32); err == nil {
				groups[uint32(value)] = true
			}
		}
	}
	root := filepath.Join(m.homeRoot, username, "public_html")
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return siteIdentity{}, fmt.Errorf("resolve site document root: %w", err)
	}
	return siteIdentity{username: username, uid: uid, gid: gid, groups: groups, root: resolvedRoot}, nil
}

func (m *FileManager) resolve(id siteIdentity, rel string, allowMissing, followFinal bool) (string, error) {
	if rel == "" {
		return id.root, nil
	}
	joined := filepath.Join(id.root, filepath.FromSlash(rel))
	parent := filepath.Dir(joined)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	if err := ensureWithinRoot(id.root, resolvedParent); err != nil {
		return "", err
	}
	if err := verifyManagedPath(id.root, resolvedParent); err != nil {
		return "", err
	}
	joined = filepath.Join(resolvedParent, filepath.Base(joined))
	if !followFinal {
		return joined, nil
	}
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if allowMissing && os.IsNotExist(err) {
			return joined, nil
		}
		return "", err
	}
	if err := ensureWithinRoot(id.root, resolved); err != nil {
		return "", err
	}
	if err := verifyManagedPath(id.root, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func (m *FileManager) regularFile(username, requestedPath string) (siteIdentity, string, string, os.FileInfo, error) {
	id, err := m.identity(username)
	if err != nil {
		return siteIdentity{}, "", "", nil, err
	}
	rel, err := cleanManagedPath(requestedPath, false)
	if err != nil {
		return siteIdentity{}, "", "", nil, err
	}
	full, err := m.resolve(id, rel, false, true)
	if err != nil {
		return siteIdentity{}, "", "", nil, err
	}
	info, err := os.Stat(full)
	if err != nil {
		return siteIdentity{}, "", "", nil, err
	}
	if !info.Mode().IsRegular() {
		return siteIdentity{}, "", "", nil, errors.New("path is not a regular file")
	}
	return id, rel, full, info, nil
}

func cleanManagedPath(raw string, allowRoot bool) (string, error) {
	if !utf8.ValidString(raw) || strings.IndexByte(raw, 0) >= 0 || len(raw) > 4096 || path.IsAbs(raw) || filepath.IsAbs(raw) {
		return "", errors.New("invalid managed path")
	}
	raw = strings.Trim(raw, "/")
	if raw == "" {
		if allowRoot {
			return "", nil
		}
		return "", errors.New("root path cannot be modified")
	}
	for _, part := range strings.Split(raw, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return "", errors.New("invalid managed path segment")
		}
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("managed path escapes document root")
	}
	return cleaned, nil
}

func normalizeManagedPaths(paths []string) ([]string, error) {
	if len(paths) == 0 || len(paths) > 200 {
		return nil, errors.New("select between 1 and 200 paths")
	}
	seen := make(map[string]bool, len(paths))
	result := make([]string, 0, len(paths))
	for _, raw := range paths {
		rel, err := cleanManagedPath(raw, false)
		if err != nil {
			return nil, err
		}
		if !seen[rel] {
			seen[rel] = true
			result = append(result, rel)
		}
	}
	return result, nil
}

func ensureWithinRoot(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("managed path escapes document root")
	}
	return nil
}

func fileEntry(rel string, info os.FileInfo, id siteIdentity) types.FileEntry {
	kind := types.FileKindFile
	if info.IsDir() {
		kind = types.FileKindDirectory
	} else if info.Mode()&os.ModeSymlink != 0 {
		kind = types.FileKindSymlink
	}
	owner, group := fileOwner(info)
	regular := info.Mode().IsRegular()
	owned := ownedBy(info, id.uid)
	writable := owned && canAccess(info, id, 0o2)
	readable := canAccess(info, id, 0o4)
	return types.FileEntry{
		Path: rel, Name: path.Base(rel), Kind: kind, Size: info.Size(), Mode: uint32(info.Mode().Perm()),
		ModifiedAt: info.ModTime(), Owner: owner, Group: group,
		Editable:     regular && info.Size() <= maxEditableBytes && readable && writable,
		Downloadable: regular && readable, Writable: writable,
		Chmod:   owned && kind != types.FileKindSymlink,
		Archive: regular && readable && isArchiveName(info.Name()),
	}
}

func fileOwner(info os.FileInfo) (string, string) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "-", "-"
	}
	owner := strconv.FormatUint(uint64(stat.Uid), 10)
	group := strconv.FormatUint(uint64(stat.Gid), 10)
	if account, err := user.LookupId(owner); err == nil {
		owner = account.Username
	}
	if item, err := user.LookupGroupId(group); err == nil {
		group = item.Name
	}
	return owner, group
}

func canAccess(info os.FileInfo, id siteIdentity, bits os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := info.Mode().Perm()
	var actual os.FileMode
	if int(stat.Uid) == id.uid {
		actual = (perm >> 6) & 0o7
	} else if id.groups[stat.Gid] {
		actual = (perm >> 3) & 0o7
	} else {
		actual = perm & 0o7
	}
	return actual&bits == bits
}

func ownedBy(info os.FileInfo, uid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == uid
}

func chownPath(name string, id siteIdentity) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Chown(name, id.uid, id.gid)
}

func chownOpenFile(file *os.File, id siteIdentity) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return file.Chown(id.uid, id.gid)
}

func writeOwnedFileAtomic(ctx context.Context, destination string, reader io.Reader, mode os.FileMode, id siteIdentity) error {
	parentInfo, err := os.Stat(filepath.Dir(destination))
	if err != nil || !canAccess(parentInfo, id, 0o3) {
		return errFileForbidden
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".nakpanel-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := chownOpenFile(tmp, id); err != nil {
		return err
	}
	if err := tmp.Chmod(mode.Perm()); err != nil {
		return err
	}
	if _, err := copyWithContext(ctx, tmp, reader); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, destination); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func sameManagedPath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && leftAbs == rightAbs
}

func pathWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func movePathAtomic(source, target string, overwrite bool) error {
	return publishPathAtomic(source, target, overwrite)
}

func publishPathAtomic(staged, target string, overwrite bool) error {
	_, err := os.Lstat(target)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if os.IsNotExist(err) {
		return os.Rename(staged, target)
	}
	if !overwrite {
		return fmt.Errorf("%w: destination already exists", errFileConflict)
	}
	backupDir, err := os.MkdirTemp(filepath.Dir(target), ".nakpanel-replace-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(backupDir)
	backup := filepath.Join(backupDir, filepath.Base(target))
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := os.Rename(staged, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	return nil
}

func copyTree(ctx context.Context, source, destination string, id siteIdentity) error {
	return filepath.WalkDir(source, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symbolic links cannot be copied")
		}
		rel, err := filepath.Rel(source, full)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		required := os.FileMode(0o4)
		if info.IsDir() {
			required = 0o5
		}
		if !canAccess(info, id, required) {
			return errFileForbidden
		}
		if entry.IsDir() {
			if err := os.Mkdir(target, info.Mode().Perm()); err != nil && !os.IsExist(err) {
				return err
			}
			return chownPath(target, id)
		}
		input, err := os.Open(full)
		if err != nil {
			return err
		}
		defer input.Close()
		return writeOwnedFileAtomic(ctx, target, input, info.Mode().Perm(), id)
	})
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func extractZIP(ctx context.Context, archivePath, destination string, id siteIdentity) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if len(reader.File) > maxArchiveEntries {
		return errors.New("archive contains too many entries")
	}
	var expanded int64
	for _, item := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if item.Mode()&os.ModeSymlink != 0 || !managedArchiveName(item.Name) {
			return errors.New("archive contains an unsafe entry")
		}
		expanded += int64(item.UncompressedSize64)
		if expanded > maxExpandedBytes {
			return errors.New("archive expanded size exceeds limit")
		}
		target := filepath.Join(destination, filepath.FromSlash(path.Clean(item.Name)))
		if err := ensureWithinRoot(destination, target); err != nil {
			return err
		}
		if item.FileInfo().IsDir() {
			if err := mkdirOwnedAll(destination, target, item.Mode().Perm(), id); err != nil {
				return err
			}
			if err := os.Chmod(target, item.Mode().Perm()); err != nil {
				return err
			}
			continue
		}
		if err := mkdirOwnedAll(destination, filepath.Dir(target), 0o755, id); err != nil {
			return err
		}
		input, err := item.Open()
		if err != nil {
			return err
		}
		err = writeOwnedFileAtomic(ctx, target, input, item.Mode().Perm(), id)
		_ = input.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTAR(ctx context.Context, archivePath, destination string, id siteIdentity, compressed bool) error {
	input, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer input.Close()
	var reader io.Reader = input
	if compressed {
		gzipReader, err := gzip.NewReader(input)
		if err != nil {
			return err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	tarReader := tar.NewReader(reader)
	entries := 0
	var expanded int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > maxArchiveEntries || !managedArchiveName(header.Name) {
			return errors.New("archive contains an unsafe number or path of entries")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			return errors.New("archive contains unsupported links or devices")
		}
		expanded += header.Size
		if expanded > maxExpandedBytes {
			return errors.New("archive expanded size exceeds limit")
		}
		target := filepath.Join(destination, filepath.FromSlash(path.Clean(header.Name)))
		if err := ensureWithinRoot(destination, target); err != nil {
			return err
		}
		if header.Typeflag == tar.TypeDir {
			mode := os.FileMode(header.Mode).Perm()
			if err := mkdirOwnedAll(destination, target, mode, id); err != nil {
				return err
			}
			if err := os.Chmod(target, mode); err != nil {
				return err
			}
			continue
		}
		if err := mkdirOwnedAll(destination, filepath.Dir(target), 0o755, id); err != nil {
			return err
		}
		if err := writeOwnedFileAtomic(ctx, target, io.LimitReader(tarReader, header.Size), os.FileMode(header.Mode).Perm(), id); err != nil {
			return err
		}
	}
}

func managedArchiveName(name string) bool {
	if !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 || len(name) > 4096 || path.IsAbs(name) {
		return false
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return false
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
	}
	return true
}

func mkdirOwnedAll(root, target string, mode os.FileMode, id siteIdentity) error {
	if err := ensureWithinRoot(root, target); err != nil {
		return err
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if info, err := os.Stat(current); os.IsNotExist(err) {
			if err := os.Mkdir(current, mode); err != nil {
				return err
			}
			if err := chownPath(current, id); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if !info.IsDir() {
			return errors.New("archive path component is not a directory")
		}
	}
	return nil
}

func isArchiveName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

func sortFileEntries(entries []types.FileEntry, field, order string) {
	desc := strings.EqualFold(order, "desc")
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		if left.Kind == types.FileKindDirectory && right.Kind != types.FileKindDirectory {
			return true
		}
		if left.Kind != types.FileKindDirectory && right.Kind == types.FileKindDirectory {
			return false
		}
		comparison := 0
		switch strings.ToLower(field) {
		case "size":
			if left.Size < right.Size {
				comparison = -1
			} else if left.Size > right.Size {
				comparison = 1
			}
		case "modified":
			if left.ModifiedAt.Before(right.ModifiedAt) {
				comparison = -1
			} else if left.ModifiedAt.After(right.ModifiedAt) {
				comparison = 1
			}
		default:
			comparison = strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name))
		}
		if comparison == 0 {
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		}
		if desc {
			return comparison > 0
		}
		return comparison < 0
	})
}

func randomTransferToken(prefix string) (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(data[:]), nil
}

func SweepFileTransfers(dir string, olderThan time.Duration) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-olderThan)
	for _, entry := range entries {
		if !transferTokenRE.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
	return nil
}
