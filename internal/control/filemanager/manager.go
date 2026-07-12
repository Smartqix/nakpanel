package filemanager

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ErrNotFound     = errors.New("file manager site not found")
	ErrForbidden    = errors.New("file manager access forbidden")
	ErrConflict     = errors.New("file manager conflict")
	ErrTooLarge     = errors.New("file manager request too large")
	ErrValidation   = errors.New("file manager validation failed")
	ErrUnavailable  = errors.New("file manager agent unavailable")
	uploadTokenRE   = regexp.MustCompile(`^upload-[a-f0-9]{32}$`)
	downloadTokenRE = regexp.MustCompile(`^download-[a-f0-9]{32}$`)
)

const (
	normalFileOperationTimeout = 30 * time.Second
	bulkFileOperationTimeout   = 5 * time.Minute
)

type Site struct {
	ID             int64
	Username       string
	Domain         string
	Status         string
	CustomerID     int64
	SubscriptionID int64
}

type Store interface {
	GetSite(context.Context, int64) (Site, error)
	RecordAudit(context.Context, auth.SessionUser, Site, string, any) error
}

type AccessPolicy interface {
	CanManageDomain(context.Context, auth.SessionUser, string) (bool, error)
}

type Agent interface {
	ListFiles(context.Context, types.FileListReq) (types.FileListResult, error)
	SearchFiles(context.Context, types.FileSearchReq) (types.FileSearchResult, error)
	ReadFile(context.Context, types.FileReadReq) (types.FileReadResult, error)
	WriteFile(context.Context, types.FileWriteReq) (types.FileMutationResult, error)
	CreateFileEntry(context.Context, types.FileCreateReq) (types.FileMutationResult, error)
	CopyFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error)
	MoveFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error)
	DeleteFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error)
	ArchiveFiles(context.Context, types.FileArchiveReq) (types.FileMutationResult, error)
	ExtractArchive(context.Context, types.FileExtractReq) (types.FileMutationResult, error)
	SetFileMode(context.Context, types.FileModeReq) (types.FileMutationResult, error)
	ImportFileTransfer(context.Context, types.FileTransferImportReq) (types.FileMutationResult, error)
	ExportFileTransfer(context.Context, types.FileTransferExportReq) (types.FileTransferResult, error)
}

type ManagerOptions struct {
	Store          Store
	Access         AccessPolicy
	Agent          Agent
	TransferDir    string
	UploadMaxBytes int64
}

type Manager struct {
	store          Store
	access         AccessPolicy
	agent          Agent
	transferDir    string
	uploadMaxBytes int64
}

func NewManager(opts ManagerOptions) *Manager {
	return &Manager{store: opts.Store, access: opts.Access, agent: opts.Agent, transferDir: opts.TransferDir, uploadMaxBytes: opts.UploadMaxBytes}
}

func (m *Manager) UploadMaxBytes() int64 { return m.uploadMaxBytes }

func (m *Manager) Site(ctx context.Context, actor auth.SessionUser, id int64) (Site, error) {
	if m == nil || m.store == nil {
		return Site{}, ErrUnavailable
	}
	site, err := m.store.GetSite(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Site{}, ErrNotFound
	}
	if err != nil {
		return Site{}, err
	}
	if actor.Role != auth.RoleAdmin {
		if m.access == nil {
			return Site{}, ErrForbidden
		}
		allowed, err := m.access.CanManageDomain(ctx, actor, site.Domain)
		if err != nil {
			return Site{}, err
		}
		if !allowed {
			return Site{}, ErrNotFound
		}
	}
	return site, nil
}

func (m *Manager) List(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileListReq) (Site, types.FileListResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return Site{}, types.FileListResult{}, err
	}
	if m.agent == nil {
		return site, types.FileListResult{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, normalFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := m.agent.ListFiles(ctx, req)
	return site, result, classifyAgentError(err)
}

func (m *Manager) Search(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileSearchReq) (Site, types.FileSearchResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return Site{}, types.FileSearchResult{}, err
	}
	if m.agent == nil {
		return site, types.FileSearchResult{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, normalFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := m.agent.SearchFiles(ctx, req)
	return site, result, classifyAgentError(err)
}

func (m *Manager) Read(ctx context.Context, actor auth.SessionUser, siteID int64, path string) (Site, types.FileReadResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return Site{}, types.FileReadResult{}, err
	}
	if m.agent == nil {
		return site, types.FileReadResult{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, normalFileOperationTimeout)
	defer cancel()
	result, err := m.agent.ReadFile(ctx, types.FileReadReq{Username: site.Username, Path: path})
	return site, result, classifyAgentError(err)
}

func (m *Manager) Write(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileWriteReq) (types.FileMutationResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if m.agent == nil {
		return types.FileMutationResult{}, ErrUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, normalFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := m.agent.WriteFile(opCtx, req)
	return result, m.auditResult(ctx, actor, site, "file.edit", map[string]any{"path": req.Path, "bytes": len(req.Content)}, result, err)
}

func (m *Manager) Create(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileCreateReq) (types.FileMutationResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if m.agent == nil {
		return types.FileMutationResult{}, ErrUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, normalFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := m.agent.CreateFileEntry(opCtx, req)
	return result, m.auditResult(ctx, actor, site, "file.create", map[string]any{"path": req.Path, "kind": req.Kind}, result, err)
}

func (m *Manager) Copy(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileBatchReq) (types.FileMutationResult, error) {
	return m.batch(ctx, actor, siteID, req, "file.copy", func(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
		return m.agent.CopyFiles(ctx, req)
	})
}

func (m *Manager) Move(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileBatchReq) (types.FileMutationResult, error) {
	return m.batch(ctx, actor, siteID, req, "file.move", func(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
		return m.agent.MoveFiles(ctx, req)
	})
}

func (m *Manager) Delete(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileBatchReq) (types.FileMutationResult, error) {
	return m.batch(ctx, actor, siteID, req, "file.delete", func(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
		return m.agent.DeleteFiles(ctx, req)
	})
}

func (m *Manager) batch(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileBatchReq, action string, call func(context.Context, types.FileBatchReq) (types.FileMutationResult, error)) (types.FileMutationResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if m.agent == nil {
		return types.FileMutationResult{}, ErrUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, bulkFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := call(opCtx, req)
	return result, m.auditResult(ctx, actor, site, action, map[string]any{"paths": req.Paths, "destination": req.Destination, "new_name": req.NewName, "overwrite": req.Overwrite}, result, err)
}

func (m *Manager) Archive(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileArchiveReq) (types.FileMutationResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if m.agent == nil {
		return types.FileMutationResult{}, ErrUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, bulkFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := m.agent.ArchiveFiles(opCtx, req)
	return result, m.auditResult(ctx, actor, site, "file.archive", map[string]any{"paths": req.Paths, "destination": req.Destination}, result, err)
}

func (m *Manager) Extract(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileExtractReq) (types.FileMutationResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if m.agent == nil {
		return types.FileMutationResult{}, ErrUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, bulkFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := m.agent.ExtractArchive(opCtx, req)
	return result, m.auditResult(ctx, actor, site, "file.extract", map[string]any{"path": req.Path, "destination": req.Destination, "overwrite": req.Overwrite}, result, err)
}

func (m *Manager) Chmod(ctx context.Context, actor auth.SessionUser, siteID int64, req types.FileModeReq) (types.FileMutationResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if m.agent == nil {
		return types.FileMutationResult{}, ErrUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, normalFileOperationTimeout)
	defer cancel()
	req.Username = site.Username
	result, err := m.agent.SetFileMode(opCtx, req)
	return result, m.auditResult(ctx, actor, site, "file.permissions", map[string]any{"path": req.Path, "mode": req.Mode, "recursive": req.Recursive}, result, err)
}

func (m *Manager) StageUpload(ctx context.Context, reader io.Reader) (string, int64, error) {
	if m == nil || strings.TrimSpace(m.transferDir) == "" {
		return "", 0, ErrUnavailable
	}
	if err := os.MkdirAll(m.transferDir, 0o700); err != nil {
		return "", 0, err
	}
	token, err := newUploadToken()
	if err != nil {
		return "", 0, err
	}
	name := filepath.Join(m.transferDir, token)
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(name)
		}
	}()
	written, err := copyContext(ctx, file, io.LimitReader(reader, m.uploadMaxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if written > m.uploadMaxBytes {
		return "", 0, ErrTooLarge
	}
	if err := file.Sync(); err != nil {
		return "", 0, err
	}
	if err := file.Close(); err != nil {
		return "", 0, err
	}
	cleanup = false
	return token, written, nil
}

func (m *Manager) Import(ctx context.Context, actor auth.SessionUser, siteID int64, token, destination string, overwrite bool, bytes int64) (types.FileMutationResult, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return types.FileMutationResult{}, err
	}
	if m.agent == nil {
		return types.FileMutationResult{}, ErrUnavailable
	}
	if !uploadTokenRE.MatchString(token) {
		return types.FileMutationResult{}, ErrValidation
	}
	opCtx, cancel := context.WithTimeout(ctx, bulkFileOperationTimeout)
	defer cancel()
	result, err := m.agent.ImportFileTransfer(opCtx, types.FileTransferImportReq{Username: site.Username, TransferToken: token, Destination: destination, Overwrite: overwrite})
	return result, m.auditResult(ctx, actor, site, "file.upload", map[string]any{"path": destination, "bytes": bytes, "overwrite": overwrite}, result, err)
}

func (m *Manager) Download(ctx context.Context, actor auth.SessionUser, siteID int64, path string) (Site, types.FileTransferResult, string, error) {
	site, err := m.Site(ctx, actor, siteID)
	if err != nil {
		return Site{}, types.FileTransferResult{}, "", err
	}
	if m.agent == nil {
		return site, types.FileTransferResult{}, "", ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, bulkFileOperationTimeout)
	defer cancel()
	result, err := m.agent.ExportFileTransfer(ctx, types.FileTransferExportReq{Username: site.Username, Path: path})
	if err != nil {
		return site, types.FileTransferResult{}, "", classifyAgentError(err)
	}
	if !downloadTokenRE.MatchString(result.TransferToken) {
		return site, types.FileTransferResult{}, "", ErrUnavailable
	}
	if err := m.store.RecordAudit(ctx, actor, site, "file.download", map[string]any{"path": path, "bytes": result.Size}); err != nil {
		_ = os.Remove(filepath.Join(m.transferDir, result.TransferToken))
		return site, types.FileTransferResult{}, "", err
	}
	return site, result, filepath.Join(m.transferDir, result.TransferToken), nil
}

func (m *Manager) CleanupTransfer(token string) {
	if uploadTokenRE.MatchString(token) || downloadTokenRE.MatchString(token) {
		_ = os.Remove(filepath.Join(m.transferDir, token))
	}
}

func (m *Manager) SweepTransfers(olderThan time.Duration) error {
	entries, err := os.ReadDir(m.transferDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-olderThan)
	for _, entry := range entries {
		if !(uploadTokenRE.MatchString(entry.Name()) || downloadTokenRE.MatchString(entry.Name())) {
			continue
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(m.transferDir, entry.Name()))
		}
	}
	return nil
}

func (m *Manager) auditResult(ctx context.Context, actor auth.SessionUser, site Site, action string, metadata any, result types.FileMutationResult, operationErr error) error {
	if operationErr != nil {
		return classifyAgentError(operationErr)
	}
	if err := m.store.RecordAudit(ctx, actor, site, action, metadata); err != nil {
		return err
	}
	return nil
}

func classifyAgentError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "no such file"), strings.Contains(message, "not found"):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case strings.Contains(message, "conflict"), strings.Contains(message, "already exists"), strings.Contains(message, "changed since"):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	case strings.Contains(message, "permission denied"), strings.Contains(message, "operation not permitted"), strings.Contains(message, "forbidden"):
		return fmt.Errorf("%w: %v", ErrForbidden, err)
	case strings.Contains(message, "too large"), strings.Contains(message, "exceeds limit"), strings.Contains(message, "exceeds the"):
		return fmt.Errorf("%w: %v", ErrTooLarge, err)
	case strings.Contains(message, "not configured"), strings.Contains(message, "dial agent"):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	case strings.Contains(message, "invalid"), strings.Contains(message, "required"), strings.Contains(message, "unsafe"), strings.Contains(message, "unsupported"):
		return fmt.Errorf("%w: %v", ErrValidation, err)
	default:
		return err
	}
}

type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

func (s *SQLStore) GetSite(ctx context.Context, id int64) (Site, error) {
	var site Site
	err := s.db.QueryRowContext(ctx, `SELECT id,username,domain,status,COALESCE(customer_id,0),COALESCE(subscription_id,0) FROM sites WHERE id=$1`, id).Scan(
		&site.ID, &site.Username, &site.Domain, &site.Status, &site.CustomerID, &site.SubscriptionID,
	)
	return site, err
}

func (s *SQLStore) RecordAudit(ctx context.Context, actor auth.SessionUser, site Site, action string, metadata any) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata) VALUES($1,NULLIF($2,0),NULLIF($3,0),$4,'site',$5,$6::jsonb)`, actor.ID, site.CustomerID, site.SubscriptionID, action, site.ID, payload)
	return err
}

func newUploadToken() (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return "upload-" + hex.EncodeToString(data[:]), nil
}

func copyContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, err := dst.Write(buffer[:n])
			total += int64(written)
			if err != nil {
				return total, err
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
