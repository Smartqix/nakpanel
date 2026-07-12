package agentclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

const maxResponseBytes = 4 << 20

type Client struct {
	socketPath string
	dialer     net.Dialer
}

func New(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		dialer: net.Dialer{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *Client) Do(ctx context.Context, req types.Request) (types.Response, error) {
	conn, err := c.dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return types.Response{}, fmt.Errorf("dial agent socket: %w", err)
	}
	defer conn.Close()
	cancelWatch := make(chan struct{})
	defer close(cancelWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-cancelWatch:
		}
	}()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return types.Response{}, fmt.Errorf("write agent request: %w", err)
	}

	limited := &io.LimitedReader{R: conn, N: maxResponseBytes + 1}
	payload, err := io.ReadAll(limited)
	if err != nil {
		if ctx.Err() != nil {
			return types.Response{}, ctx.Err()
		}
		return types.Response{}, fmt.Errorf("read agent response: %w", err)
	}
	if len(payload) > maxResponseBytes {
		return types.Response{}, errors.New("read agent response: response too large")
	}
	var resp types.Response
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resp); err != nil {
		return types.Response{}, fmt.Errorf("read agent response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return types.Response{}, errors.New("read agent response: multiple json values")
	}
	return resp, nil
}

func (c *Client) Ping(ctx context.Context) (types.Response, error) {
	return c.Do(ctx, types.Request{
		Op:   types.OpPing,
		ID:   newID(),
		Data: json.RawMessage(`{}`),
	})
}

func (c *Client) ReloadService(ctx context.Context, service string) (types.Response, error) {
	data, err := json.Marshal(types.ReloadServiceReq{Name: service})
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal reload request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpReloadService,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) CreateSite(ctx context.Context, req types.CreateSiteReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal create site request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpCreateSite,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) CreateDatabase(ctx context.Context, req types.CreateDatabaseReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal create database request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpCreateDatabase,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) IssueCert(ctx context.Context, req types.IssueCertReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal issue cert request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpIssueCert,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) CreateBackup(ctx context.Context, req types.CreateBackupReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal create backup request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpCreateBackup,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) RestoreBackup(ctx context.Context, req types.RestoreBackupReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal restore backup request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpRestoreBackup,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) ConfigureWebmail(ctx context.Context, req types.ConfigureWebmailReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal configure webmail request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpConfigureWebmail,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) ConfigureDNSZone(ctx context.Context, req types.ConfigureDNSZoneReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal configure dns zone request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpConfigureDNSZone,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) ReconcileSystem(ctx context.Context, req types.ReconcileSystemReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal reconcile system request: %w", err)
	}

	return c.Do(ctx, types.Request{
		Op:   types.OpReconcileSystem,
		ID:   newID(),
		Data: data,
	})
}

func (c *Client) SetHostingState(ctx context.Context, req types.SetHostingStateReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal hosting state request: %w", err)
	}
	return c.Do(ctx, types.Request{Op: types.OpSetHostingState, ID: newID(), Data: data})
}

func (c *Client) CollectUsage(ctx context.Context, req types.CollectUsageReq) (types.CollectUsageResult, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.CollectUsageResult{}, fmt.Errorf("marshal usage request: %w", err)
	}
	resp, err := c.Do(ctx, types.Request{Op: types.OpCollectUsage, ID: newID(), Data: data})
	if err != nil {
		return types.CollectUsageResult{}, err
	}
	if !resp.OK {
		return types.CollectUsageResult{}, errors.New(resp.Error)
	}
	var result types.CollectUsageResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return types.CollectUsageResult{}, fmt.Errorf("decode usage response: %w", err)
	}
	return result, nil
}

func (c *Client) RuntimeCapabilities(ctx context.Context) (types.RuntimeCapabilities, error) {
	resp, err := c.Do(ctx, types.Request{Op: types.OpRuntimeCapabilities, ID: newID(), Data: json.RawMessage(`{}`)})
	if err != nil {
		return types.RuntimeCapabilities{}, err
	}
	if !resp.OK {
		return types.RuntimeCapabilities{}, errors.New(resp.Error)
	}
	var result types.RuntimeCapabilities
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return types.RuntimeCapabilities{}, fmt.Errorf("decode capabilities response: %w", err)
	}
	return result, nil
}

func (c *Client) ApplySiteRuntime(ctx context.Context, req types.ApplySiteRuntimeReq) (types.Response, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return types.Response{}, fmt.Errorf("marshal site runtime request: %w", err)
	}
	return c.Do(ctx, types.Request{Op: types.OpApplySiteRuntime, ID: newID(), Data: data})
}

func (c *Client) ListFiles(ctx context.Context, req types.FileListReq) (types.FileListResult, error) {
	var result types.FileListResult
	return result, c.doFileOp(ctx, types.OpListFiles, req, &result)
}

func (c *Client) SearchFiles(ctx context.Context, req types.FileSearchReq) (types.FileSearchResult, error) {
	var result types.FileSearchResult
	return result, c.doFileOp(ctx, types.OpSearchFiles, req, &result)
}

func (c *Client) ReadFile(ctx context.Context, req types.FileReadReq) (types.FileReadResult, error) {
	var result types.FileReadResult
	return result, c.doFileOp(ctx, types.OpReadFile, req, &result)
}

func (c *Client) WriteFile(ctx context.Context, req types.FileWriteReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpWriteFile, req, &result)
}

func (c *Client) CreateFileEntry(ctx context.Context, req types.FileCreateReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpCreateFileEntry, req, &result)
}

func (c *Client) CopyFiles(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpCopyFiles, req, &result)
}

func (c *Client) MoveFiles(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpMoveFiles, req, &result)
}

func (c *Client) DeleteFiles(ctx context.Context, req types.FileBatchReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpDeleteFiles, req, &result)
}

func (c *Client) ArchiveFiles(ctx context.Context, req types.FileArchiveReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpArchiveFiles, req, &result)
}

func (c *Client) ExtractArchive(ctx context.Context, req types.FileExtractReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpExtractArchive, req, &result)
}

func (c *Client) SetFileMode(ctx context.Context, req types.FileModeReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpSetFileMode, req, &result)
}

func (c *Client) ImportFileTransfer(ctx context.Context, req types.FileTransferImportReq) (types.FileMutationResult, error) {
	var result types.FileMutationResult
	return result, c.doFileOp(ctx, types.OpImportFileTransfer, req, &result)
}

func (c *Client) ExportFileTransfer(ctx context.Context, req types.FileTransferExportReq) (types.FileTransferResult, error) {
	var result types.FileTransferResult
	return result, c.doFileOp(ctx, types.OpExportFileTransfer, req, &result)
}

func (c *Client) doFileOp(ctx context.Context, op string, payload any, result any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s request: %w", op, err)
	}
	response, err := c.Do(ctx, types.Request{Op: op, ID: newID(), Data: data})
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New(response.Error)
	}
	if err := json.Unmarshal(response.Data, result); err != nil {
		return fmt.Errorf("decode %s response: %w", op, err)
	}
	return nil
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
