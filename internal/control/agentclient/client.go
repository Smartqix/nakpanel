package agentclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

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

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return types.Response{}, fmt.Errorf("write agent request: %w", err)
	}

	var resp types.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return types.Response{}, fmt.Errorf("read agent response: %w", err)
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

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
