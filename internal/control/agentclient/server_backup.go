package agentclient

import (
	"context"

	"github.com/nakroteck/nakpanel/internal/types"
)

func (c *Client) CreateServerBackup(ctx context.Context, req types.CreateServerBackupReq) (types.CreateServerBackupResult, error) {
	var result types.CreateServerBackupResult
	// The operation ID is durable across River retries; reusing it as the RPC
	// ID lets the agent replay a cached outcome instead of re-archiving.
	if req.OperationID != "" {
		return result, c.doResultWithID(ctx, types.OpCreateServerBackup, req.OperationID, req, &result)
	}
	return result, c.doResult(ctx, types.OpCreateServerBackup, req, &result)
}

func (c *Client) VerifyServerBackup(ctx context.Context, req types.VerifyServerBackupReq) (types.VerifyServerBackupResult, error) {
	var result types.VerifyServerBackupResult
	return result, c.doResult(ctx, types.OpVerifyServerBackup, req, &result)
}

func (c *Client) PruneServerBackups(ctx context.Context, req types.PruneServerBackupsReq) (types.PruneServerBackupsResult, error) {
	var result types.PruneServerBackupsResult
	return result, c.doResult(ctx, types.OpPruneServerBackups, req, &result)
}

func (c *Client) TestBackupDestination(ctx context.Context, req types.TestBackupDestinationReq) (types.TestBackupDestinationResult, error) {
	var result types.TestBackupDestinationResult
	return result, c.doResult(ctx, types.OpTestBackupDestination, req, &result)
}
