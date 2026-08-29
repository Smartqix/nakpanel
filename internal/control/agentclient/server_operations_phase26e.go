package agentclient

import (
	"context"

	"github.com/nakroteck/nakpanel/internal/types"
)

func (c *Client) ApplyUpdates(ctx context.Context, req types.ApplyUpdatesReq) (types.UpdateState, error) {
	var result types.UpdateState
	err := c.doResultWithID(ctx, types.OpApplyUpdates, req.OperationID, req, &result)
	return result, err
}

func (c *Client) ControlHostPower(ctx context.Context, req types.HostPowerReq) (types.HostPowerResult, error) {
	var result types.HostPowerResult
	err := c.doResultWithID(ctx, types.OpControlHostPower, req.OperationID, req, &result)
	return result, err
}
