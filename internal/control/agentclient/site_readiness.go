package agentclient

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (c *Client) InspectSiteReadiness(ctx context.Context, req types.InspectSiteReadinessReq) (types.SiteReadinessResult, error) {
	var result types.SiteReadinessResult
	err := c.doResult(ctx, types.OpInspectSiteReadiness, req, &result)
	return result, err
}
