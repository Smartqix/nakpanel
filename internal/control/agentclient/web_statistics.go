package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (c *Client) statisticsCall(ctx context.Context, op string, req any, result any) error {
	response, err := c.doTyped(ctx, op, req)
	if err != nil {
		return err
	}
	if !response.OK {
		return errors.New("web statistics agent operation failed")
	}
	return json.Unmarshal(response.Data, result)
}
func (c *Client) GenerateWebStatistics(ctx context.Context, req types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	var result types.WebStatisticsResult
	err := c.statisticsCall(ctx, types.OpGenerateWebStatistics, req, &result)
	return result, err
}
func (c *Client) ReadWebStatistics(ctx context.Context, req types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	var result types.WebStatisticsResult
	err := c.statisticsCall(ctx, types.OpReadWebStatistics, req, &result)
	return result, err
}
func (c *Client) WebStatisticsStatus(ctx context.Context) (types.WebStatisticsStatus, error) {
	var result types.WebStatisticsStatus
	err := c.statisticsCall(ctx, types.OpWebStatisticsStatus, struct{}{}, &result)
	return result, err
}
