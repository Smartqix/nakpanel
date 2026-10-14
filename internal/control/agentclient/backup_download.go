package agentclient

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/nakroteck/nakpanel/internal/types"
)

func (c *Client) ReadBackupChunk(ctx context.Context, req types.ReadBackupChunkReq) (types.ReadBackupChunkResult, error) {
	var result types.ReadBackupChunkResult
	data, err := json.Marshal(req)
	if err != nil {
		return result, err
	}
	response, err := c.Do(ctx, types.Request{Op: types.OpReadBackupChunk, ID: newID(), Data: data})
	if err != nil {
		return result, err
	}
	if !response.OK {
		return result, errors.New("backup archive could not be read or verified")
	}
	err = json.Unmarshal(response.Data, &result)
	return result, err
}
