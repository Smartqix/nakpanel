package provision

import (
	"context"
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"reflect"
	"testing"
)

func TestSiteRemovalArgsContainOnlyIDs(t *testing.T) {
	args := RemoveSiteArgs{OperationID: 10, Revision: 2}
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]int64
	if err = json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fields, map[string]int64{"operation_id": 10, "revision": 2}) {
		t.Fatalf("args=%s", data)
	}
	opts := args.InsertOpts()
	if opts.Queue != quota.HeavyQueue || opts.MaxAttempts != 3 || !opts.UniqueOpts.ByArgs || len(opts.UniqueOpts.ByState) != 5 {
		t.Fatalf("unsafe enqueue options=%#v", opts)
	}
}
func TestSiteRemovalUnconfiguredFailsClosed(t *testing.T) {
	manager := new(Manager)
	ctx := context.Background()
	actor := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}
	if _, err := manager.RemoveSiteFor(ctx, actor, types.RemoveSiteReq{}); err == nil {
		t.Fatal("unconfigured removal allowed")
	}
	if _, err := manager.SiteRemovalFor(ctx, actor, 1); err == nil {
		t.Fatal("unconfigured history allowed")
	}
	if _, err := manager.RetrySiteRemovalFor(ctx, actor, 1); err == nil {
		t.Fatal("unconfigured retry allowed")
	}
}
