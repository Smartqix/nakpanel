package rpc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeWordPressProvisioner struct {
	requests []types.WordPressOperationReq
}

func (f *fakeWordPressProvisioner) RunWordPress(_ context.Context, req types.WordPressOperationReq) (types.WordPressOperationResult, error) {
	f.requests = append(f.requests, req)
	return types.WordPressOperationResult{Action: req.Action, Changed: true}, nil
}

func TestDispatchWordPressOperationIsEnumeratedAndStrict(t *testing.T) {
	provisioner := &fakeWordPressProvisioner{}
	dispatcher := NewDispatcher(nil, Options{WordPress: provisioner})
	payload, err := json.Marshal(types.WordPressOperationReq{
		Action: types.WordPressActionInspect,
		Site: types.WordPressSiteSpec{
			SiteID:      7,
			Username:    "npdemo",
			Domain:      "example.test",
			PHPVersion:  "8.4",
			HostingMode: types.PHPHostingModeClassic,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := dispatcher.Dispatch(context.Background(), types.Request{Op: types.OpRunWordPress, ID: "wp-good", Data: payload})
	if !response.OK || len(provisioner.requests) != 1 {
		t.Fatalf("dispatch = %+v, calls=%d", response, len(provisioner.requests))
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	raw["command"] = "sh -c id"
	bad, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	response = dispatcher.Dispatch(context.Background(), types.Request{Op: types.OpRunWordPress, ID: "wp-bad", Data: bad})
	if response.OK || len(provisioner.requests) != 1 {
		t.Fatalf("strict dispatch = %+v, calls=%d", response, len(provisioner.requests))
	}
}
