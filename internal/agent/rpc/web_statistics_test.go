package rpc

import (
	"context"
	"encoding/json"
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

type fakeStatistics struct{ reads, generations, statuses int }

func (f *fakeStatistics) ReadWebStatistics(context.Context, types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	f.reads++
	return types.WebStatisticsResult{HTML: []byte("report")}, nil
}
func (f *fakeStatistics) GenerateWebStatistics(context.Context, types.WebStatisticsRequest) (types.WebStatisticsResult, error) {
	f.generations++
	return types.WebStatisticsResult{}, nil
}
func (f *fakeStatistics) WebStatisticsStatus(context.Context) (types.WebStatisticsStatus, error) {
	f.statuses++
	return types.WebStatisticsStatus{Available: true}, nil
}

func TestStatisticsReadBodiesAreNeverCached(t *testing.T) {
	fake := &fakeStatistics{}
	d := NewDispatcher(nil, Options{WebStatistics: fake})
	for _, op := range []string{types.OpReadWebStatistics, types.OpWebStatisticsStatus} {
		for i := 0; i < 2; i++ {
			if response := d.Dispatch(context.Background(), types.Request{ID: op, Op: op, Data: json.RawMessage(`{}`)}); !response.OK {
				t.Fatalf("%s: %s", op, response.Error)
			}
		}
	}
	if fake.reads != 2 || fake.statuses != 2 || len(d.responses) != 0 {
		t.Fatalf("read=%d status=%d cache=%d", fake.reads, fake.statuses, len(d.responses))
	}
	for i := 0; i < 2; i++ {
		d.Dispatch(context.Background(), types.Request{ID: "generation", Op: types.OpGenerateWebStatistics, Data: json.RawMessage(`{}`)})
	}
	if fake.generations != 1 || len(d.responses) != 1 {
		t.Fatalf("generation cache: calls=%d cache=%d", fake.generations, len(d.responses))
	}
}
