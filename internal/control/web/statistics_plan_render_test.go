package web

import (
	"bytes"
	"context"
	"github.com/nakroteck/nakpanel/internal/types"
	"strings"
	"testing"
)

func TestStatisticsEngineSelectorPreservesLegacyValue(t *testing.T) {
	var output bytes.Buffer
	if err := statisticsEngineSelect(types.LogsPreset{StatisticsEnabled: true}).Render(context.Background(), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `value="goaccess" selected`) || !strings.Contains(output.String(), `name="logs_statistics_engine"`) {
		t.Fatalf("legacy engine not selected: %s", output.String())
	}
}
