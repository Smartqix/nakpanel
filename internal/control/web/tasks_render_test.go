package web

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

func TestTasksTrayRendersEightJobsAndHiddenZeroBadge(t *testing.T) {
	data := dashboard.Data{}
	for id := int64(1); id <= 12; id++ {
		data.Jobs = append(data.Jobs, dashboard.Job{ID: id, Kind: "create_site", Target: "owned.test", State: "discarded", LastError: "<last failure>", CreatedAt: time.Now()})
	}
	render := func() string {
		var b bytes.Buffer
		if err := tasksTray(data).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	body := render()
	if strings.Count(body, "data-np-task-id=") != 8 || !strings.Contains(body, "Create site") || !strings.Contains(body, "&lt;last failure&gt;") || !strings.Contains(body, `aria-controls="np-tasks-panel"`) || !strings.Contains(body, `data-np-tasks-count hidden`) {
		t.Fatalf("tray: %s", body)
	}
	data.ActiveJobs = 12
	body = render()
	if strings.Contains(body, `data-np-tasks-count hidden`) || !strings.Contains(body, `data-np-tasks-count>12</span>`) {
		t.Fatalf("active badge: %s", body)
	}
	items := TaskItems(data.Jobs)
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"finalized_at":null`) {
		t.Fatalf("timestamps: %s", raw)
	}
}
