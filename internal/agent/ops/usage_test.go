package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestUsageCollectorMeasuresHomeAndIncrementalNginxTraffic(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeRoot, "acct", "index.html"), []byte("123456"), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	first := `127.0.0.1 - - [10/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	period := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	result, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Sites) != 1 || result.Sites[0].HomeBytes != 6 || result.Sites[0].TrafficBytes != 120 {
		t.Fatalf("usage result = %#v", result)
	}
	second := `127.0.0.1 - - [10/Jul/2026:12:01:00 +0000] "GET /a HTTP/1.1" 200 80 "-" "curl"` + "\n"
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString(second)
	_ = file.Close()
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	third := `127.0.0.1 - - [10/Jul/2026:12:02:00 +0000] "GET /b HTTP/1.1" 200 30 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(third), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err = collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath), Cursor: result.Sites[0].Cursor}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Sites[0].TrafficBytes; got != 110 {
		t.Fatalf("traffic delta = %d, want 110", got)
	}
}

func TestUsageCollectorMonthlyResetIgnoresPriorLogEntries(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	log := `127.0.0.1 - - [30/Jun/2026:23:59:59 +0000] "GET /old HTTP/1.1" 200 900 "-" "curl"` + "\n" +
		`127.0.0.1 - - [01/Jul/2026:00:00:01 +0000] "GET /new HTTP/1.1" 200 100 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	result, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{
		Sites:       []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}},
		PeriodStart: time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Sites[0].TrafficBytes; got != 100 {
		t.Fatalf("July traffic = %d, want 100", got)
	}
}

func TestUsageCollectorDoesNotAdvancePastPartialLogLine(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	complete := `127.0.0.1 - - [10/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "curl"` + "\n"
	partial := `127.0.0.1 - - [10/Jul/2026:12:01:00 +0000] "GET /partial HTTP/1.1" 200 80 "-" "curl"`
	if err := os.WriteFile(logPath, []byte(complete+partial), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	period := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	first, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Sites[0].TrafficBytes; got != 120 {
		t.Fatalf("first traffic = %d, want 120", got)
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("\n")
	_ = file.Close()
	second, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath), Cursor: first.Sites[0].Cursor}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Sites[0].TrafficBytes; got != 80 {
		t.Fatalf("completed partial traffic = %d, want 80", got)
	}
}

func TestUsageCollectorRejectsUnrecoverableLogRotation(t *testing.T) {
	root := t.TempDir()
	homeRoot := filepath.Join(root, "home")
	logRoot := filepath.Join(root, "logs")
	if err := os.MkdirAll(filepath.Join(homeRoot, "acct"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(logRoot, "acct-example-test.access.log")
	line := `127.0.0.1 - - [10/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "curl"` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	collector := NewUsageCollector(homeRoot, logRoot, "")
	period := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	first, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath)}}, PeriodStart: period})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: filepath.Base(logPath), Cursor: first.Sites[0].Cursor}}, PeriodStart: period})
	if err == nil || !strings.Contains(err.Error(), "cursor gap") {
		t.Fatalf("CollectUsage error = %v, want cursor gap", err)
	}
}

func TestUsageCollectorRejectsLogOutsideManagedRoot(t *testing.T) {
	collector := NewUsageCollector(t.TempDir(), t.TempDir(), "")
	_, err := collector.CollectUsage(context.Background(), types.CollectUsageReq{Sites: []types.SiteUsageInput{{SiteID: 1, Username: "acct", AccessLog: "/tmp/outside.log"}}})
	if err == nil {
		t.Fatal("CollectUsage returned nil error")
	}
}
