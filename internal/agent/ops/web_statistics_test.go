package ops

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func statisticsFixture(t *testing.T) (*WebStatisticsGenerator, types.WebStatisticsRequest, string) {
	t.Helper()
	g := NewWebStatisticsGenerator()
	g.logRoot = t.TempDir()
	g.reportRoot = filepath.Join(t.TempDir(), "reports")
	g.now = func() time.Time { return time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC) }
	req := types.WebStatisticsRequest{SiteID: 7, Domain: "example.test", Username: "example", Generation: 1, RetentionDays: 30, AnonymizeIP: true}
	path := filepath.Join(g.logRoot, "example-example-test.access.log")
	g.run = func(_ context.Context, input string, args ...string) error {
		if len(args) == 0 || args[len(args)-1] != "-" {
			t.Fatal("GoAccess requires explicit stdin marker")
		}
		for i, arg := range args {
			if arg == "-o" {
				data := []byte("<!doctype html><title>GoAccess</title>")
				if strings.HasSuffix(args[i+1], ".json") {
					data = []byte(`{"general":{"unique_visitors":1}}`)
				}
				if err := os.WriteFile(args[i+1], data, 0600); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return g, req, path
}

func TestWebStatisticsSanitizesSecretsBeforeGoAccess(t *testing.T) {
	g, req, path := statisticsFixture(t)
	line := `203.0.113.49 - bob [08/Sep/2026:11:00:00 +0000] "GET http://alice:password@example.test/shop?secret=hidden HTTP/1.1" 200 321 "https://refuser:refpass@search.test/find?token=hidden#secret" "Mozilla/5.0"` + "\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	var summary types.WebStatisticsSummary
	if err := g.sanitizedInput(context.Background(), req, &input, g.now().Add(-time.Hour*24), g.now(), &summary); err != nil {
		t.Fatal(err)
	}
	text := input.String()
	for _, secret := range []string{"203.0.113.49", "bob", "alice", "password", "refuser", "refpass", "token", "hidden", "?", "#"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q in sanitized input %s", secret, text)
		}
	}
	for _, expected := range []string{"203.0.113.0", "http://example.test/shop", "https://search.test/find", "Mozilla/5.0"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in %s", expected, text)
		}
	}
	if summary.Requests != 1 || summary.Bandwidth != 321 {
		t.Fatalf("summary %+v", summary)
	}
}

func TestWebStatisticsLastGoodAndRetry(t *testing.T) {
	g, req, path := statisticsFixture(t)
	if err := os.WriteFile(path, []byte(`203.0.113.49 - - [08/Sep/2026:11:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "agent"`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := g.GenerateWebStatistics(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Summary.Requests != 1 || first.Summary.Visitors != 1 {
		t.Fatalf("summary %+v", first.Summary)
	}
	if _, err = g.GenerateWebStatistics(context.Background(), req); err != nil {
		t.Fatalf("retry: %v", err)
	}
	run := g.run
	g.run = func(context.Context, string, ...string) error { return errors.New("private token should not escape") }
	failed := req
	failed.Generation = 2
	failed.RetainGeneration = 1
	if _, err = g.GenerateWebStatistics(context.Background(), failed); err == nil || strings.Contains(err.Error(), "token") {
		t.Fatalf("failure: %v", err)
	}
	if _, err = g.ReadWebStatistics(context.Background(), req); err != nil {
		t.Fatalf("lost last good: %v", err)
	}
	g.run = run
	next := failed
	next.Generation = 3
	if _, err = g.GenerateWebStatistics(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if _, err = g.ReadWebStatistics(context.Background(), req); err != nil {
		t.Fatalf("removed actual prior successful generation: %v", err)
	}
	changed := next
	changed.AnonymizeIP = false
	if _, err = g.ReadWebStatistics(context.Background(), changed); err == nil {
		t.Fatal("read report generated under different privacy settings")
	}
	next.Generation = 4
	next.RetainGeneration = 3
	if _, err = g.GenerateWebStatistics(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(g.reportPath(req)); !os.IsNotExist(err) {
		t.Fatal("old report not pruned")
	}
}

func TestWebStatisticsRotationsAndSafety(t *testing.T) {
	g, req, path := statisticsFixture(t)
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	_, _ = zip.Write([]byte(`2001:db8:abcd:1234::1 - - [08/Sep/2026:11:00:00 +0000] "GET /missing HTTP/1.1" 404 12 "-" "agent"` + "\n"))
	_ = zip.Close()
	if err := os.WriteFile(path+".2.gz", compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := g.GenerateWebStatistics(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Errors != 1 {
		t.Fatal("gzip rotation not included")
	}
	req.Generation = 2
	if err := os.Symlink(path+".2.gz", path); err != nil {
		t.Fatal(err)
	}
	if _, err = g.GenerateWebStatistics(context.Background(), req); err == nil {
		t.Fatal("symlink log accepted")
	}
	req.Domain = "../../etc/passwd"
	if _, err = g.GenerateWebStatistics(context.Background(), req); err == nil {
		t.Fatal("unsafe identity accepted")
	}
}

func TestWebStatisticsReportSizeBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(path, []byte("oversized"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStatisticsFile(path, 2); err == nil {
		t.Fatal("oversized report accepted")
	}
}

func TestWebStatisticsRejectsUnparseableNonemptyLog(t *testing.T) {
	g, req, path := statisticsFixture(t)
	if err := os.WriteFile(path, []byte("not a combined log record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.GenerateWebStatistics(context.Background(), req); err == nil {
		t.Fatal("unparseable logs produced a healthy empty report")
	}
}
