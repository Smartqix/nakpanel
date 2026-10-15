package dnstemplate

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
)

func dnsFixture(t *testing.T) (*sql.DB, *Manager) {
	t.Helper()
	db := removaldb.New(t, "")
	driver := riverdatabasesql.New(db)
	m, err := rivermigrate.New(driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Migrate(context.Background(), rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	client, err := river.NewClient(driver, &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return db, NewManager(db, client)
}

func TestStalePreviewLeavesZone(t *testing.T) {
	db, manager := dnsFixture(t)
	ctx := context.Background()
	preview, err := manager.Preview(ctx, 1, "all", 0)
	if err != nil {
		t.Fatal(err)
	}
	view, err := manager.View(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.SaveSettings(ctx, 1, types.DNSTemplateSettingsInput{ExpectedRevision: view.Template.OptimisticRevision, SOA: view.Template.SOA, ZoneStatus: "active", SubdomainPolicy: "parent"})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.ApplyPreview(ctx, 1, preview.ID, preview.PreviewToken, "APPLY DNS TEMPLATE"); !errors.Is(err, ErrStalePreview) {
		t.Fatalf("stale apply: %v", err)
	}
	var jobs int
	if err = db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='sync_dns_template'`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("stale preview queued a mutation: %d %v", jobs, err)
	}
}
