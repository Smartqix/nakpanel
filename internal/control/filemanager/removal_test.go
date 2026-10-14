package filemanager

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
)

func TestSiteRemovalBlocksNewDirectFileOperations(t *testing.T) {
	db := removaldb.New(t, "")
	removaldb.Site(t, db, 1, "primary.test", nil)
	id := removaldb.Site(t, db, 1, "addon.test", nil)
	store := NewSQLStore(db)
	if _, err := store.GetSite(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sites SET removal_state='queued' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSite(context.Background(), id); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("new file request can enter a reserved removal", err)
	}
}
