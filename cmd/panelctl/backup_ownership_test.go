package main

import (
	"context"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestRestoreAdoptsOnlyAuthenticatedImportedDatabaseInventory(t *testing.T) {
	targets := []types.DatabaseAdminTarget{{DatabaseID: 7, Name: "restored_db", Principal: "restored_user"}, {DatabaseID: 8, Name: "other_db", Principal: "other_user"}}
	var adopted []types.DatabaseAdminTarget
	adopt := func(_ context.Context, target types.DatabaseAdminTarget) error {
		adopted = append(adopted, target)
		return nil
	}
	if err := adoptImportedDatabaseOwnership(context.Background(), []string{"restored_db"}, targets, adopt); err != nil {
		t.Fatal(err)
	}
	if len(adopted) != 1 || adopted[0] != targets[0] {
		t.Fatal("restore adopted a target not imported from archive")
	}
	for _, names := range [][]string{{"missing_db"}, {"restored_db", "restored_db"}} {
		adopted = nil
		if err := adoptImportedDatabaseOwnership(context.Background(), names, targets, adopt); err == nil {
			t.Fatal("invalid import mapping accepted")
		}
		if len(adopted) != 0 {
			t.Fatal("invalid inventory caused partial adoption")
		}
	}
}
