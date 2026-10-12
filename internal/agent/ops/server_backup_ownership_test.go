package ops

import (
	"slices"
	"testing"
)

func TestServerBackupIncludesPrivateDatabaseOwnershipParent(t *testing.T) {
	if !slices.Contains(serverBackupTrees, "/var/lib/nakpanel-agent") {
		t.Fatal("server backup omits root-owned database retry markers or their private parent permissions")
	}
}
