package ops

import (
	"slices"
	"testing"
)

func TestServerBackupTreesIncludeNginxPolicyZones(t *testing.T) {
	if !slices.Contains(serverBackupTrees, "/etc/nginx/conf.d") {
		t.Fatal("server backup omits nginx policy-zone definitions required by restored vhosts")
	}
}
