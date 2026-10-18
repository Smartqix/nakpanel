package main

import "testing"

func TestRuntimeRemovalInternalVersionUsesInstalledPlatform(t *testing.T) {
	for _, tc := range []struct{ data, want string }{
		{`{"os_id":"ubuntu","version_id":"24.04","profile":"ubuntu-24.04","internal_php_version":"8.3"}`, "8.3"},
		{`{"os_id":"ubuntu","version_id":"26.04","profile":"ubuntu-26.04-native","internal_php_version":"8.5"}`, "8.5"},
		{`{"os_id":"ubuntu","version_id":"26.04","profile":"ubuntu-26.04-sury","internal_php_version":"8.5"}`, "8.5"},
		{`{"os_id":"ubuntu","version_id":"26.04","profile":"ubuntu-26.04-native","internal_php_version":"8.3"}`, ""},
		{`{"os_id":"ubuntu","version_id":"26.04","profile":"ubuntu-26.04-native","internal_php_version":"8.5","bootstrap_pending":true}`, ""},
		{`{}`, ""},
	} {
		got, err := internalPHPFromProfile([]byte(tc.data))
		if tc.want == "" {
			if err == nil {
				t.Fatalf("unsafe mapping accepted: %s", tc.data)
			}
		} else if err != nil || got != tc.want {
			t.Fatalf("got %q %v want %q", got, err, tc.want)
		}
	}
}
func TestRuntimeRemovalMissingProfileProtectsLegacyInternalPHP(t *testing.T) {
	got, err := installedInternalPHPVersion(t.TempDir() + "/absent")
	if err != nil || got != "8.3" {
		t.Fatalf("got %q %v", got, err)
	}
}
