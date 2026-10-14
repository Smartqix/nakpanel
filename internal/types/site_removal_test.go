package types

import (
	"encoding/json"
	"testing"
)

func TestSiteRemovalDefaultsRetainDatabasesAndBackups(t *testing.T) {
	var req RemoveSiteReq
	if err := json.Unmarshal([]byte(`{"site_id":7}`), &req); err != nil {
		t.Fatal(err)
	}
	if len(req.DeleteDatabaseIDs) != 0 {
		t.Fatal("database removal enabled by default")
	}
	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["delete_backups"]; ok {
		t.Fatal("backup deletion is exposed")
	}
}

func TestSiteRemovalSnapshotStableDigest(t *testing.T) {
	left := SiteRemovalSnapshot{SchemaVersion: 1, Sites: []SiteRemovalSite{{SiteID: 2, Domain: "b.test"}, {SiteID: 1, Domain: "a.test"}}}
	right := SiteRemovalSnapshot{SchemaVersion: 1, Sites: []SiteRemovalSite{{SiteID: 1, Domain: "a.test"}, {SiteID: 2, Domain: "b.test"}}}
	if left.Digest() != right.Digest() {
		t.Fatal("inventory order changed approval")
	}
	right.Sites[0].Domain = "replacement.test"
	if left.Digest() == right.Digest() {
		t.Fatal("changed identity retained approval")
	}
}

func TestSiteRemovalSharedSecretBindingDigest(t *testing.T) {
	left := SiteRemovalSnapshot{SchemaVersion: 1, Resources: []SiteRemovalResource{{Kind: "application_secret", ID: 4, Name: "FIRST"}, {Kind: "application_secret", ID: 4, Name: "SECOND"}}}
	right := SiteRemovalSnapshot{SchemaVersion: 1, Resources: []SiteRemovalResource{{Kind: "application_secret", ID: 4, Name: "SECOND"}, {Kind: "application_secret", ID: 4, Name: "FIRST"}}}
	if left.Digest() != right.Digest() {
		t.Fatal("shared-secret binding order changed approval")
	}
}
