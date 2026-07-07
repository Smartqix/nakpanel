package types

import (
	"encoding/json"
	"testing"
)

func TestPhase6OpsAreEnumerated(t *testing.T) {
	for _, op := range []string{
		OpCreateBackup,
		OpConfigureWebmail,
		OpConfigureDNSZone,
		OpReconcileSystem,
	} {
		if op == "" {
			t.Fatalf("phase6 op is empty")
		}
	}
}

func TestPhase6PayloadsRoundTrip(t *testing.T) {
	backup := CreateBackupReq{
		Domain:    "example.test",
		Username:  "npdemo",
		Docroot:   "/home/npdemo/public_html",
		Databases: []string{"np_demo"},
		OutputDir: "/var/lib/nakpanel/backups",
	}
	raw, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("Marshal backup returned error: %v", err)
	}
	var decoded CreateBackupReq
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal backup returned error: %v", err)
	}
	if decoded.Domain != backup.Domain || decoded.Databases[0] != "np_demo" {
		t.Fatalf("decoded backup = %#v, want %#v", decoded, backup)
	}

	reconcile := ReconcileSystemReq{
		Sites: []ReconcileSiteReq{{
			Username:      "npdemo",
			Domain:        "example.test",
			PHPVersion:    "8.3",
			EnableWebmail: true,
			EnableDNS:     true,
			Address:       "192.0.2.10",
		}},
	}
	raw, err = json.Marshal(reconcile)
	if err != nil {
		t.Fatalf("Marshal reconcile returned error: %v", err)
	}
	var decodedReconcile ReconcileSystemReq
	if err := json.Unmarshal(raw, &decodedReconcile); err != nil {
		t.Fatalf("Unmarshal reconcile returned error: %v", err)
	}
	if len(decodedReconcile.Sites) != 1 || decodedReconcile.Sites[0].Domain != "example.test" {
		t.Fatalf("decoded reconcile = %#v, want one example.test site", decodedReconcile)
	}
}
