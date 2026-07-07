package types

import (
	"encoding/json"
	"testing"
)

func TestCreateSiteRequestCarriesServerDerivedResourceLimits(t *testing.T) {
	req := CreateSiteReq{
		Username:   "npdemo",
		Domain:     "example.test",
		PHPVersion: "8.3",
		Limits: SiteResourceLimits{
			DiskQuotaMB:       1024,
			PHPFPMMaxChildren: 3,
			PHPMemoryMB:       128,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	for _, want := range []string{`"disk_quota_mb":1024`, `"php_max_children":3`, `"php_memory_mb":128`} {
		if !json.Valid(data) || !containsJSONField(string(data), want) {
			t.Fatalf("CreateSiteReq JSON = %s, missing %s", data, want)
		}
	}

	var decoded CreateSiteReq
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if decoded.Limits.DiskQuotaMB != 1024 || decoded.Limits.PHPFPMMaxChildren != 3 || decoded.Limits.PHPMemoryMB != 128 {
		t.Fatalf("decoded resource limits = %#v", decoded.Limits)
	}
}

func containsJSONField(data string, field string) bool {
	return len(data) >= len(field) && jsonContains(data, field)
}

func jsonContains(data string, field string) bool {
	for i := 0; i+len(field) <= len(data); i++ {
		if data[i:i+len(field)] == field {
			return true
		}
	}
	return false
}
