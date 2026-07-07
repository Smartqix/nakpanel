package types

import (
	"encoding/json"
	"testing"
)

func TestReloadServiceRequestJSON(t *testing.T) {
	encoded, err := json.Marshal(ReloadServiceReq{Name: "nginx"})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if string(encoded) != `{"name":"nginx"}` {
		t.Fatalf("encoded = %s", encoded)
	}
}
