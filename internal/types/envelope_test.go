package types

import (
	"encoding/json"
	"testing"
)

func TestRequestEnvelopeRoundTrip(t *testing.T) {
	payload := CreateSiteReq{
		Username:   "client01",
		Domain:     "example.com",
		PHPVersion: "8.3",
		Docroot:    "/home/client01/public_html",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := Request{
		Op:   OpCreateSite,
		ID:   "01J00000000000000000000000",
		Data: data,
	}

	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var decoded Request
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	if decoded.Op != OpCreateSite {
		t.Fatalf("Op = %q, want %q", decoded.Op, OpCreateSite)
	}
	if decoded.ID != req.ID {
		t.Fatalf("ID = %q, want %q", decoded.ID, req.ID)
	}

	var decodedPayload CreateSiteReq
	if err := json.Unmarshal(decoded.Data, &decodedPayload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if decodedPayload != payload {
		t.Fatalf("payload = %#v, want %#v", decodedPayload, payload)
	}
}

func TestAgentVocabularyConstants(t *testing.T) {
	want := map[string]string{
		"ping":               OpPing,
		"reload_service":     OpReloadService,
		"create_system_user": OpCreateSystemUser,
		"create_site":        OpCreateSite,
		"issue_cert":         OpIssueCert,
		"create_database":    OpCreateDatabase,
	}

	for value, got := range want {
		if got != value {
			t.Fatalf("op constant = %q, want %q", got, value)
		}
	}
}

func TestDatabaseEngineConstants(t *testing.T) {
	if EngineMariaDB != "mariadb" {
		t.Fatalf("EngineMariaDB = %q, want mariadb", EngineMariaDB)
	}
	if EngineMySQL != "mysql" {
		t.Fatalf("EngineMySQL = %q, want mysql", EngineMySQL)
	}
	if EnginePgSQL != "pgsql" {
		t.Fatalf("EnginePgSQL = %q, want pgsql", EnginePgSQL)
	}
}
