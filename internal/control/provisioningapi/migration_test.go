package provisioningapi

import (
	"os"
	"strings"
	"testing"
)

func TestPhase20MigrationContainsProvisioningSecurityBoundaries(t *testing.T) {
	payload, err := os.ReadFile("../../../migrations/20260714000022_phase20_provisioning_api.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration := string(payload)
	for _, want := range []string{"CREATE TABLE api_keys", "key_salt BYTEA", "key_hash BYTEA", "ip_allowlist CIDR[]", "CREATE TABLE billing_accounts", "external_ref TEXT NOT NULL UNIQUE", "CREATE TABLE api_idempotency_records", "CREATE TABLE customer_login_tokens", "token_hash BYTEA NOT NULL UNIQUE", "CREATE TABLE billing_webhook_outbox", "plans_api_slug_immutable", "plans_assign_api_slug"} {
		if !strings.Contains(migration, want) {
			t.Errorf("migration missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(migration), "raw_key") {
		t.Fatal("migration must never persist the raw API key")
	}
}
