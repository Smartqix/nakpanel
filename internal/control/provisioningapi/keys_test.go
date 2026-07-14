package provisioningapi

import (
	"crypto/subtle"
	"testing"
	"time"
)

func TestGenerateAPIKeyStoresOnlySaltedDigest(t *testing.T) {
	generated, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Raw) < 50 || generated.Prefix == "" {
		t.Fatalf("generated key is too short: %#v", generated)
	}
	if string(generated.Hash) == generated.Raw || len(generated.Hash) != 32 || len(generated.Salt) < 16 {
		t.Fatal("raw key must not be persisted as its digest or salt")
	}
	parsedPrefix, err := APIKeyPrefix(generated.Raw)
	if err != nil || parsedPrefix != generated.Prefix {
		t.Fatalf("parse prefix: %q, %v", parsedPrefix, err)
	}
	want := HashAPIKey(generated.Raw, generated.Salt)
	if subtle.ConstantTimeCompare(want, generated.Hash) != 1 {
		t.Fatal("generated digest cannot authenticate its raw key")
	}
}

func TestAPIKeyPrefixRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "abc", "npk_short_secret", "npk_bad prefix_secret", "Bearer npk_123456789012_secret"} {
		if _, err := APIKeyPrefix(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestAPIKeyUsability(t *testing.T) {
	now := time.Now()
	key := APIKey{Scope: ScopeProvisioning, ExpiresAt: now.Add(time.Minute)}
	if err := key.ValidateAt(now); err != nil {
		t.Fatal(err)
	}
	key.RevokedAt = now
	if err := key.ValidateAt(now); err != ErrAPIKeyRevoked {
		t.Fatalf("got %v", err)
	}
	key.RevokedAt = time.Time{}
	key.ExpiresAt = now.Add(-time.Second)
	if err := key.ValidateAt(now); err != ErrAPIKeyExpired {
		t.Fatalf("got %v", err)
	}
}
