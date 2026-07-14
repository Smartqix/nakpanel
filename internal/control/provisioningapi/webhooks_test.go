package provisioningapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestWebhookConfigRejectsUnsafeEndpoints(t *testing.T) {
	for _, cfg := range []WebhookConfig{{URL: "http://billing.example.test/hook", Secret: "secret"}, {URL: "https://user:pass@example.test/hook", Secret: "secret"}, {URL: "https://example.test/hook"}, {Secret: "secret"}} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("unsafe webhook config accepted: %#v", cfg)
		}
	}
	for _, cfg := range []WebhookConfig{{}, {URL: "http://127.0.0.1:8080/hook", Secret: "secret"}, {URL: "https://billing.example.test/hook", Secret: "secret"}} {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid webhook config rejected: %#v: %v", cfg, err)
		}
	}
}

func TestWebhookSignatureCoversTimestampDotAndExactBody(t *testing.T) {
	body := []byte(`{"id":"acc_test","event":"account.provisioned"}`)
	timestamp := "1784037000"
	mac := hmac.New(sha256.New, []byte("top-secret"))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if got := SignWebhook("top-secret", timestamp, body); got != want {
		t.Fatalf("signature=%s want %s", got, want)
	}
	if SignWebhook("top-secret", timestamp, append(body, ' ')) == want {
		t.Fatal("signature ignored exact body bytes")
	}
}
