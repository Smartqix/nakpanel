package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (SHA-1 rows). The reference secret is the
// ASCII bytes "12345678901234567890"; the vectors list 8-digit codes, so the
// expected 6-digit values are their trailing six digits.
func TestTOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, vector := range vectors {
		step := TOTPStep(time.Unix(vector.unix, 0).UTC())
		if got := TOTPCode(secret, step); got != vector.code {
			t.Fatalf("TOTP(%d) = %s, want %s", vector.unix, got, vector.code)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	current := TOTPStep(now)

	// Codes for the current, previous, and next step are all accepted.
	for _, step := range []int64{current, current - 1, current + 1} {
		accepted, ok := VerifyTOTP(secret, TOTPCode(secret, step), now, 0)
		if !ok || accepted != step {
			t.Fatalf("step %d not accepted (got %d, %t)", step, accepted, ok)
		}
	}
	// Two steps of skew are rejected.
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, current-2), now, 0); ok {
		t.Fatal("accepted a code two steps old")
	}
	// Replay: a code at or before the last used step is rejected.
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, current), now, current); ok {
		t.Fatal("accepted a replayed code")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("accepted a short code")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("generated %d codes", len(codes))
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != 11 || code[5] != '-' {
			t.Fatalf("unexpected code format %q", code)
		}
		if seen[code] {
			t.Fatal("duplicate recovery code")
		}
		seen[code] = true
	}
	if NormalizeRecoveryCode(" ab cde-fghjk ") != "ABCDE-FGHJK" {
		t.Fatal("normalize failed")
	}
}

func TestOTPAuthURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	uri := OTPAuthURI("nakpanel", "admin@nakpanel.test", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/nakpanel:admin@nakpanel.test?") {
		t.Fatalf("unexpected uri %s", uri)
	}
	if !strings.Contains(uri, "issuer=nakpanel") || !strings.Contains(uri, "digits=6") {
		t.Fatalf("uri missing parameters: %s", uri)
	}
	if !strings.Contains(FormatTOTPSecret(secret), " ") {
		t.Fatal("formatted secret is not grouped")
	}
}
