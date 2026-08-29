package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RFC 6238 TOTP (SHA-1, 6 digits, 30-second step) implemented on the
// standard library, matching every mainstream authenticator app's defaults.

const (
	// TOTPSecretSize follows RFC 4226's recommended 160-bit shared secret.
	TOTPSecretSize = 20
	totpDigits     = 6
	// TOTPStepSeconds is the RFC 6238 time step.
	TOTPStepSeconds = 30
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh random shared secret.
func GenerateTOTPSecret() ([]byte, error) {
	secret := make([]byte, TOTPSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// TOTPStep converts a wall-clock time to its RFC 6238 counter value.
func TOTPStep(now time.Time) int64 {
	return now.Unix() / TOTPStepSeconds
}

// TOTPCode computes the 6-digit code for one counter step.
func TOTPCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// VerifyTOTP checks a submitted code against the current step and its
// immediate neighbors (clock skew tolerance of one step in each direction).
// Replay is prevented by only accepting steps later than lastUsedStep; the
// accepted step is returned so the caller persists it.
func VerifyTOTP(secret []byte, code string, now time.Time, lastUsedStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	current := TOTPStep(now)
	for _, step := range []int64{current, current - 1, current + 1} {
		if step <= lastUsedStep {
			continue
		}
		expected := TOTPCode(secret, step)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// FormatTOTPSecret renders the secret for manual entry, grouped in fours.
func FormatTOTPSecret(secret []byte) string {
	encoded := totpEncoding.EncodeToString(secret)
	var groups []string
	for len(encoded) > 4 {
		groups = append(groups, encoded[:4])
		encoded = encoded[4:]
	}
	groups = append(groups, encoded)
	return strings.Join(groups, " ")
}

// OTPAuthURI builds the otpauth:// enrollment URI encoded into the QR code.
func OTPAuthURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	values := url.Values{}
	values.Set("secret", totpEncoding.EncodeToString(secret))
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", "6")
	values.Set("period", "30")
	return "otpauth://totp/" + label + "?" + values.Encode()
}

// Recovery codes: ten single-use codes in the form XXXXX-XXXXX from an
// unambiguous alphabet, stored argon2id-hashed like passwords.

const (
	RecoveryCodeCount    = 10
	recoveryCodeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ0123456789"
	recoveryCodeHalf     = 5
)

// GenerateRecoveryCodes returns freshly random plain-text codes; callers hash
// them immediately and show them to the user exactly once.
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count <= 0 {
		count = RecoveryCodeCount
	}
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw := make([]byte, recoveryCodeHalf*2)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		var b strings.Builder
		for j, value := range raw {
			if j == recoveryCodeHalf {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryCodeAlphabet[int(value)%len(recoveryCodeAlphabet)])
		}
		codes = append(codes, b.String())
	}
	return codes, nil
}

// NormalizeRecoveryCode canonicalizes user input before hashing/verifying.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	return strings.ReplaceAll(code, " ", "")
}
