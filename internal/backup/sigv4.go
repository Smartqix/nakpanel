package backup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 request signing — the subset S3-compatible object
// stores require. Payload hashing supports both precomputed SHA-256 values
// and the streaming-friendly UNSIGNED-PAYLOAD sentinel.

const unsignedPayload = "UNSIGNED-PAYLOAD"

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// uriEncode implements the AWS canonical URI encoding: unreserved characters
// pass through, everything else is percent-encoded uppercase; "/" is kept
// when encodeSlash is false (canonical path).
func uriEncode(value string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteString("%")
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

func canonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		vals := append([]string(nil), values[key]...)
		sort.Strings(vals)
		for _, val := range vals {
			parts = append(parts, uriEncode(key, true)+"="+uriEncode(val, true))
		}
	}
	return strings.Join(parts, "&")
}

// signV4 signs req in place. payloadHash is the hex SHA-256 of the body or
// unsignedPayload for streaming bodies.
func signV4(req *http.Request, accessKey, secretKey, region, payloadHash string, now time.Time) {
	const service = "s3"
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	signedHeaderNames := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if req.Header.Get("Content-Type") != "" {
		signedHeaderNames = append(signedHeaderNames, "content-type")
	}
	if req.Header.Get("Range") != "" {
		signedHeaderNames = append(signedHeaderNames, "range")
	}
	sort.Strings(signedHeaderNames)

	var canonicalHeaders strings.Builder
	for _, name := range signedHeaderNames {
		var value string
		if name == "host" {
			value = req.Host
			if value == "" {
				value = req.URL.Host
			}
		} else {
			value = req.Header.Get(name)
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(value))
		canonicalHeaders.WriteString("\n")
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")

	canonicalPath := req.URL.EscapedPath()
	if canonicalPath == "" {
		canonicalPath = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath,
		canonicalQuery(req.URL.Query()),
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	signingKey = hmacSHA256(signingKey, []byte(region))
	signingKey = hmacSHA256(signingKey, []byte(service))
	signingKey = hmacSHA256(signingKey, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	req.Header.Set("Authorization", strings.Join([]string{
		"AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope,
		"SignedHeaders=" + signedHeaders,
		"Signature=" + signature,
	}, ", "))
}
