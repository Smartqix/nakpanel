package gitremote

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// KeyTitle is a display label, never a filesystem path or authentication identity.
func KeyTitle(domain, remote string, siteID int64) string {
	name := "repository"
	if normalized, err := Normalize(remote); err == nil {
		if parsed, err := url.Parse(normalized); err == nil {
			name = strings.TrimSuffix(path.Base(parsed.Path), ".git")
		}
	}
	return "Nakpanel - " + strings.Join(strings.Fields(domain), " ") + " - " + strings.Join(strings.Fields(name), " ") + " - site-" + strconv.FormatInt(siteID, 10)
}

func PublicKeyFingerprint(key string) string {
	fields := strings.Fields(key)
	if len(fields) < 2 {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}
