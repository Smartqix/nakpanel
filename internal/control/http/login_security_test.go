package panelhttp

import (
	"regexp"
	"strings"
	"testing"
)

// fail2banFailregex mirrors deploy/fail2ban/nakpanel-login.conf with <HOST>
// expanded. If these drift apart the jail silently stops matching.
var fail2banFailregex = regexp.MustCompile(`nakpanel-auth: login failed for "[^"]*" from (\S+)\s*$`)

// TestAuthFailureLineAlwaysMatchesFail2banFilter pins a one-character jail
// bypass: the email is attacker-controlled, and %q escapes an embedded quote
// as \", which made [^"]* stop early so the line never matched and the source
// IP was never banned.
func TestAuthFailureLineAlwaysMatchesFail2banFilter(t *testing.T) {
	hostile := []string{
		"victim@example.com",
		`a"b@example.com`,
		`" from 1.2.3.4` + "\n" + `nakpanel-auth: login failed for "x`,
		`back\slash@example.com`,
		strings.Repeat("a", 500) + "@example.com",
		"user with spaces@example.com",
		"\x00\x1b[31m@example.com",
	}
	for _, email := range hostile {
		line := "Aug 27 00:00:00 host nakpanel-auth: login failed for \"" +
			sanitizeLogField(email) + "\" from 203.0.113.5"
		if strings.Count(line, "\n") != 0 {
			t.Fatalf("sanitized line contains a newline for %q", email)
		}
		match := fail2banFailregex.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf("fail2ban filter does not match the line produced for %q:\n%s", email, line)
		}
		if match[1] != "203.0.113.5" {
			t.Fatalf("filter captured host %q (expected 203.0.113.5) for %q", match[1], email)
		}
	}
}

func TestSanitizeLogFieldKeepsOrdinaryEmailsIntact(t *testing.T) {
	for _, email := range []string{"admin@nakpanel.test", "first.last+tag@sub.example.co.uk", "a_b-c@x.io"} {
		if got := sanitizeLogField(email); got != email {
			t.Fatalf("sanitizeLogField(%q) = %q, want it unchanged", email, got)
		}
	}
}
