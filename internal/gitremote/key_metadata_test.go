package gitremote

import (
	"strings"
	"testing"
)

func TestKeyTitle(t *testing.T) {
	for _, remote := range []string{"git@github.com:team/website.git", "ssh://git@github.com/team/website.git"} {
		if got := KeyTitle("kofik.com", remote, 58); got != "Nakpanel - kofik.com - website - site-58" {
			t.Fatal(got)
		}
	}
	if strings.ContainsAny(KeyTitle("example.test", "bad\ninput", 1), "\r\n") {
		t.Fatal("unsafe title")
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	if PublicKeyFingerprint("") != "" {
		t.Fatal("empty key")
	}
	a := PublicKeyFingerprint("ssh-ed25519 YWJj old-comment")
	if a == "" || a != PublicKeyFingerprint("ssh-ed25519 YWJj new-comment") {
		t.Fatal("comment affects fingerprint")
	}
}
