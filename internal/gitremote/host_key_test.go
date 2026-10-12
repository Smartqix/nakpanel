package gitremote

import "testing"

func TestTrustedHostKeyExactProviderOnly(t *testing.T) {
	for _, remote := range []string{"git@github.com:team/repo.git", "ssh://git@github.com:22/team/repo.git"} {
		key := TrustedHostKey(remote)
		if PublicKeyFingerprint(key[len("github.com "):]) != "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU" {
			t.Fatal("incorrect GitHub pin")
		}
	}
	for _, remote := range []string{"git@github.com.evil.test:team/repo.git", "ssh://git@github.com:2222/team/repo.git", "https://github.com/team/repo.git", "git@example.test:team/repo.git"} {
		if TrustedHostKey(remote) != "" {
			t.Fatalf("trusted unknown host: %s", remote)
		}
	}
}
