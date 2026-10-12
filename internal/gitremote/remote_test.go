package gitremote

import "testing"

func TestNormalize(t *testing.T) {
	for _, raw := range []string{"git@github.com:org/repo.git", "ssh://git@github.com/org/repo.git", "https://github.com/org/repo.git"} {
		if _, err := Normalize(raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{"ssh://git:password@github.com/org/repo", "https://token@github.com/repo", "file:///tmp/repo", "ext::command", "ssh://-x@github.com/repo", "ssh://127.0.0.1/repo", "https://169.254.169.254/repo", "https://example.com/repo?token=secret", "git@github.com:repo\ncommand"} {
		if _, err := Normalize(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
