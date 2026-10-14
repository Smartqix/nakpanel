package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositorySyncExportsSourcesWithoutIgnoredPrivateState(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{".gitignore": ".superpowers/\nbin/\n.env\n", "tracked.go": "package fixture\n", "new.go": "package fixture\n", ".env": "private", ".superpowers/private": "private"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", ".gitignore", "tracked.go"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %s: %v", out, err)
		}
	}
	common, err := filepath.Abs("common.sh")
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "captured.tar")
	cmd := exec.Command("bash", "-se", "--", common, root, archive)
	cmd.Stdin = strings.NewReader(`source "$1"
capture="$3"
multipass_exec_short(){ return 0; }
multipass(){ if [[ "$1" == transfer ]]; then cp "$2" "${capture}"; fi; }
wait_for_repo_sync(){ return 0; }
sync_repo "$2"
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sync: %s: %v", out, err)
	}
	out, err := exec.Command("tar", "-tf", archive).CombinedOutput()
	if err != nil {
		t.Fatalf("archive: %s: %v", out, err)
	}
	files := string(out)
	for _, want := range []string{"tracked.go", "new.go", ".gitignore"} {
		if !strings.Contains(files, want) {
			t.Errorf("missing %s: %s", want, files)
		}
	}
	for _, forbidden := range []string{".superpowers", ".env", ".git/"} {
		if strings.Contains(files, forbidden) {
			t.Errorf("private state included: %s", files)
		}
	}
}
