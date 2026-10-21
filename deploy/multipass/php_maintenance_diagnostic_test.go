package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPHPPackageDiagnosticRefusesNonHostedMachinesBeforeAnyCommand(t *testing.T) {
	path, err := filepath.Abs("php-maintenance-diagnostic.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	for _, host := range []struct{ actions, runner string }{{"false", "local"}, {"false", "github-hosted"}, {"true", "local"}} {
		t.Run(host.actions+"/"+host.runner, func(t *testing.T) {
			cmd := exec.Command("bash", path)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GITHUB_ACTIONS=" + host.actions, "RUNNER_ENVIRONMENT=" + host.runner}
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "requires a disposable Actions runner") {
				t.Fatalf("host guard: %s %v", out, err)
			}
		})
	}
}

func TestPHPPackageDiagnosticImportAndUnsafeTokenAreInert(t *testing.T) {
	cmd := exec.Command("python3", "-c", `import importlib.util
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('diagnostic','php-maintenance-diagnostic.py')
m=importlib.util.module_from_spec(spec)
with patch('subprocess.run',side_effect=AssertionError('unexpected external command')):
 spec.loader.exec_module(m)
 for token in ('bad','../php-diag-1-1','php-diag-1-1/../../other'):
  try:m.main(token)
  except ValueError as error:assert str(error)=='unsafe diagnostic token'
  else:raise AssertionError('unsafe token accepted')
`)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("diagnostic import/token guard: %s %v", out, err)
	}
}
