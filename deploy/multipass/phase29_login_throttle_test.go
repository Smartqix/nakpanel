package multipass

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPhase29LoginThrottleDiagnosticBehavior(t *testing.T) {
	for _, path := range []string{"phase29-verify.sh", "phase29-login-throttle.py", "phase29_login_throttle_test.py"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "python3", "phase29_login_throttle_test.py", "-v").CombinedOutput(); err != nil {
		t.Fatalf("Phase29 login diagnostics behavior: %v\n%s", err, out)
	}
}
