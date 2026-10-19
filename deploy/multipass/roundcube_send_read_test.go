package multipass

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRoundcubeHTTPComposeSendRead(t *testing.T) {
	// Child Python reads do not enter Go's test cache dependency log.
	for _, path := range []string{"internal-tools-verify.sh", "roundcube-send-read.py", "roundcube_send_read_test.py", "ubuntu-platform-verify.sh"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatalf("read Roundcube qualification dependency %s: %v", path, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "roundcube_send_read_test.py", "-v")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Roundcube HTTP qualification behavior: %v\n%s", err, output)
	}
}
