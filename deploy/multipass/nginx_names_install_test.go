package multipass

import (
	"os"
	"strings"
	"testing"
)

func TestNginxSupportsFullLengthDomainNames(t *testing.T) {
	data, err := os.ReadFile("../nginx/nakpanel-server-names.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "server_names_hash_bucket_size 512;") {
		t.Fatal("valid long DNS names need sufficient nginx hash bucket space")
	}
	data, err = os.ReadFile("../install/phase7-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "nginx-server-names-install.sh") {
		t.Fatal("fresh installations and upgrades must install the hostname capacity configuration")
	}
	data, err = os.ReadFile("../install/nginx-server-names-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"nginx -t", "rollback", "systemctl reload nginx", "-L", "mktemp", "mv -f"} {
		if !strings.Contains(string(data), marker) {
			t.Errorf("hostname configuration installer is missing %q", marker)
		}
	}
}
