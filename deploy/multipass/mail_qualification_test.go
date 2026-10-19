package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMailQualificationBrowserKeepsProductionDefaultsAndBoundsLabOverride(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	helper, err := filepath.Abs("qualification-browser-config.cjs")
	if err != nil {
		t.Fatal(err)
	}
	script := `const assert=require('node:assert/strict');const config=require(process.argv[1]);
const normal=config({});assert.equal(normal.context.ignoreHTTPSErrors,false);assert.equal(normal.launch.args.length,0);
const lab=config({NAKPANEL_QA_GUEST_IP:'192.168.252.88',NAKPANEL_QA_IGNORE_HTTPS_ERRORS:'1'});assert.equal(lab.context.ignoreHTTPSErrors,true);assert.ok(lab.launch.args[0].includes('MAP *.test 192.168.252.88'));
for(const e of [{NAKPANEL_QA_IGNORE_HTTPS_ERRORS:'1'},{NAKPANEL_QA_GUEST_IP:'127.0.0.1,MAP * malicious'},{NAKPANEL_QA_GUEST_IP:'not-an-ip'}])assert.throws(()=>config(e));
`
	out, err := exec.Command(node, "-e", script, helper).CombinedOutput()
	if err != nil {
		t.Fatalf("browser configuration: %s %v", out, err)
	}
}

func TestMailQualificationRunsRealBrowserAndTrustedProtocolsWithoutPublishingState(t *testing.T) {
	data, err := os.ReadFile("mail-workspace-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{"assert_current_vm_identity", "mail-workspace-live-verify.cjs", "NAKPANEL_QA_STAGE=prepare", "NAKPANEL_QA_STAGE=scope", "NAKPANEL_QA_STAGE=cleanup", "mail-workspace-protocol-verify.py", "NAKPANEL_QA_MAIL_CA_FILE=/etc/stalwart/tls/cert.pem", "mktemp -d", "chmod 700", "phase29-fixtures.tsv"} {
		if !strings.Contains(script, want) {
			t.Errorf("missing real Mail gate %s", want)
		}
	}
	if strings.Contains(script, "_create_unverified_context") || strings.Contains(script, "cp \"${state}\" \"${NAKPANEL_CELL_REPORT_DIR}") {
		t.Fatal("private state published or protocol TLS verification disabled")
	}
	protocol, err := os.ReadFile("mail-workspace-protocol-verify.py")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(protocol), "NAKPANEL_QA_MAIL_CA_FILE") {
		t.Fatal("explicit trusted local CA support missing")
	}
	wrapper, err := os.ReadFile("ubuntu-platform-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wrapper), "internal-tools mail-workspace phase33") {
		t.Fatal("mandatory Mail workspace gate missing from native sequence")
	}
}
