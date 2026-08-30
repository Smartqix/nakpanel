package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPhase30InstallerHasValidShellSyntax(t *testing.T) {
	cmd := exec.Command("bash", "-n", "../install/phase30-install.sh")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n phase30-install.sh: %v\n%s", err, output)
	}
}

func TestPhase3RunsCanonicalPhase30InstallerBeforeServicesAndProvisioning(t *testing.T) {
	data, err := os.ReadFile("phase3-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	installer := strings.Index(script, `sudo bash "${REMOTE_SRC}/deploy/install/phase30-install.sh"`)
	agentStart := strings.Index(script, "sudo systemctl restart nakpanel-agent.service")
	panelStart := strings.Index(script, "sudo systemctl restart nakpanel.service")
	provision := strings.Index(script, `create_status="$(curl`)
	if installer < 0 {
		t.Fatal("Phase 3 must run the canonical phase30-install.sh")
	}
	for label, index := range map[string]int{
		"agent startup":     agentStart,
		"panel startup":     panelStart,
		"site provisioning": provision,
	} {
		if index < 0 || installer >= index {
			t.Fatalf("Phase 3 must run phase30-install.sh before %s", label)
		}
	}
}

func TestPhase30InstallerPinsAndValidatesProductionPHPToolchain(t *testing.T) {
	data, err := os.ReadFile("../install/phase30-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{
		`VERSION_ID:-`, `24.04`, `ppa:ondrej/php`, `Signed-By`,
		`PHP_VERSIONS=(8.3 8.4 8.5)`,
		`php${version}-cli`, `php${version}-fpm`, `php${version}-bcmath`,
		`php${version}-curl`, `php${version}-gd`, `php${version}-imagick`,
		`php${version}-intl`, `php${version}-mbstring`, `php${version}-mysql`,
		`php${version}-redis`, `php${version}-soap`, `php${version}-xml`,
		`php${version}-zip`, `php${version}-common`, `php${version}-opcache`,
		`php${version}-readline`, `php${version}-apcu`,
		`COMPOSER_VERSION=`, `getcomposer.org/download/${COMPOSER_VERSION}/composer.phar`,
		`composer.phar.sha256sum`, `WP_CLI_VERSION=2.12.0`,
		`wp-cli-${WP_CLI_VERSION}.phar.sha512`, `wp-cli.sha512.check`,
		`sha256sum --check`, `sha512sum --check`,
		`self-update is disabled`, `cli update is disabled`, `chmod 0555`,
		`php-fpm${version}`, `PHP_MAJOR_VERSION`, `get_loaded_extensions`, `Zend OPcache`,
		`"${fpm}" -v`, `"${fpm}" -F -y`, `[[ -S "${config}.sock" ]]`,
		`kill -0 "${fpm_pid}"`, `SECONDS + 5`, `wait "${fpm_pid}"`,
		`ready_checks`, `kill -KILL "${fpm_pid}"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase30 installer is missing %q", want)
		}
	}
	if strings.Contains(script, "NAKPANEL_PHP_VERSIONS") {
		t.Fatal("canonical installer must not inherit a runtime subset override")
	}
}

func TestPhase30InstallerMakesClamAVSignaturesReadyOrFailsClosed(t *testing.T) {
	data, err := os.ReadFile("../install/phase30-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{
		"clamav-freshclam", "freshclam", "/var/lib/clamav/*.cvd", "/var/lib/clamav/*.cld",
		"ClamAV signatures are unavailable", "clamscan --version",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("phase30 installer does not fail closed on missing ClamAV readiness: missing %q", want)
		}
	}
}

func TestUnifiedInstallerRunsPhase30AfterPhase21To25(t *testing.T) {
	data, err := os.ReadFile("../install/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	prerequisite := strings.Index(script, `bash "${SCRIPT_DIR}/phase21-25-install.sh"`)
	phase30 := strings.Index(script, `bash "${SCRIPT_DIR}/phase30-install.sh"`)
	if prerequisite < 0 || phase30 < 0 || prerequisite >= phase30 {
		t.Fatal("unified installer must run phase30-install.sh after phase21-25-install.sh")
	}
}
