package multipass

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDatabaseManagerRuntimeIsolation(t *testing.T) {
	checks := map[string][]string{
		"../database-manager/nginx.conf":               {"listen 127.0.0.1:9082", "access_log off", "client_max_body_size 17m", "limit_conn manager 8"},
		"../database-manager/php-fpm.conf":             {"clear_env = yes", "pm.max_children = 4", "session.use_strict_mode", "php_value[session.save_path]", "display_errors] = off"},
		"../systemd/nakpanel-database-manager.service": {"User=nakpanel-dbmgr", "ProtectSystem=strict", "ProtectHome=true", "IPAddressDeny=any", "-/etc/nakpanel", "-/var/lib/nakpanel", "CapabilityBoundingSet="},
		"../database-manager/tmpfiles.conf":            {"/run/nakpanel-db-manager 0750 nakpanel nakpanel-dbmgr", "/var/lib/nakpanel-database-manager/grants 0700"},
		"../database-manager/panel-runtime.conf":       {"ReadWritePaths=/run/nakpanel-db-manager", "SupplementaryGroups=nakpanel-dbmgr"},
	}
	for path, fragments := range checks {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range fragments {
			if !strings.Contains(string(data), fragment) {
				t.Errorf("%s missing %q", path, fragment)
			}
		}
	}
	script := readExecutableScript(t, "../install/database-manager-install.sh")
	for _, fragment := range []string{"VERSION=5.2.3", "SHA256=57881348297c4412f86c410547cf76b4d8a236574dd2c6b7d6a2beebe7fc44e3", "sha256sum --check --status", "--no-same-owner", "systemd-tmpfiles --create", "nakpanel.service.d"} {
		if !strings.Contains(script, fragment) {
			t.Errorf("installer missing %q", fragment)
		}
	}
}

func TestDatabaseManagerPHPAdapter(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP not installed")
	}
	out, err := exec.Command(php, "../database-manager/adapter_test.php").CombinedOutput()
	if err != nil {
		t.Fatalf("adapter tests failed: %v\n%s", err, out)
	}
	for _, file := range []string{"adapter.php", "prepend.php", "signon.php", "health.php", "config.inc.php"} {
		out, err = exec.Command(php, "-l", "../database-manager/"+file).CombinedOutput()
		if err != nil {
			t.Fatalf("PHP syntax %s: %v\n%s", file, err, out)
		}
	}
}

func TestDatabaseManagerAllowsOnlyFixedMessageScript(t *testing.T) {
	data, err := os.ReadFile("../database-manager/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)
	for _, want := range []string{"location = /js/messages.php {", "fastcgi_param SCRIPT_FILENAME /opt/nakpanel-database-manager/current/js/messages.php;"} {
		if !strings.Contains(config, want) {
			t.Errorf("runtime is missing protected message script directive %q", want)
		}
	}
	if strings.Contains(config, "fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name") {
		t.Fatal("runtime must not execute arbitrary PHP scripts")
	}
}
