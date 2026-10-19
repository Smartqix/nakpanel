package ops

import (
	"context"
	"strings"
	"testing"
)

func TestRoundcubeMySQLRequiresPDOInTrustedCLIAndFPM(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		cli, fpm, foreign, valid bool
	}{{"ready", true, true, false, true}, {"CLI missing PDO", false, true, false, false}, {"FPM missing PDO", true, false, false, false}, {"PATH shadow", true, true, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			probe := completeRuntimeProbe("8.3")
			if tc.cli {
				probe.outputs[runtimeCommandKey("/usr/bin/php8.3", "-m")] = append(probe.outputs[runtimeCommandKey("/usr/bin/php8.3", "-m")], []byte("pdo_mysql\n")...)
			}
			if tc.fpm {
				probe.outputs[runtimeCommandKey("/usr/sbin/php-fpm8.3", "-i")] = []byte("pdo_mysql\nPDO Driver for MySQL => enabled\n")
			}
			if tc.foreign {
				probe.paths["php8.3"] = "/home/tenant/php8.3"
			}
			err := checkRoundcubeMySQLRuntime(context.Background(), "8.3", probe, fixedPHPResolver{distroPHPRuntime("8.3")})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("probe exposed runtime environment")
			}
		})
	}
}

func TestRoundcubeRuntimeProbeDropsEnvironmentOverrides(t *testing.T) {
	for _, name := range []string{"PHPRC", "PHP_INI_SCAN_DIR", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"} {
		t.Setenv(name, "secret-canary")
	}
	t.Setenv("NAKPANEL_ROUNDCUBE_PROBE_MARKER", "retained")
	values := roundcubeRuntimeEnvironment()
	joined := strings.Join(values, "\n")
	if strings.Contains(joined, "secret-canary") || !strings.Contains(joined, "NAKPANEL_ROUNDCUBE_PROBE_MARKER=retained") {
		t.Fatal("runtime environment override was retained or unrelated context lost")
	}
}
