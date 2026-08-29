package ops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type serverAdminCommandCall struct {
	name string
	args []string
}

type serverAdminScriptedRunner struct {
	mu      sync.Mutex
	calls   []serverAdminCommandCall
	handler func(context.Context, string, []string) ([]byte, error)
}

func (r *serverAdminScriptedRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, serverAdminCommandCall{name: name, args: append([]string(nil), args...)})
	r.mu.Unlock()
	if r.handler == nil {
		return nil, nil
	}
	return r.handler(ctx, name, args)
}

func (r *serverAdminScriptedRunner) snapshotCalls() []serverAdminCommandCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]serverAdminCommandCall(nil), r.calls...)
}

type serverAdminMapFileReader struct {
	files map[string][]byte
}

func (r serverAdminMapFileReader) ReadFile(path string, maxBytes int64) ([]byte, error) {
	data, ok := r.files[path]
	if !ok {
		return nil, errors.New("not found")
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrServerAdminOutputLimit
	}
	return append([]byte(nil), data...), nil
}

func TestServerAdminInspectManagedServicesUsesFixedRegistry(t *testing.T) {
	now := time.Date(2026, 7, 23, 15, 30, 0, 0, time.UTC)
	runner := &serverAdminScriptedRunner{
		handler: func(_ context.Context, name string, args []string) ([]byte, error) {
			if name != "systemctl" {
				t.Fatalf("command = %q, want systemctl", name)
			}
			if got := args[len(args)-1]; got != "nginx.service" {
				t.Fatalf("unit = %q, want nginx.service", got)
			}
			return []byte(strings.Join([]string{
				"LoadState=loaded",
				"ActiveState=active",
				"SubState=running",
				"UnitFileState=enabled",
				"Result=success",
				"MainPID=4321",
				"NRestarts=2",
				"MemoryCurrent=1048576",
				"CPUUsageNSec=5000",
				"ActiveEnterTimestampUSec=1721748600000000",
			}, "\n")), nil
		},
	}
	inspector := NewServerAdminInspector(ServerAdminInspectorOptions{
		Runner: runner, Now: func() time.Time { return now },
	})

	services, err := inspector.InspectManagedServices(context.Background(), types.InspectManagedServicesReq{
		ServiceIDs: []string{"web", "web"},
	})
	if err != nil {
		t.Fatalf("InspectManagedServices returned error: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("service count = %d, want 1", len(services))
	}
	service := services[0]
	if service.ID != "web" || service.DisplayName != "nginx" || !service.Available {
		t.Fatalf("service identity = %#v", service)
	}
	if service.ActiveState != "active" || service.MainPID != 4321 || service.RestartCount != 2 {
		t.Fatalf("service state = %#v", service)
	}
	if service.MemoryBytes != 1048576 || service.CPUUsageNSec != 5000 {
		t.Fatalf("service resources = %#v", service)
	}
	if service.ActiveSince.IsZero() || !service.CheckedAt.Equal(now) {
		t.Fatalf("service timestamps = %#v", service)
	}
	if len(service.AllowedActions) == 0 {
		t.Fatalf("allowed actions are empty: %#v", service)
	}

	calls := runner.snapshotCalls()
	if len(calls) != 1 {
		t.Fatalf("command calls = %#v, want one", calls)
	}
	for _, arg := range calls[0].args {
		if strings.ContainsAny(arg, ";&|`$") {
			t.Fatalf("unsafe command argument %q", arg)
		}
	}
}

func TestServerAdminRejectsUnknownServiceBeforeExecution(t *testing.T) {
	runner := &serverAdminScriptedRunner{}
	inspector := NewServerAdminInspector(ServerAdminInspectorOptions{Runner: runner})

	_, err := inspector.InspectManagedServices(context.Background(), types.InspectManagedServicesReq{
		ServiceIDs: []string{"nginx.service; reboot"},
	})
	if !errors.Is(err, ErrServerAdminRegistryID) {
		t.Fatalf("error = %v, want ErrServerAdminRegistryID", err)
	}
	if calls := runner.snapshotCalls(); len(calls) != 0 {
		t.Fatalf("runner called for unknown registry id: %#v", calls)
	}
}

func TestServerAdminInspectTimeParsesFixedTimedatectlProperties(t *testing.T) {
	now := time.Date(2026, 7, 23, 11, 45, 0, 0, time.FixedZone("EDT", -4*60*60))
	runner := &serverAdminScriptedRunner{
		handler: func(_ context.Context, name string, args []string) ([]byte, error) {
			if name != "timedatectl" {
				return nil, fmt.Errorf("unexpected command %q", name)
			}
			wantPrefix := []string{"show", "--no-pager"}
			if len(args) < len(wantPrefix) || args[0] != wantPrefix[0] || args[1] != wantPrefix[1] {
				t.Fatalf("timedatectl args = %#v", args)
			}
			return []byte("Timezone=America/New_York\nLocalRTC=no\nNTP=yes\nNTPSynchronized=yes\nCanNTP=yes\nRuntimeNTPServers=192.0.2.10\n"), nil
		},
	}
	inspector := NewServerAdminInspector(ServerAdminInspectorOptions{
		Runner: runner, Now: func() time.Time { return now },
	})

	state, err := inspector.InspectTime(context.Background())
	if err != nil {
		t.Fatalf("InspectTime returned error: %v", err)
	}
	if !state.Available || state.Timezone != "America/New_York" || state.RTCLocal {
		t.Fatalf("time state = %#v", state)
	}
	if !state.SyncEnabled || !state.Synchronized || state.Backend != "systemd-timesyncd" {
		t.Fatalf("NTP state = %#v", state)
	}
	if state.Source != "192.0.2.10" || !state.UniversalTime.Equal(now.UTC()) {
		t.Fatalf("time source/timestamp = %#v", state)
	}
}

func TestServerAdminInspectPHPUsesFixedHandlersAndValidatesFPM(t *testing.T) {
	now := time.Date(2026, 7, 23, 16, 0, 0, 0, time.UTC)
	runner := &serverAdminScriptedRunner{
		handler: func(_ context.Context, name string, args []string) ([]byte, error) {
			switch name {
			case "/usr/bin/php":
				return []byte("PHP 8.3.12 (cli)\n"), nil
			case "/usr/bin/php8.1", "/usr/bin/php8.2", "/usr/bin/php8.5":
				return nil, errors.New("not found")
			case "/usr/bin/php8.4":
				if len(args) == 1 && args[0] == "--version" {
					return []byte("PHP 8.4.23 (cli)\n"), nil
				}
				return nil, errors.New("CLI-only PHP must not be used for module discovery")
			case "/usr/bin/php8.3":
				if len(args) != 1 {
					return nil, errors.New("unexpected PHP arguments")
				}
				switch args[0] {
				case "--version":
					return []byte("PHP 8.3.12 (cli) (built: Jul 1 2026)\n"), nil
				case "-m":
					return []byte("[PHP Modules]\nZend OPcache\njson\ncurl\nJSON\n\n[Zend Modules]\nZend OPcache\n"), nil
				}
			case "/usr/sbin/php-fpm8.3":
				if len(args) == 1 && args[0] == "-tt" {
					return []byte("configuration file test is successful\n"), nil
				}
			case "systemctl":
				unit := args[len(args)-1]
				if unit == "php8.1-fpm.service" || unit == "php8.2-fpm.service" ||
					unit == "php8.4-fpm.service" || unit == "php8.5-fpm.service" {
					return []byte("LoadState=not-found\nActiveState=inactive\nSubState=dead\n"), nil
				}
				if unit == "php8.3-fpm.service" {
					return []byte("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n"), nil
				}
			}
			return nil, fmt.Errorf("unexpected command %q %#v", name, args)
		},
	}
	inspector := NewServerAdminInspector(ServerAdminInspectorOptions{
		Runner: runner, Now: func() time.Time { return now },
	})

	handlers, err := inspector.InspectPHP(context.Background())
	if err != nil {
		t.Fatalf("InspectPHP returned error: %v", err)
	}
	if len(handlers) != 5 {
		t.Fatalf("handler count = %d, want 5", len(handlers))
	}
	if handlers[1].ID != "php82" || handlers[1].State != "not_installed" {
		t.Fatalf("PHP 8.2 handler = %#v", handlers[1])
	}
	handler := handlers[2]
	if handler.ID != "php83" || handler.State != "active" || !handler.Default || !handler.ConfigValid {
		t.Fatalf("PHP 8.3 handler = %#v", handler)
	}
	if handler.FullVersion != "8.3.12" || handler.SAPI != "fpm-fcgi" {
		t.Fatalf("PHP version/SAPI = %#v", handler)
	}
	if len(handler.Extensions) != 3 {
		t.Fatalf("extensions = %#v, want three unique entries", handler.Extensions)
	}
	foundProtectedJSON := false
	for _, extension := range handler.Extensions {
		if strings.EqualFold(extension.Name, "json") {
			foundProtectedJSON = extension.Protected
		}
		if !extension.Installed || !extension.Enabled {
			t.Fatalf("extension state = %#v", extension)
		}
	}
	if !foundProtectedJSON {
		t.Fatalf("json extension was not protected: %#v", handler.Extensions)
	}
	if handlers[3].ID != "php84" || handlers[3].State != "not_installed" ||
		handlers[3].FullVersion != "8.4.23" || len(handlers[3].Extensions) != 0 {
		t.Fatalf("CLI-only PHP 8.4 handler = %#v", handlers[3])
	}
	for _, call := range runner.snapshotCalls() {
		switch call.name {
		case "/usr/bin/php", "/usr/bin/php8.1", "/usr/bin/php8.2", "/usr/bin/php8.3",
			"/usr/bin/php8.4", "/usr/bin/php8.5",
			"/usr/sbin/php-fpm8.3", "systemctl":
		default:
			t.Fatalf("command escaped fixed PHP registry: %#v", call)
		}
	}
}

func TestServerAdminCommandsHaveOutputAndTimeBounds(t *testing.T) {
	t.Run("output", func(t *testing.T) {
		runner := &serverAdminScriptedRunner{
			handler: func(context.Context, string, []string) ([]byte, error) {
				return []byte(strings.Repeat("x", 65)), nil
			},
		}
		inspector := NewServerAdminInspector(ServerAdminInspectorOptions{
			Runner: runner, MaxCommandOutput: 64,
		})
		_, err := inspector.InspectTime(context.Background())
		if !errors.Is(err, ErrServerAdminOutputLimit) {
			t.Fatalf("error = %v, want ErrServerAdminOutputLimit", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		runner := &serverAdminScriptedRunner{
			handler: func(ctx context.Context, _ string, _ []string) ([]byte, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		inspector := NewServerAdminInspector(ServerAdminInspectorOptions{
			Runner: runner, CommandTimeout: 10 * time.Millisecond,
		})
		_, err := inspector.InspectTime(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want context deadline exceeded", err)
		}
	})
}

func TestServerAdminInspectServerBuildsCompleteReadOnlySnapshot(t *testing.T) {
	now := time.Date(2026, 7, 23, 17, 0, 0, 0, time.UTC)
	files := serverAdminMapFileReader{files: map[string][]byte{
		"/etc/hostname":   []byte("panel01\n"),
		"/etc/os-release": []byte("NAME=Ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\n"),
		"/proc/uptime":    []byte("90061.50 100.00\n"),
		"/proc/loadavg":   []byte("0.10 0.20 0.30 1/123 456\n"),
		"/proc/meminfo":   []byte("MemTotal: 1000 kB\nMemAvailable: 600 kB\nSwapTotal: 500 kB\nSwapFree: 400 kB\n"),
	}}
	runner := &serverAdminScriptedRunner{
		handler: func(_ context.Context, name string, args []string) ([]byte, error) {
			switch name {
			case "uname":
				return []byte("6.8.0-63-generic\n"), nil
			case "df":
				path := args[len(args)-1]
				mountpoint := "/"
				device := "/dev/vda1"
				if path == "/home" {
					mountpoint, device = "/home", "/dev/vdb1"
				}
				if path == "/var/lib/nakpanel" {
					mountpoint = "/"
				}
				return []byte("Filesystem 1B-blocks Avail Inodes IFree Mounted on\n" +
					device + " 1000000 400000 10000 8000 " + mountpoint + "\n"), nil
			case "ss":
				return []byte("tcp LISTEN 0 4096 0.0.0.0:7443 0.0.0.0:*\nudp UNCONN 0 0 [::]:53 [::]:*\n"), nil
			case "timedatectl":
				return []byte("Timezone=UTC\nLocalRTC=no\nNTP=yes\nNTPSynchronized=yes\nCanNTP=yes\n"), nil
			case "systemctl":
				return []byte("LoadState=not-found\nActiveState=inactive\nSubState=dead\n"), nil
			case "/usr/bin/php", "/usr/bin/php8.2", "/usr/bin/php8.3":
				return nil, errors.New("not found")
			default:
				return nil, fmt.Errorf("unexpected command %q %#v", name, args)
			}
		},
	}
	inspector := NewServerAdminInspector(ServerAdminInspectorOptions{
		Runner: runner, FileReader: files, Now: func() time.Time { return now },
	})

	inventory, err := inspector.InspectServer(context.Background())
	if err != nil {
		t.Fatalf("InspectServer returned error: %v", err)
	}
	if inventory.Status != types.ServerStateHealthy || inventory.LastError != "" {
		t.Fatalf("inventory health = %#v", inventory)
	}
	if inventory.Hostname != "panel01" || inventory.OperatingSystem != "Ubuntu 24.04.2 LTS" ||
		inventory.Kernel != "6.8.0-63-generic" || inventory.UptimeSeconds != 90061 {
		t.Fatalf("host inventory = %#v", inventory)
	}
	if len(inventory.LoadAverage) != 3 || inventory.Memory.TotalBytes != 1000*1024 ||
		inventory.Memory.SwapFreeBytes != 400*1024 {
		t.Fatalf("resource inventory = %#v", inventory)
	}
	if len(inventory.Filesystems) != 2 {
		t.Fatalf("filesystems = %#v, want deduplicated root and /home", inventory.Filesystems)
	}
	if len(inventory.Listeners) != 2 || inventory.Listeners[0].ServiceID != "dns" ||
		inventory.Listeners[1].ServiceID != "panel" {
		t.Fatalf("listeners = %#v", inventory.Listeners)
	}
	if len(inventory.Services) != len(managedServiceDescriptors) {
		t.Fatalf("services = %d, want %d", len(inventory.Services), len(managedServiceDescriptors))
	}
	if len(inventory.PHPHandlers) != len(phpHandlerDescriptors) {
		t.Fatalf("PHP handlers = %#v", inventory.PHPHandlers)
	}
	if len(inventory.Components) != len(managedServiceDescriptors)+len(phpHandlerDescriptors) {
		t.Fatalf("components = %#v", inventory.Components)
	}
}
