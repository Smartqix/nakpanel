package backup

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCollectPlatformUsesObservedToolsAndIntent(t *testing.T) {
	p, err := collectPlatform(context.Background(), "test-dsn", platformProbe{
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/etc/os-release":
				return []byte("ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n"), nil
			case "/etc/nakpanel/platform.json":
				return []byte(fmt.Sprintf(`{"os_id":"ubuntu","version_id":"26.04","architecture":%q,"profile":"ubuntu-26.04-native","internal_php_version":"8.5","hosting_php_versions":["8.3"]}`, runtime.GOARCH)), nil
			}
			return nil, errors.New("missing")
		},
		command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "SHOW server_version") {
				return []byte("18.0 (Ubuntu 18.0-1)"), nil
			}
			if strings.Contains(joined, "SELECT DISTINCT version") {
				return []byte("8.3\n8.4\n"), nil
			}
			switch name {
			case "php8.5":
				if args[0] == "-r" {
					return []byte("8.5"), nil
				}
				return []byte("PHP 8.5.1"), nil
			case "/usr/sbin/php-fpm8.5":
				return []byte("PHP 8.5.1 (fpm-fcgi)"), nil
			case "pg_dump", "pg_restore":
				return []byte(name + " (PostgreSQL) 18.0"), nil
			case "mariadb-dump":
				return []byte("mariadb-dump Ver 10.19 Distrib 11.8.3-MariaDB"), nil
			case "mariadb":
				if args[0] == "--version" {
					return []byte("mariadb from 11.8.3-MariaDB, client 15.2 for Linux"), nil
				}
				return []byte("11.8.3-MariaDB-0ubuntu1"), nil
			case "stalwart-mail":
				return []byte("Stalwart Mail Server v0.11.8"), nil
			}
			return nil, errors.New("no tool")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.MariaDBDumpVersion != "11.8.3" || p.MariaDBClientVersion != "11.8.3" || p.PostgresServerVersion != "18.0" || p.StalwartVersion != "0.11.8" {
		t.Fatalf("wrong observed versions %+v", p)
	}
	if len(p.HostingPHPVersions) != 0 || strings.Join(p.RequiredPHPVersions, ",") != "8.3,8.4" || !p.PHPInventoryComplete {
		t.Fatalf("trusted configured inventory instead of tools/SQL: %+v", p)
	}
}

func TestImageProvenanceUsesActualRootlessImageDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	ref := "registry.example.test/app@" + digest
	probe := platformProbe{command: func(_ context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "json_agg") {
			return []byte(fmt.Sprintf(`[{"username":"tenant","subscription_id":7,"image_ref":%q}]`, ref)), nil
		}
		if name != "runuser" || !strings.Contains(joined, "XDG_DATA_HOME=/var/lib/nakpanel/containers/sub-7/data") || !strings.Contains(joined, "podman image inspect") {
			t.Fatalf("wrong observation command %s %s", name, joined)
		}
		return []byte(digest), nil
	}}
	got := collectImageDigests(context.Background(), "test-dsn", probe)
	if got[ref] != digest {
		t.Fatalf("digests=%v", got)
	}
}
