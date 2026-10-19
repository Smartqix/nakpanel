package ops

import (
	"bytes"
	"github.com/nakroteck/nakpanel/internal/backup"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestServerBackupTreesIncludeNginxPolicyZones(t *testing.T) {
	if !slices.Contains(serverBackupTrees, "/etc/nginx/conf.d") {
		t.Fatal("server backup omits nginx policy-zone definitions required by restored vhosts")
	}
}

func TestServerBackupArchivesSharedPodmanRuntimeWithDependentValkeyUnit(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "nakpanel-podman-runtime.service")
	cache := filepath.Join(root, "nakpanel-valkey@12.service")
	sharedData := renderValkeyPodmanRuntimeUnit()
	cacheData := "[Unit]\nRequires=nakpanel-podman-runtime.service\nAfter=nakpanel-podman-runtime.service\n[Service]\nExecStart=/usr/bin/true\n"
	for name, data := range map[string]string{shared: sharedData, cache: cacheData} {
		if err := os.WriteFile(name, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	units, err := collectNakpanelUnits(root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(units, shared) || !slices.Contains(units, cache) {
		t.Fatalf("backup inventory loses required shared dependency: %v", units)
	}
	key := make([]byte, 32)
	var encrypted bytes.Buffer
	writer, err := backup.NewArchiveWriter(&encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range units {
		if err := writer.AddTreeMapped(unit, "/etc/systemd/system/"+filepath.Base(unit), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := backup.NewArchiveReader(bytes.NewReader(encrypted.Bytes()), key)
	if err != nil {
		t.Fatal(err)
	}
	archived := map[string]string{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		archived[header.Name] = string(data)
	}
	if err := reader.Finish(); err != nil {
		t.Fatal(err)
	}
	if archived["files/etc/systemd/system/nakpanel-podman-runtime.service"] != sharedData {
		t.Fatal("shared root-managed runtime unit did not survive encrypted archive")
	}
	if !strings.Contains(archived["files/etc/systemd/system/nakpanel-valkey@12.service"], "Requires=nakpanel-podman-runtime.service") {
		t.Fatal("dependent Valkey unit did not survive encrypted archive")
	}
}
