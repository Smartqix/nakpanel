package ops

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestValkeyStartupRestoresOnlyTenantTraversalFromPersistedUnits(t *testing.T) {
	root := t.TempDir()
	units := filepath.Join(root, "units")
	runtimeRoot := filepath.Join(root, "run", "nakpanel", "valkey")
	if err := os.MkdirAll(units, 0755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(runtimeRoot)
	if err := os.MkdirAll(parent, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	agentSocket := filepath.Join(parent, "agent.sock")
	if err := os.WriteFile(agentSocket, []byte("private socket fixture"), 0660); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id  int64
		uid string
	}{{12, "1200"}, {13, "1300"}} {
		req := types.EnsureValkeyReq{SubscriptionID: tc.id, MemoryMB: 64, CPUPercent: 25, ProcessLimit: 64}
		unit := renderValkeyUnit(req, tc.uid, tc.uid, "/etc/nakpanel/valkey/sub-12", "/run/nakpanel/valkey/sub-12", "registry.example.test/valkey@sha256:"+strings.Repeat("a", 64))
		if err := os.WriteFile(filepath.Join(units, "nakpanel-valkey@"+strings.TrimPrefix(tc.uid, "1")+".unused"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		name := "nakpanel-valkey@12.service"
		if tc.id == 13 {
			name = "nakpanel-valkey@13.service"
		}
		if err := os.WriteFile(filepath.Join(units, name), []byte(unit), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// A user service or unrelated generated unit is not an ACL authority.
	if err := os.WriteFile(filepath.Join(units, "other.service"), []byte("[Service]\nGroup=1400\nExecStart=/usr/bin/podman run --user 1400:1400 image\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runner := &callRunner{}
	if err := restoreValkeyRuntimeAccess(context.Background(), units, parent, uint32(os.Geteuid()), runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != "setfacl -m u:1200:--x,u:1300:--x "+parent {
		t.Fatalf("startup ACL replay=%v", runner.calls)
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode().Perm() != 0750 {
		t.Fatalf("runtime parent permissions broadened: %v %v", info, err)
	}
	info, err = os.Stat(agentSocket)
	if err != nil || info.Mode().Perm()&0007 != 0 {
		t.Fatalf("agent socket permissions broadened: %v %v", info, err)
	}
}

func TestValkeyStartupRejectsUntrustedUnitMetadataWithoutACLChanges(t *testing.T) {
	valid := renderValkeyUnit(types.EnsureValkeyReq{SubscriptionID: 12, MemoryMB: 64, CPUPercent: 25, ProcessLimit: 64}, "1200", "1200", "/etc/nakpanel/valkey/sub-12", "/run/nakpanel/valkey/sub-12", "registry.example.test/valkey@sha256:"+strings.Repeat("a", 64))
	for _, tc := range []struct {
		name, contents string
		mode           os.FileMode
		symlink        bool
	}{
		{name: "group writable", contents: valid, mode: 0660},
		{name: "world writable", contents: valid, mode: 0666},
		{name: "symlink", contents: valid, mode: 0644, symlink: true},
		{name: "wrong runtime identity", contents: strings.Replace(valid, "RuntimeDirectory=nakpanel/valkey/sub-12", "RuntimeDirectory=another/private", 1), mode: 0644},
		{name: "unsafe UID", contents: strings.Replace(valid, "--user 1200:1200", "--user root:1200", 1), mode: 0644},
		{name: "UID zero", contents: strings.Replace(valid, "--user 1200:1200", "--user 0:1200", 1), mode: 0644},
		{name: "group mismatch", contents: strings.Replace(valid, "Group=1200", "Group=1300", 1), mode: 0644},
		{name: "foreign executable", contents: strings.Replace(valid, "ExecStart=/usr/bin/podman run ", "ExecStart=/home/tenant/runner ", 1), mode: 0644},
		{name: "root group", contents: strings.Replace(strings.Replace(valid, "--user 1200:1200", "--user 1200:0", 1), "Group=1200", "Group=0", 1), mode: 0644},
		{name: "wrong container identity", contents: strings.Replace(valid, "--name nakpanel-valkey-sub-12", "--name nakpanel-valkey-sub-13", 1), mode: 0644},
		{name: "non-root controller", contents: strings.Replace(valid, "[Service]", "[Service]\nUser=1200", 1), mode: 0644},
		{name: "multiple runtime directories", contents: strings.Replace(valid, "RuntimeDirectory=nakpanel/valkey/sub-12", "RuntimeDirectory=nakpanel/valkey/sub-12 other", 1), mode: 0644},
		{name: "duplicate group directive", contents: strings.Replace(valid, "Group=1200", "Group=1300\nGroup=1200", 1), mode: 0644},
		{name: "duplicate executable directive", contents: valid + "\n[Service]\nExecStart=/usr/bin/true\n", mode: 0644},
		{name: "duplicate tenant option", contents: strings.Replace(valid, "--user 1200:1200", "--user 1200:1200 --user 1300:1300", 1), mode: 0644},
		{name: "negative tenant", contents: strings.Replace(valid, "--user 1200:1200", "--user -1:1200", 1), mode: 0644},
		{name: "UID overflow", contents: strings.Replace(valid, "--user 1200:1200", "--user 4294967296:1200", 1), mode: 0644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			unit := filepath.Join(root, "nakpanel-valkey@12.service")
			if tc.symlink {
				target := filepath.Join(root, "target")
				if err := os.WriteFile(target, []byte(tc.contents), tc.mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, unit); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(unit, []byte(tc.contents), tc.mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(unit, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			runner := &callRunner{}
			if err := restoreValkeyRuntimeAccess(context.Background(), root, filepath.Join(root, "run", "nakpanel"), uint32(os.Geteuid()), runner); err == nil {
				t.Fatal("untrusted cache unit authorized runtime ACL")
			}
			if len(runner.calls) != 0 {
				t.Fatalf("untrusted metadata changed ACL: %v", runner.calls)
			}
		})
	}
}

func TestValkeyStartupACLFailureIsReported(t *testing.T) {
	root := t.TempDir()
	unit := renderValkeyUnit(types.EnsureValkeyReq{SubscriptionID: 12, MemoryMB: 64, CPUPercent: 25, ProcessLimit: 64}, "1200", "1200", "/etc/nakpanel/valkey/sub-12", "/run/nakpanel/valkey/sub-12", "image")
	if err := os.WriteFile(filepath.Join(root, "nakpanel-valkey@12.service"), []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{err: os.ErrPermission}
	if err := restoreValkeyRuntimeAccess(context.Background(), root, root, uint32(os.Geteuid()), runner); !errors.Is(err, os.ErrPermission) {
		t.Fatal("ACL restoration failure was hidden")
	}
}

func TestValkeyStartupRequiresRootOwnedUnitsInProduction(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fixture requires a non-root owner")
	}
	root := t.TempDir()
	unit := renderValkeyUnit(types.EnsureValkeyReq{SubscriptionID: 12}, "1200", "1200", "/etc/nakpanel/valkey/sub-12", "/run/nakpanel/valkey/sub-12", "image")
	if err := os.WriteFile(filepath.Join(root, "nakpanel-valkey@12.service"), []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}
	runner := &callRunner{}
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{SystemdUnitDir: root, Runner: runner})
	if err := p.RestoreValkeyRuntimeAccess(context.Background()); err == nil {
		t.Fatal("non-root unit owner became ACL authority")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("untrusted owner changed ACL: %v", runner.calls)
	}
}

func TestValkeyStartupDoesNotMutateWhenNoCacheUnitsExist(t *testing.T) {
	root := t.TempDir()
	runner := &callRunner{}
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{SystemdUnitDir: root, Runner: runner})
	if err := p.RestoreValkeyRuntimeAccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("empty startup changed runtime: %v", runner.calls)
	}
}

func TestValkeyStartupRejectsUnsafeRuntimeParent(t *testing.T) {
	for _, mode := range []string{"symlink", "writable", "foreign-owner"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			units := filepath.Join(root, "units")
			if err := os.Mkdir(units, 0755); err != nil {
				t.Fatal(err)
			}
			unit := renderValkeyUnit(types.EnsureValkeyReq{SubscriptionID: 12}, "1200", "1200", "/etc/nakpanel/valkey/sub-12", "/run/nakpanel/valkey/sub-12", "image")
			if err := os.WriteFile(filepath.Join(units, "nakpanel-valkey@12.service"), []byte(unit), 0644); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(root, "run-parent")
			if mode == "symlink" {
				if err := os.Symlink(root, parent); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(parent, 0750); err != nil {
					t.Fatal(err)
				}
				if mode == "writable" {
					if err := os.Chmod(parent, 0770); err != nil {
						t.Fatal(err)
					}
				}
			}
			owner := uint32(os.Geteuid())
			if mode == "foreign-owner" {
				owner++
			}
			runner := &callRunner{}
			if err := restoreValkeyRuntimeAccess(context.Background(), units, parent, owner, runner); err == nil {
				t.Fatal("unsafe ACL target accepted")
			}
			if len(runner.calls) != 0 {
				t.Fatalf("unsafe target changed ACL: %v", runner.calls)
			}
		})
	}
}

func TestValkeyPersistsSharedPodmanBootDependencyBeforeServiceEnable(t *testing.T) {
	root := t.TempDir()
	units := filepath.Join(root, "units")
	runner := &toolkitRunner{}
	p := NewHostingToolkitProvisioner(HostingToolkitOptions{SystemdUnitDir: units, ValkeyConfigRoot: filepath.Join(root, "config"), ValkeyRuntimeRoot: filepath.Join(root, "run", "valkey"), Runner: runner, ValkeyImage: "registry.example.test/valkey@sha256:" + strings.Repeat("a", 64)})
	p.lookupUser = func(string) (*user.User, error) {
		return &user.User{Username: "nptenant", Uid: strconv.Itoa(os.Geteuid() + 1), Gid: strconv.Itoa(os.Getgid() + 1)}, nil
	}
	// A disabled cache still persists its boot dependency for later activation.
	if _, err := p.EnsureValkey(context.Background(), types.EnsureValkeyReq{SubscriptionID: 12, Username: "nptenant", State: "disabled", ACLHash: strings.Repeat("a", 64), MemoryMB: 64, MaxClients: 32, CPUPercent: 25, ProcessLimit: 64}); err != nil {
		t.Fatal(err)
	}
	cache, err := os.ReadFile(filepath.Join(units, "nakpanel-valkey@12.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"Requires=nakpanel-podman-runtime.service", "After=podman.service nakpanel-podman-runtime.service"} {
		if !strings.Contains(string(cache), line+"\n") {
			t.Fatalf("cache starts without runtime directory dependency %q", line)
		}
	}
	runtime, err := os.ReadFile(filepath.Join(units, "nakpanel-podman-runtime.service"))
	if err != nil {
		t.Fatal(err)
	}
	// PID 1 creates these paths before sandboxing ExecStart. No tenant owns them,
	// and stopping a cache cannot delete the shared Podman runtime.
	for _, line := range []string{"User=root", "Group=root", "Type=oneshot", "RemainAfterExit=yes", "RuntimeDirectory=containers libpod crun", "RuntimeDirectoryMode=0755", "RuntimeDirectoryPreserve=yes", "ExecStart=/usr/bin/true", "ProtectSystem=strict", "ReadWritePaths=/run/containers /run/libpod /run/crun"} {
		if !strings.Contains(string(runtime), line+"\n") {
			t.Fatalf("unsafe or incomplete Podman runtime unit: missing %q", line)
		}
	}
	if strings.Contains(string(runtime), "ReadWritePaths=/run\n") {
		t.Fatal("runtime helper exposes all /run")
	}
}

func TestValkeyRefusesInvalidAccountIdentityBeforeMutatingHost(t *testing.T) {
	for _, identity := range []struct{ uid, gid string }{{"0", "1200"}, {"1200", "0"}, {"root", "1200"}, {"1200", "4294967296"}} {
		t.Run(identity.uid+":"+identity.gid, func(t *testing.T) {
			root := t.TempDir()
			runner := &callRunner{}
			configRoot := filepath.Join(root, "config")
			p := NewHostingToolkitProvisioner(HostingToolkitOptions{SystemdUnitDir: filepath.Join(root, "units"), ValkeyConfigRoot: configRoot, ValkeyRuntimeRoot: filepath.Join(root, "run", "valkey"), Runner: runner, ValkeyImage: "registry.example.test/valkey@sha256:" + strings.Repeat("a", 64)})
			p.lookupUser = func(string) (*user.User, error) {
				return &user.User{Username: "nptenant", Uid: identity.uid, Gid: identity.gid}, nil
			}
			if _, err := p.EnsureValkey(context.Background(), types.EnsureValkeyReq{SubscriptionID: 12, Username: "nptenant", State: "disabled", ACLHash: strings.Repeat("a", 64), MemoryMB: 64, MaxClients: 32, CPUPercent: 25, ProcessLimit: 64}); err == nil {
				t.Fatal("unsafe cache account accepted")
			}
			if len(runner.calls) != 0 {
				t.Fatalf("unsafe identity changed host services: %v", runner.calls)
			}
			if _, err := os.Stat(configRoot); !os.IsNotExist(err) {
				t.Fatalf("unsafe identity wrote configuration: %v", err)
			}
		})
	}
}

func TestValkeyStartupPreservesSystemUIDTenantAndDeduplicatesGrants(t *testing.T) {
	root := t.TempDir()
	for _, id := range []int64{12, 13} {
		unit := renderValkeyUnit(types.EnsureValkeyReq{SubscriptionID: id}, "997", "982", "/etc/nakpanel/valkey/sub-12", "/run/nakpanel/valkey/sub-12", "image")
		if err := os.WriteFile(filepath.Join(root, "nakpanel-valkey@"+strconv.FormatInt(id, 10)+".service"), []byte(unit), 0644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &callRunner{}
	if err := restoreValkeyRuntimeAccess(context.Background(), root, root, uint32(os.Geteuid()), runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != "setfacl -m u:997:--x "+root {
		t.Fatalf("system UID grant=%v", runner.calls)
	}
}
