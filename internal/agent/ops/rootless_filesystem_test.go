//go:build linux || darwin

package ops

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRootlessDirectoryMetadataRefusesForeignOwnersAndWritableNamespaces(t *testing.T) {
	valid := unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())}
	for _, role := range []rootlessDirectoryRole{rootlessManaged, rootlessPrivate} {
		if err := validateRootlessDirectory(&valid, role, os.Geteuid(), os.Getegid()); err != nil {
			t.Fatal(err)
		}
		foreign := valid
		foreign.Uid++
		if err := validateRootlessDirectory(&foreign, role, os.Geteuid(), os.Getegid()); err == nil {
			t.Fatal("foreign existing directory owner accepted")
		}
		foreign = valid
		foreign.Gid++
		if err := validateRootlessDirectory(&foreign, role, os.Geteuid(), os.Getegid()); err == nil {
			t.Fatal("foreign existing directory group accepted")
		}
		writable := valid
		writable.Mode |= 0o022
		if err := validateRootlessDirectory(&writable, role, os.Geteuid(), os.Getegid()); err == nil {
			t.Fatal("group/world writable directory accepted")
		}
	}
	sticky := unix.Stat_t{Mode: unix.S_IFDIR | unix.S_ISVTX | 0o777, Uid: 0, Gid: 0}
	if err := validateRootlessDirectory(&sticky, rootlessStickyTemporary, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := validateRootlessDirectory(&sticky, rootlessManaged, 0, 0); err == nil {
		t.Fatal("sticky temporary boundary accepted as a managed mutation target")
	}
	sticky.Uid++
	if err := validateRootlessDirectory(&sticky, rootlessStickyTemporary, 0, 0); err == nil {
		t.Fatal("non-root sticky boundary accepted")
	}
}

func TestRootlessInstalledPanelAncestorMetadata(t *testing.T) {
	// The original L1v3 snapshot has a panel-owned0755 ancestor and a
	// root-owned0700 subscription namespace, followed by private tenant leaves.
	for _, panel := range []unix.Stat_t{{Mode: unix.S_IFDIR | 0o755, Uid: 999, Gid: 988}, {Mode: unix.S_IFDIR | 0o750, Uid: 999, Gid: 988}} {
		if err := validateRootlessDirectory(&panel, rootlessAncestor, 999, 988); err != nil {
			t.Fatalf("installed panel ancestor%04o refused: %v", panel.Mode&0o777, err)
		}
		for _, mutate := range []func(*unix.Stat_t){
			func(st *unix.Stat_t) { st.Uid = 997 },
			func(st *unix.Stat_t) { st.Gid = 987 },
			func(st *unix.Stat_t) { st.Mode |= 0o020 },
			func(st *unix.Stat_t) { st.Mode |= unix.S_ISGID },
		} {
			unsafe := panel
			mutate(&unsafe)
			if err := validateRootlessDirectory(&unsafe, rootlessAncestor, 999, 988); err == nil {
				t.Fatalf("unsafe panel ancestor accepted: %+v", unsafe)
			}
		}
		if err := validateRootlessDirectory(&panel, rootlessAncestor, 0, 0); err == nil {
			t.Fatal("panel owner implicitly trusted without an exact configured identity")
		}
	}
	leaf := unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: 994, Gid: 985}
	if err := validateRootlessDirectory(&leaf, rootlessPrivate, 994, 985); err != nil {
		t.Fatalf("original tenant private leaf refused: %v", err)
	}
	if err := validateRootlessDirectory(&leaf, rootlessManaged, 0, 0); err == nil {
		t.Fatal("tenant-owned namespace adopted as manager-owned")
	}
}

func TestRootlessPanelAncestorTrustIsBoundToDefaultPathAndAccount(t *testing.T) {
	lookups := 0
	lookup := func(name string) (*user.User, error) {
		lookups++
		if name != "nakpanel" {
			t.Fatalf("unexpected account lookup: %q", name)
		}
		return &user.User{Username: "nakpanel", Uid: "999", Gid: "988"}, nil
	}
	lookupGroup := func(name string) (*user.Group, error) {
		if name != "nakpanel" {
			t.Fatalf("unexpected group lookup: %q", name)
		}
		return &user.Group{Name: "nakpanel", Gid: "988"}, nil
	}
	for _, path := range []string{"/var/lib/foreign/containers", "/var/lib/nakpanel", "/var/lib/nakpanel/containers/../containers", "/tmp/containers"} {
		owner, err := rootlessPanelOwner(path, lookup, lookupGroup)
		if err != nil || owner != nil || lookups != 0 {
			t.Fatalf("custom path obtained panel trust: %q, %+v, %v", path, owner, err)
		}
	}
	owner, err := rootlessPanelOwner("/var/lib/nakpanel/containers", lookup, lookupGroup)
	if err != nil || owner == nil || owner.uid != 999 || owner.gid != 988 || lookups != 1 {
		t.Fatalf("installed account identity not resolved exactly: %+v, %v", owner, err)
	}
	fs := &rootlessFilesystem{panelOwner: owner}
	for _, path := range []string{"/var/lib/nakpanel-other", "/var/lib/nakpanel/containers", "/tmp/nakpanel", "/var/lib/foreign"} {
		if uid, gid := fs.ancestorOwner(path); uid != 0 || gid != 0 {
			t.Fatalf("panel trust escaped exact ancestor: %q", path)
		}
	}
	if uid, gid := fs.ancestorOwner("/var/lib/nakpanel"); uid != 999 || gid != 988 {
		t.Fatal("exact panel ancestor lost its trusted identity")
	}
	for _, account := range []*user.User{nil, {Username: "other", Uid: "999", Gid: "988"}, {Username: "nakpanel", Uid: "bad", Gid: "988"}, {Username: "nakpanel", Uid: "0", Gid: "988"}} {
		if _, err := rootlessPanelOwner("/var/lib/nakpanel/containers", func(string) (*user.User, error) { return account, nil }, lookupGroup); err == nil {
			t.Fatalf("untrusted panel lookup accepted: %+v", account)
		}
	}
	if _, err := rootlessPanelOwner("/var/lib/nakpanel/containers", func(string) (*user.User, error) { return nil, errors.New("lookup refused") }, lookupGroup); err == nil {
		t.Fatal("panel lookup failure ignored")
	}
	for _, group := range []*user.Group{nil, {Name: "other", Gid: "988"}, {Name: "nakpanel", Gid: "bad"}, {Name: "nakpanel", Gid: "0"}} {
		if _, err := rootlessPanelOwner("/var/lib/nakpanel/containers", lookup, func(string) (*user.Group, error) { return group, nil }); err == nil {
			t.Fatalf("untrusted panel group accepted: %+v", group)
		}
	}
	if _, err := rootlessPanelOwner("/var/lib/nakpanel/containers", lookup, func(string) (*user.Group, error) { return nil, errors.New("group lookup refused") }); err == nil {
		t.Fatal("panel group lookup failure ignored")
	}
}

func TestRootlessFilesystemClosesAllAnchorsOnSuccessAndRefusal(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "refusal"}[refuse], func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "state")
			fs := &rootlessFilesystem{}
			defer fs.close()
			node, err := fs.path(state, rootlessManaged, os.Geteuid(), os.Getegid(), true)
			if err != nil {
				t.Fatal(err)
			}
			if refuse {
				outside := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(state, "sub-7")); err != nil {
					t.Fatal(err)
				}
				if _, err := fs.managedChild(node, "sub-7"); err == nil {
					t.Fatal("nofollow open of a symlink succeeded")
				}
			}
			opened := append([]*rootlessDirectory(nil), fs.directories...)
			fs.close()
			for _, directory := range opened {
				if _, err := unix.FcntlInt(uintptr(directory.fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					t.Fatalf("anchor fd%d remained open: %v", directory.fd, err)
				}
			}
			if len(fs.directories) != 0 {
				t.Fatal("closed anchors retained for an unsafe second close")
			}
		})
	}
}

func TestRootlessNamespaceDoesNotChmodSharedTemporaryBoundary(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "nakpanel-rootless-unanchored-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(root)
	before, err := os.Stat("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	fs := &rootlessFilesystem{}
	defer fs.close()
	if _, err := fs.path(root, rootlessManaged, os.Geteuid(), os.Getegid(), true); err == nil {
		t.Fatal("managed mutation directly under shared temporary boundary accepted without a private ancestor")
	}
	after, err := os.Stat("/tmp")
	if err != nil || before.Mode() != after.Mode() {
		t.Fatalf("shared temporary boundary changed: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("untrusted target was changed: %v, %v", info, err)
	}
}

func TestRootlessConfigRejectsRenamedVerifiedDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config")
	if err := os.Mkdir(config, 0o700); err != nil {
		t.Fatal(err)
	}
	fs := &rootlessFilesystem{}
	defer fs.close()
	node, err := fs.path(config, rootlessPrivate, os.Geteuid(), os.Getegid(), false)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "containers.conf")
	if err := os.WriteFile(sentinel, []byte("outside-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(config, config+"-previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, config); err != nil {
		t.Fatal(err)
	}
	identity := applicationIdentity{uid: os.Geteuid(), gid: os.Getegid(), configHome: config}
	if err := fs.writeConfig(node, node, identity, []byte("must-not-write")); err == nil {
		t.Fatal("renamed verified directory accepted")
	}
	value, err := os.ReadFile(sentinel)
	if err != nil || string(value) != "outside-sentinel" {
		t.Fatalf("outside sentinel changed: %q, %v", value, err)
	}
}

func rootlessResourceTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRootlessCreatedDirectoryCleanupRefusesReplacementAndPreexistingObject(t *testing.T) {
	root := rootlessResourceTestRoot(t)
	fs := &rootlessFilesystem{}
	defer fs.close()
	parent, err := fs.path(filepath.Join(root, "parent"), rootlessManaged, os.Geteuid(), os.Getegid(), true)
	if err != nil {
		t.Fatal(err)
	}
	name := "created"
	path := filepath.Join(root, "parent", name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	var made unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &made, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(path, "sentinel")
	if err := os.WriteFile(sentinel, []byte("replacement-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeRootlessCreatedDirectory(parent.fd, name, &made)
	if _, err := fs.child(parent, name, rootlessPrivate, os.Geteuid(), os.Getegid(), true); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("exclusive creation did not refuse preexisting object: %v", err)
	}
	raw, err := os.ReadFile(sentinel)
	if err != nil || string(raw) != "replacement-sentinel" {
		t.Fatalf("replacement/preexisting object changed: %q, %v", raw, err)
	}
	if err := os.Remove(sentinel); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	removeRootlessCreatedDirectory(parent.fd, name, &made)
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("replacement symlink changed: %v", err)
	}
}

func TestRootlessConfigSyncsPublishedDirectoriesAndPropagatesFailure(t *testing.T) {
	for _, fail := range []string{"none", "destination", "staging"} {
		t.Run(fail, func(t *testing.T) {
			p, req, _ := freshStoppedRootlessIdentityFixture(t, &applicationRuntimeTestRunner{})
			identity, err := p.prepareRootlessIdentity(req, false)
			if err != nil {
				t.Fatal(err)
			}
			fs := &rootlessFilesystem{}
			defer fs.close()
			config, err := fs.path(identity.configHome, rootlessPrivate, identity.uid, identity.gid, false)
			if err != nil {
				t.Fatal(err)
			}
			stagePath := filepath.Dir(identity.configHome)
			staging, err := fs.path(stagePath, rootlessManaged, os.Geteuid(), os.Getegid(), false)
			if err != nil {
				t.Fatal(err)
			}
			paths := []string{filepath.Join(identity.configHome, "containers"), stagePath}
			calls := 0
			content := "durable-config-replacement"
			fs.syncDirectory = func(fd int) error {
				if calls >= len(paths) {
					t.Fatal("unexpected extra directory sync")
				}
				var actual, expected unix.Stat_t
				if err := unix.Fstat(fd, &actual); err != nil {
					t.Fatal(err)
				}
				if err := unix.Stat(paths[calls], &expected); err != nil {
					t.Fatal(err)
				}
				if actual.Dev != expected.Dev || actual.Ino != expected.Ino || actual.Mode&unix.S_IFMT != unix.S_IFDIR {
					t.Fatal("sync did not use expected held directory")
				}
				raw, err := os.ReadFile(filepath.Join(paths[0], "containers.conf"))
				if err != nil || string(raw) != content {
					t.Fatalf("directory sync preceded actual config publication: %q, %v", raw, err)
				}
				index := calls
				calls++
				if (fail == "destination" && index == 0) || (fail == "staging" && index == 1) {
					return unix.EIO
				}
				return unix.Fsync(fd)
			}
			err = fs.writeConfig(config, staging, identity, []byte(content))
			wantCalls := 2
			if fail == "destination" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("directory sync calls=%d, want%d", calls, wantCalls)
			}
			if fail == "none" && err != nil {
				t.Fatal(err)
			}
			if fail != "none" && !errors.Is(err, unix.EIO) {
				t.Fatalf("directory sync failure not propagated: %v", err)
			}
		})
	}
}

func TestRootlessPrivateCreationDoesNotLeakOnEMFILE(t *testing.T) {
	if os.Getenv("NAKPANEL_ROOTLESS_EMFILE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRootlessPrivateCreationDoesNotLeakOnEMFILE$", "-test.v")
		cmd.Env = append(os.Environ(), "NAKPANEL_ROOTLESS_EMFILE_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Logf("owned resource child:\n%s", out)
		if err != nil {
			t.Fatalf("resource child failed: %v", err)
		}
		return
	}
	root := rootlessResourceTestRoot(t)
	fs := &rootlessFilesystem{}
	defer fs.close()
	staging, err := fs.path(filepath.Join(root, "staging"), rootlessManaged, os.Geteuid(), os.Getegid(), true)
	if err != nil {
		t.Fatal(err)
	}
	// Initialize Go's entropy watchdog/timer runtime before exhausting FDs.
	if _, err := rootlessTemporaryName(); err != nil {
		t.Fatal(err)
	}
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	if limited.Cur > 64 {
		limited.Cur = 64
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	fillers := []int{}
	for {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
		if err != nil {
			if !errors.Is(err, unix.EMFILE) {
				t.Fatal(err)
			}
			break
		}
		fillers = append(fillers, fd)
	}
	_, captureErr := fs.privateChild(staging, staging, "tenant-child", os.Geteuid(), os.Getegid())
	for _, fd := range fillers {
		_ = unix.Close(fd)
	}
	_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &original)
	if !errors.Is(captureErr, unix.EMFILE) {
		t.Fatalf("expected owned FD exhaustion, got %v", captureErr)
	}
	entries, err := os.ReadDir(filepath.Join(root, "staging"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".nakpanel-rootless-") {
			t.Fatalf("failed private creation leaked owned temporary directory %s", entry.Name())
		}
	}
}
