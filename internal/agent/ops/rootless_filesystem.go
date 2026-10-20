//go:build linux || darwin

package ops

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type rootlessDirectoryRole uint8

const (
	rootlessAncestor rootlessDirectoryRole = iota
	rootlessManaged
	rootlessPrivate
	rootlessStickyTemporary
)

type rootlessDirectory struct {
	fd     int
	parent *rootlessDirectory
	name   string
	role   rootlessDirectoryRole
	uid    int
	gid    int
}

type rootlessOwner struct{ uid, gid int }

type rootlessFilesystem struct {
	directories   []*rootlessDirectory
	panelOwner    *rootlessOwner
	syncDirectory func(int) error
}

// Preparations can share a subscription's config and private leaves. Serialize
// their descriptor-bound publication so legitimate concurrent jobs cannot
// replace another preparation's just-verified objects.
var rootlessFilesystemMu sync.Mutex

// Only the default container store crosses the installed panel account's
// directory. Its ownership is trusted by exact account identity, never adopted
// or changed, and never inferred from another configured path's owner.
func rootlessPanelOwner(stateRoot string, lookupUser func(string) (*user.User, error), lookupGroup func(string) (*user.Group, error)) (*rootlessOwner, error) {
	if stateRoot != "/var/lib/nakpanel/containers" {
		return nil, nil
	}
	account, err := lookupUser("nakpanel")
	if err != nil {
		return nil, err
	}
	if account == nil || account.Username != "nakpanel" {
		return nil, errors.New("rootless panel ancestor requires the installed panel account")
	}
	group, err := lookupGroup("nakpanel")
	if err != nil {
		return nil, err
	}
	if group == nil || group.Name != "nakpanel" {
		return nil, errors.New("rootless panel ancestor requires the installed panel group")
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(group.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return nil, errors.New("rootless panel ancestor has an invalid account identity")
	}
	return &rootlessOwner{uid, gid}, nil
}

func (fs *rootlessFilesystem) ancestorOwner(path string) (int, int) {
	if path == "/var/lib/nakpanel" && fs.panelOwner != nil {
		return fs.panelOwner.uid, fs.panelOwner.gid
	}
	return 0, 0
}

func (fs *rootlessFilesystem) close() {
	for i := len(fs.directories) - 1; i >= 0; i-- {
		_ = unix.Close(fs.directories[i].fd)
	}
	fs.directories = nil
}

func validateRootlessDirectory(st *unix.Stat_t, role rootlessDirectoryRole, uid, gid int) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return errors.New("rootless path must be a real directory without special ownership modes")
	}
	if role == rootlessStickyTemporary {
		if st.Uid != 0 || st.Mode&unix.S_ISVTX == 0 || st.Mode&0o777 != 0o777 {
			return errors.New("rootless temporary boundary is not root-owned sticky1777")
		}
		return nil
	}
	if st.Mode&(0o022|unix.S_ISVTX) != 0 {
		return errors.New("rootless managed path is writable by another identity")
	}
	if role == rootlessAncestor {
		trustedPanel := uid > 0 && gid > 0 && int(st.Uid) == uid && int(st.Gid) == gid
		if st.Uid != 0 && int(st.Uid) != os.Geteuid() && !trustedPanel {
			return errors.New("rootless ancestor has an unexpected owner")
		}
	} else if int(st.Uid) != uid || int(st.Gid) != gid {
		return errors.New("rootless directory has an unexpected owner")
	}
	return nil
}

func (d *rootlessDirectory) verify() error {
	var opened unix.Stat_t
	if err := unix.Fstat(d.fd, &opened); err != nil {
		return err
	}
	if err := validateRootlessDirectory(&opened, d.role, d.uid, d.gid); err != nil {
		return err
	}
	if d.parent != nil {
		if err := d.parent.verify(); err != nil {
			return err
		}
		var named unix.Stat_t
		if err := unix.Fstatat(d.parent.fd, d.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if named.Dev != opened.Dev || named.Ino != opened.Ino || named.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("rootless directory changed during preparation")
		}
	}
	return nil
}

// Only OS-owned Darwin top-level aliases are accepted. Tenant-controlled
// symlinks anywhere below these aliases remain forbidden.
func rootlessCanonicalPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return "", errors.New("rootless managed path must be an absolute non-root directory")
	}
	if runtime.GOOS == "darwin" {
		first := strings.Split(strings.TrimPrefix(path, "/"), "/")[0]
		if first == "var" || first == "tmp" || first == "etc" {
			alias := "/" + first
			info, err := os.Lstat(alias)
			if err != nil {
				return "", err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(alias)
				if err != nil || !ownedBy(info, 0) || filepath.Clean(filepath.Join("/", link)) != "/private/"+first {
					return "", errors.New("untrusted rootless OS path alias")
				}
				path = "/private" + path
			}
		}
	}
	return path, nil
}

func rootlessTemporaryBoundary(path string) bool {
	switch path {
	case "/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp":
		return true
	}
	return false
}

func (fs *rootlessFilesystem) path(path string, role rootlessDirectoryRole, uid, gid int, create bool) (*rootlessDirectory, error) {
	path, err := rootlessCanonicalPath(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := &rootlessDirectory{fd: fd, role: rootlessAncestor}
	fs.directories = append(fs.directories, current)
	if err := current.verify(); err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	currentPath := ""
	needsPrivateAnchor := false
	for index, component := range components {
		currentPath += "/" + component
		last := index == len(components)-1
		childRole, childUID, childGID := rootlessAncestor, 0, 0
		if last {
			childRole, childUID, childGID = role, uid, gid
		} else {
			childUID, childGID = fs.ancestorOwner(currentPath)
		}
		var st unix.Stat_t
		err := unix.Fstatat(current.fd, component, &st, unix.AT_SYMLINK_NOFOLLOW)
		missing := errors.Is(err, unix.ENOENT)
		if err != nil && !missing {
			return nil, err
		}
		if missing {
			if currentPath == "/var/lib/nakpanel" && fs.panelOwner != nil {
				return nil, errors.New("installed rootless panel ancestor is missing")
			}
			if !create || needsPrivateAnchor {
				return nil, errors.New("rootless creation requires a verified private or managed anchor")
			}
			childRole, childUID, childGID = rootlessManaged, os.Geteuid(), os.Getegid()
			if last {
				childRole, childUID, childGID = role, uid, gid
			}
		} else if !last && rootlessTemporaryBoundary(currentPath) && st.Mode&unix.S_ISVTX != 0 {
			childRole = rootlessStickyTemporary
			needsPrivateAnchor = true
		}
		if !missing && int(st.Uid) == os.Geteuid() && st.Mode&0o077 == 0 && (!last || role == rootlessPrivate) {
			needsPrivateAnchor = false
		}
		if last && needsPrivateAnchor {
			return nil, errors.New("rootless temporary path lacks a manager-owned private anchor")
		}
		current, err = fs.child(current, component, childRole, childUID, childGID, missing)
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (fs *rootlessFilesystem) child(parent *rootlessDirectory, name string, role rootlessDirectoryRole, uid, gid int, create bool) (result *rootlessDirectory, resultErr error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("unsafe rootless path component")
	}
	if err := parent.verify(); err != nil {
		return nil, err
	}
	created := false
	if create {
		if err := unix.Mkdirat(parent.fd, name, 0o700); err != nil {
			return nil, err
		}
		created = true
		var made unix.Stat_t
		if err := unix.Fstatat(parent.fd, name, &made, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		defer func() {
			if resultErr != nil {
				removeRootlessCreatedDirectory(parent.fd, name, &made)
			}
		}()
	}
	fd, err := unix.Openat(parent.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	node := &rootlessDirectory{fd: fd, parent: parent, name: name, role: role, uid: uid, gid: gid}
	fs.directories = append(fs.directories, node)
	if created {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if err := validateRootlessDirectory(&st, rootlessManaged, os.Geteuid(), os.Getegid()); err != nil {
			return nil, err
		}
		if os.Geteuid() == 0 && role == rootlessPrivate {
			if err := unix.Fchown(fd, uid, gid); err != nil {
				return nil, err
			}
		}
	}
	if err := node.verify(); err != nil {
		return nil, err
	}
	if role == rootlessManaged || role == rootlessPrivate {
		mode := uint32(0o711)
		if role == rootlessPrivate {
			mode = 0o700
		}
		if err := unix.Fchmod(fd, mode); err != nil {
			return nil, err
		}
	}
	return node, node.verify()
}

// A failed open must not leave a freshly created staging directory behind.
// Never remove a preexisting object, replacement inode, symlink or contents.
func removeRootlessCreatedDirectory(parentFD int, name string, made *unix.Stat_t) {
	var current unix.Stat_t
	if unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		current.Dev == made.Dev && current.Ino == made.Ino && current.Mode&unix.S_IFMT == unix.S_IFDIR {
		_ = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
	}
}

func prepareRootlessFilesystem(stateRoot, runtimeRoot string, identity applicationIdentity, content []byte) error {
	rootlessFilesystemMu.Lock()
	defer rootlessFilesystemMu.Unlock()
	panelOwner, err := rootlessPanelOwner(stateRoot, user.Lookup, user.LookupGroup)
	if err != nil {
		return err
	}
	fs := &rootlessFilesystem{panelOwner: panelOwner}
	defer fs.close()
	state, err := fs.path(stateRoot, rootlessManaged, os.Geteuid(), os.Getegid(), true)
	if err != nil {
		return err
	}
	baseName := filepath.Base(filepath.Dir(identity.stateHome))
	base, err := fs.managedChild(state, baseName)
	if err != nil {
		return err
	}
	for _, name := range []string{"home", "data"} {
		if _, err := fs.privateChild(base, base, name, identity.uid, identity.gid); err != nil {
			return err
		}
	}
	config, err := fs.privateChild(base, base, "config", identity.uid, identity.gid)
	if err != nil {
		return err
	}
	runtimeDir, err := fs.path(runtimeRoot, rootlessManaged, os.Geteuid(), os.Getegid(), true)
	if err != nil {
		return err
	}
	if _, err := fs.privateChild(runtimeDir, runtimeDir, filepath.Base(identity.runtimeHome), identity.uid, identity.gid); err != nil {
		return err
	}
	if err := fs.writeConfig(config, base, identity, content); err != nil {
		return err
	}
	return fs.verify()
}

func (fs *rootlessFilesystem) managedChild(parent *rootlessDirectory, name string) (*rootlessDirectory, error) {
	var st unix.Stat_t
	err := unix.Fstatat(parent.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	return fs.child(parent, name, rootlessManaged, os.Geteuid(), os.Getegid(), errors.Is(err, unix.ENOENT))
}

func rootlessTemporaryName() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return ".nakpanel-rootless-" + hex.EncodeToString(value[:]), nil
}

func (fs *rootlessFilesystem) privateChild(parent, staging *rootlessDirectory, name string, uid, gid int) (*rootlessDirectory, error) {
	var st unix.Stat_t
	err := unix.Fstatat(parent.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return fs.child(parent, name, rootlessPrivate, uid, gid, false)
	}
	if !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	// Create/chown under a manager-owned anchor, never inside a tenant-owned
	// parent where a different preexisting directory could replace a new child.
	if err := staging.verify(); err != nil {
		return nil, err
	}
	var stageInfo unix.Stat_t
	if err := unix.Fstat(staging.fd, &stageInfo); err != nil {
		return nil, err
	}
	if int(stageInfo.Uid) != os.Geteuid() || stageInfo.Mode&0o022 != 0 {
		return nil, errors.New("rootless staging anchor is not manager-owned")
	}
	temporary, err := rootlessTemporaryName()
	if err != nil {
		return nil, err
	}
	node, err := fs.child(staging, temporary, rootlessPrivate, uid, gid, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Unlinkat(staging.fd, temporary, unix.AT_REMOVEDIR) }()
	if err := parent.verify(); err != nil {
		return nil, err
	}
	if err := node.verify(); err != nil {
		return nil, err
	}
	if err := rootlessRenameDirectory(staging.fd, temporary, parent.fd, name); err != nil {
		return nil, err
	}
	node.parent, node.name = parent, name
	return node, node.verify()
}

func writeExistingRootlessConfig(identity applicationIdentity, content []byte) error {
	rootlessFilesystemMu.Lock()
	defer rootlessFilesystemMu.Unlock()
	panelOwner, err := rootlessPanelOwner(filepath.Dir(filepath.Dir(identity.configHome)), user.Lookup, user.LookupGroup)
	if err != nil {
		return err
	}
	fs := &rootlessFilesystem{panelOwner: panelOwner}
	defer fs.close()
	config, err := fs.path(identity.configHome, rootlessPrivate, identity.uid, identity.gid, false)
	if err != nil {
		return err
	}
	if identity.uid != os.Geteuid() {
		return errors.New("rootless config requires its verified managed staging anchor")
	}
	if err := fs.writeConfig(config, config, identity, content); err != nil {
		return err
	}
	return fs.verify()
}

func (fs *rootlessFilesystem) verify() error {
	for _, directory := range fs.directories {
		if err := directory.verify(); err != nil {
			return err
		}
	}
	return nil
}

func (fs *rootlessFilesystem) writeConfig(config, staging *rootlessDirectory, identity applicationIdentity, content []byte) error {
	directory, err := fs.privateChild(config, staging, "containers", identity.uid, identity.gid)
	if err != nil {
		return err
	}
	var existing unix.Stat_t
	err = unix.Fstatat(directory.fd, "containers.conf", &existing, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err == nil && (existing.Mode&unix.S_IFMT != unix.S_IFREG || existing.Nlink != 1 || int(existing.Uid) != identity.uid || int(existing.Gid) != identity.gid) {
		return errors.New("rootless config file has an unsafe type or owner")
	}
	temporary, err := rootlessTemporaryName()
	if err != nil {
		return err
	}
	if err := staging.verify(); err != nil {
		return err
	}
	var stageInfo unix.Stat_t
	if err := unix.Fstat(staging.fd, &stageInfo); err != nil {
		return err
	}
	if int(stageInfo.Uid) != os.Geteuid() || stageInfo.Mode&0o022 != 0 {
		return errors.New("rootless config staging anchor is not manager-owned")
	}
	fd, err := unix.Openat(staging.fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	defer func() { _ = unix.Unlinkat(staging.fd, temporary, 0) }()
	if os.Geteuid() == 0 {
		if err := file.Chown(identity.uid, identity.gid); err != nil {
			return err
		}
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := fs.verify(); err != nil {
		return err
	}
	var prepared, staged unix.Stat_t
	if err := unix.Fstat(fd, &prepared); err != nil {
		return err
	}
	if err := unix.Fstatat(staging.fd, temporary, &staged, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if prepared.Dev != staged.Dev || prepared.Ino != staged.Ino || staged.Mode&unix.S_IFMT != unix.S_IFREG || staged.Nlink != 1 {
		return errors.New("rootless config staging file changed")
	}
	if err := unix.Renameat(staging.fd, temporary, directory.fd, "containers.conf"); err != nil {
		return err
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(directory.fd, "containers.conf", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG || named.Nlink != 1 || named.Mode&0o777 != 0o600 || int(named.Uid) != identity.uid || int(named.Gid) != identity.gid {
		return errors.New("rootless config changed during preparation")
	}
	if err := fs.syncPublishedDirectory(directory); err != nil {
		return err
	}
	if staging.fd != directory.fd {
		if err := fs.syncPublishedDirectory(staging); err != nil {
			return err
		}
	}
	return fs.verify()
}

func (fs *rootlessFilesystem) syncPublishedDirectory(directory *rootlessDirectory) error {
	if err := directory.verify(); err != nil {
		return err
	}
	if fs.syncDirectory != nil {
		return fs.syncDirectory(directory.fd)
	}
	return unix.Fsync(directory.fd)
}
