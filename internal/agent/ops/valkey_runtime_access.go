package ops

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// RestoreValkeyRuntimeAccess restores the traversal-only grants lost when /run
// is recreated. Persisted root-managed cache units are the authority; neither
// usernames supplied over RPC nor tenant-writable files can authorize a grant.
// Call this after the agent creates its private socket parent, before serving RPC.
func (p *HostingToolkitProvisioner) RestoreValkeyRuntimeAccess(ctx context.Context) error {
	valkeyMutationMu.Lock()
	defer valkeyMutationMu.Unlock()
	return restoreValkeyRuntimeAccess(ctx, p.systemdUnitDir, filepath.Dir(p.valkeyRuntimeRoot), 0, p.runner)
}

func restoreValkeyRuntimeAccess(ctx context.Context, unitDir, runtimeParent string, ownerUID uint32, runner CommandRunner) error {
	entries, err := os.ReadDir(unitDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read persisted cache units: %w", err)
	}
	uids := map[uint32]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "nakpanel-valkey@") || !strings.HasSuffix(name, ".service") {
			continue
		}
		if err := validateValkeyManagedDirectory(unitDir, ownerUID); err != nil {
			return err
		}
		rawID := strings.TrimSuffix(strings.TrimPrefix(name, "nakpanel-valkey@"), ".service")
		id, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != rawID {
			return fmt.Errorf("invalid persisted cache unit identity %q", name)
		}
		file, err := os.OpenFile(filepath.Join(unitDir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("open persisted cache unit %s: %w", name, err)
		}
		data, err := readValkeyManagedUnit(file, ownerUID)
		closeErr := file.Close()
		if err != nil {
			return fmt.Errorf("inspect persisted cache unit %s: %w", name, err)
		}
		if closeErr != nil {
			return closeErr
		}
		uid, err := valkeyUnitTenantUID(data, id)
		if err != nil {
			return fmt.Errorf("inspect persisted cache unit %s: %w", name, err)
		}
		uids[uid] = true
	}
	if len(uids) == 0 {
		return nil
	}
	// Validate the complete inventory before changing a single ACL. This grant is
	// deliberately confined to the shared parent: agent.sock, the tenant runtime
	// leaf, and credential files keep their existing ownership and permissions.
	if err := validateValkeyManagedDirectory(runtimeParent, ownerUID); err != nil {
		return err
	}
	sorted := make([]uint32, 0, len(uids))
	for uid := range uids {
		sorted = append(sorted, uid)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	grants := make([]string, 0, len(sorted))
	for _, uid := range sorted {
		grants = append(grants, "u:"+strconv.FormatUint(uint64(uid), 10)+":--x")
	}
	output, err := runner.Run(ctx, "setfacl", "-m", strings.Join(grants, ","), runtimeParent)
	if err != nil {
		return fmt.Errorf("restore subscription cache traversal: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func validateValkeyManagedDirectory(path string, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect cache managed directory %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0022 != 0 || !ok || stat.Uid != ownerUID {
		return fmt.Errorf("cache managed directory %s must be root-owned without symlinks or group/world write access", path)
	}
	return nil
}

func readValkeyManagedUnit(file *os.File, ownerUID uint32) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !ok || stat.Uid != ownerUID {
		return nil, fmt.Errorf("cache unit must be a root-owned regular file without group/world write access")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, fmt.Errorf("cache unit exceeds size limit")
	}
	return data, nil
}

func valkeyUnitTenantUID(data []byte, id int64) (uint32, error) {
	values := map[string]string{}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Service]" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		switch key {
		case "Group", "User", "RuntimeDirectory", "ExecStart":
			if !ok {
				return 0, fmt.Errorf("malformed cache unit directive")
			}
			if _, exists := values[key]; exists {
				return 0, fmt.Errorf("ambiguous cache unit directive %s", key)
			}
			values[key] = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if values["RuntimeDirectory"] != fmt.Sprintf("nakpanel/valkey/sub-%d", id) {
		return 0, fmt.Errorf("cache runtime directory does not match subscription")
	}
	if value := values["User"]; value != "" && value != "root" && value != "0" {
		return 0, fmt.Errorf("cache controller must run as root")
	}
	args := strings.Fields(values["ExecStart"])
	if len(args) < 3 || args[0] != "/usr/bin/podman" || args[1] != "run" {
		return 0, fmt.Errorf("cache executable is not root-managed Podman")
	}
	pair, name := "", ""
	for index := 2; index < len(args); index++ {
		switch args[index] {
		case "--user":
			if pair != "" || index+1 >= len(args) {
				return 0, fmt.Errorf("ambiguous cache tenant identity")
			}
			index++
			pair = args[index]
		case "--name":
			if name != "" || index+1 >= len(args) {
				return 0, fmt.Errorf("ambiguous cache container identity")
			}
			index++
			name = args[index]
		}
	}
	if name != fmt.Sprintf("nakpanel-valkey-sub-%d", id) {
		return 0, fmt.Errorf("cache container does not match subscription")
	}
	rawUID, rawGID, ok := strings.Cut(pair, ":")
	if !ok {
		return 0, fmt.Errorf("cache tenant must have numeric UID and GID")
	}
	uid, err := valkeyTenantID(rawUID)
	if err != nil {
		return 0, err
	}
	if _, err := valkeyTenantID(rawGID); err != nil {
		return 0, err
	}
	if values["Group"] != rawGID {
		return 0, fmt.Errorf("cache runtime group differs from container tenant group")
	}
	return uid, nil
}

func valkeyTenantID(raw string) (uint32, error) {
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || value == 0 || value == uint64(^uint32(0)) || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("cache tenant must use a non-root numeric identity")
	}
	return uint32(value), nil
}

// A shared dependency gives PID 1 ownership of the rootful runtime directories.
// Unlike optional ReadWritePaths entries, RuntimeDirectory creates absent paths
// before the consuming cache service receives its read-only filesystem sandbox.
func renderValkeyPodmanRuntimeUnit() string {
	return `[Unit]
Description=Nakpanel rootful container runtime directories

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
RuntimeDirectory=containers libpod crun
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ExecStart=/usr/bin/true
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run/containers /run/libpod /run/crun
`
}
