package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// Snapshot actual files, not the previous Git tree: a failed publication must
// restore local edits and pre-existing untracked files as well as committed code.
func (p *HostingToolkitProvisioner) snapshotGitDeployment(ctx context.Context, username, repository, target, current, revision string) (func() error, func(), error) {
	old, err := p.gitTree(ctx, username, repository, current)
	if err != nil {
		return nil, nil, err
	}
	next, err := p.gitTree(ctx, username, repository, revision)
	if err != nil {
		return nil, nil, err
	}
	paths := map[string]bool{}
	for path := range old {
		paths[path] = true
	}
	for path := range next {
		paths[path] = true
	}
	names := make([]string, 0, len(paths))
	for path := range paths {
		names = append(names, path)
	}
	sort.Strings(names)
	backup, err := os.MkdirTemp(p.gitRoot, ".git-recovery-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(backup) }
	if _, err := p.runner.Run(ctx, "chown", username+":"+username, backup); err != nil {
		cleanup()
		return nil, nil, err
	}
	type savedFile struct {
		path, backup string
		exists       bool
	}
	var files []savedFile
	var total int64
	for i, path := range names {
		destination := filepath.Join(target, path)
		if err := ensureNoSymlinkComponents(target, filepath.Dir(destination)); err != nil {
			cleanup()
			return nil, nil, err
		}
		info, err := os.Lstat(destination)
		entry := savedFile{path: destination, backup: filepath.Join(backup, strconv.Itoa(i))}
		if errors.Is(err, os.ErrNotExist) {
			files = append(files, entry)
			continue
		}
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		if !info.Mode().IsRegular() {
			cleanup()
			return nil, nil, errors.New("unsafe Git snapshot source")
		}
		total += info.Size()
		if total > 256<<20 {
			cleanup()
			return nil, nil, errors.New("Git recovery snapshot exceeds 256 MiB")
		}
		if _, err := p.runner.Run(ctx, "runuser", "-u", username, "--", "cp", "-p", "--", destination, entry.backup); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("snapshot Git deployment: %w", err)
		}
		entry.exists = true
		files = append(files, entry)
	}
	undo := func() error {
		recovery, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		var failures []error
		for _, file := range files {
			if err := ensureNoSymlinkComponents(target, filepath.Dir(file.path)); err != nil {
				failures = append(failures, err)
				continue
			}
			if _, err := p.runner.Run(recovery, "runuser", "-u", username, "--", "rm", "-f", "--", file.path); err != nil {
				failures = append(failures, err)
				continue
			}
			if file.exists {
				if _, err := p.runner.Run(recovery, "runuser", "-u", username, "--", "cp", "-p", "--", file.backup, file.path); err != nil {
					failures = append(failures, err)
				}
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("Git recovery incomplete; snapshot retained at %s: %w", backup, errors.Join(failures...))
		}
		return nil
	}
	return undo, cleanup, nil
}
