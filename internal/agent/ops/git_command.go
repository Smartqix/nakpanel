package ops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

func readGitState(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid Git state file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("Git state file exceeds size limit")
	}
	return data, err
}

type gitOutputBuffer struct {
	sync.Mutex
	bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

func (b *gitOutputBuffer) Write(data []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	const limit = 8 << 20
	if b.Len()+len(data) > limit {
		remaining := limit - b.Len()
		if remaining > 0 {
			_, _ = b.Buffer.Write(data[:remaining])
		}
		b.exceeded = true
		b.cancel()
		return len(data), nil
	}
	return b.Buffer.Write(data)
}

// Production Git subprocesses have a wall-clock and output cap; test runners
// remain injectable. Kill the process group so transport children cannot linger.
func (p *HostingToolkitProvisioner) runBoundedGit(ctx context.Context, name string, args ...string) ([]byte, error) {
	switch p.runner.(type) {
	case ExecRunner, *ExecRunner:
	default:
		return p.runner.Run(ctx, name, args...)
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	output := &gitOutputBuffer{cancel: cancel}
	cmd := exec.CommandContext(bounded, name, args...)
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if output.exceeded {
		err = errors.Join(err, errors.New("Git command output exceeds 8 MiB"))
	}
	return output.Bytes(), err
}

// RLIMIT_FSIZE bounds each incoming pack to 512 MiB and RLIMIT_AS bounds Git
// memory to 1 GiB. Repository storage also remains charged to the site UID.
func (p *HostingToolkitProvisioner) runGitTransport(ctx context.Context, args ...string) ([]byte, error) {
	switch p.runner.(type) {
	case ExecRunner, *ExecRunner:
		limited := append([]string{}, args[:3]...)
		limited = append(limited, "prlimit", "--fsize=536870912", "--as=1073741824", "--nofile=256", "--")
		limited = append(limited, args[3:]...)
		return p.runBoundedGit(ctx, "runuser", limited...)
	default:
		return p.runBoundedGit(ctx, "runuser", args...)
	}
}
