package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sftpSettings struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
	User string `json:"username"`
	// HostKey pins the server host key as an OpenSSH SHA256 fingerprint
	// ("SHA256:..."). When empty the first observed key is accepted and
	// reported so the operator can pin it.
	HostKey string `json:"host_key"`
}

type sftpCredential struct {
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Password   string `json:"password,omitempty"`
}

type sftpDestination struct {
	settings sftpSettings
	creds    sftpCredential

	observedHostKey string
}

func newSFTPDestination(settings json.RawMessage, credential []byte) (Destination, error) {
	var cfg sftpSettings
	dec := json.NewDecoder(bytes.NewReader(settings))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("backup: sftp settings: %w", err)
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("backup: sftp host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, errors.New("backup: sftp port is invalid")
	}
	if strings.TrimSpace(cfg.User) == "" {
		return nil, errors.New("backup: sftp username is required")
	}
	cfg.Path = strings.TrimSpace(cfg.Path)
	if cfg.Path == "" || !strings.HasPrefix(cfg.Path, "/") {
		return nil, errors.New("backup: sftp path must be absolute")
	}
	cfg.Path = path.Clean(cfg.Path)
	var creds sftpCredential
	credDec := json.NewDecoder(bytes.NewReader(credential))
	credDec.DisallowUnknownFields()
	if err := credDec.Decode(&creds); err != nil {
		return nil, fmt.Errorf("backup: sftp credential: %w", err)
	}
	if creds.PrivateKey == "" && creds.Password == "" {
		return nil, errors.New("backup: sftp credential requires private_key or password")
	}
	return &sftpDestination{settings: cfg, creds: creds}, nil
}

// ObservedHostKey returns the SHA256 fingerprint seen on the last connection,
// for surfacing through test-connection flows so operators can pin it.
func (d *sftpDestination) ObservedHostKey() string {
	return d.observedHostKey
}

func (d *sftpDestination) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if d.creds.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if d.creds.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(d.creds.PrivateKey), []byte(d.creds.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(d.creds.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("backup: sftp private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if d.creds.Password != "" {
		methods = append(methods, ssh.Password(d.creds.Password))
	}
	return methods, nil
}

func (d *sftpDestination) connect(ctx context.Context) (*ssh.Client, *sftp.Client, error) {
	methods, err := d.authMethods()
	if err != nil {
		return nil, nil, err
	}
	pinned := strings.TrimSpace(d.settings.HostKey)
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		d.observedHostKey = fingerprint
		if pinned == "" {
			return nil
		}
		if fingerprint != pinned {
			return fmt.Errorf("backup: sftp host key mismatch: got %s want %s", fingerprint, pinned)
		}
		return nil
	}
	config := &ssh.ClientConfig{
		User:            d.settings.User,
		Auth:            methods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}
	address := net.JoinHostPort(d.settings.Host, fmt.Sprintf("%d", d.settings.Port))
	dialer := net.Dialer{Timeout: config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	sshClient := ssh.NewClient(sshConn, chans, reqs)
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return nil, nil, err
	}
	return sshClient, sftpClient, nil
}

func (d *sftpDestination) withClient(ctx context.Context, fn func(*sftp.Client) error) error {
	sshClient, client, err := d.connect(ctx)
	if err != nil {
		return err
	}
	defer sshClient.Close()
	defer client.Close()
	return fn(client)
}

func (d *sftpDestination) remotePath(name string) string {
	return path.Join(d.settings.Path, name)
}

func (d *sftpDestination) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if err := validateObjectName(name); err != nil {
		return err
	}
	return d.withClient(ctx, func(client *sftp.Client) error {
		if err := client.MkdirAll(d.settings.Path); err != nil {
			return err
		}
		partPath := d.remotePath(name) + ".part"
		file, err := client.Create(partPath)
		if err != nil {
			return err
		}
		if _, err := io.Copy(file, r); err != nil {
			file.Close()
			_ = client.Remove(partPath)
			return err
		}
		if err := file.Close(); err != nil {
			_ = client.Remove(partPath)
			return err
		}
		final := d.remotePath(name)
		// PosixRename overwrites atomically, so the final name is never absent.
		// Only fall back to the non-atomic path (remove-then-rename) when the
		// server lacks the posix-rename extension.
		if err := client.PosixRename(partPath, final); err != nil {
			if removeErr := client.Remove(final); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				var status *sftp.StatusError
				if !errors.As(removeErr, &status) || status.FxCode() != sftp.ErrSSHFxNoSuchFile {
					_ = client.Remove(partPath)
					return fmt.Errorf("replace %s: %w", final, removeErr)
				}
			}
			if err := client.Rename(partPath, final); err != nil {
				_ = client.Remove(partPath)
				return err
			}
		}
		return nil
	})
}

func (d *sftpDestination) Open(ctx context.Context, name string) (io.ReadCloser, int64, error) {
	if err := validateObjectName(name); err != nil {
		return nil, 0, err
	}
	sshClient, client, err := d.connect(ctx)
	if err != nil {
		return nil, 0, err
	}
	file, err := client.Open(d.remotePath(name))
	if err != nil {
		client.Close()
		sshClient.Close()
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		client.Close()
		sshClient.Close()
		return nil, 0, err
	}
	return &sftpFile{file: file, client: client, ssh: sshClient}, info.Size(), nil
}

type sftpFile struct {
	file   *sftp.File
	client *sftp.Client
	ssh    *ssh.Client
}

func (f *sftpFile) Read(p []byte) (int, error) { return f.file.Read(p) }

func (f *sftpFile) Close() error {
	err := f.file.Close()
	f.client.Close()
	f.ssh.Close()
	return err
}

func (d *sftpDestination) List(ctx context.Context) ([]ObjectInfo, error) {
	var result []ObjectInfo
	err := d.withClient(ctx, func(client *sftp.Client) error {
		entries, err := client.ReadDir(d.settings.Path)
		if err != nil {
			// A destination that has never been written to has no directory
			// yet; that is an empty listing, not a failure.
			var status *sftp.StatusError
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrNotExist) ||
				(errors.As(err, &status) && status.FxCode() == sftp.ErrSSHFxNoSuchFile) {
				return nil
			}
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), ".part") {
				continue
			}
			result = append(result, ObjectInfo{Name: entry.Name(), Size: entry.Size(), ModTime: entry.ModTime()})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (d *sftpDestination) Delete(ctx context.Context, name string) error {
	if err := validateObjectName(name); err != nil {
		return err
	}
	return d.withClient(ctx, func(client *sftp.Client) error {
		if err := client.Remove(d.remotePath(name)); err != nil && !errors.Is(err, io.EOF) {
			var status *sftp.StatusError
			if errors.As(err, &status) && status.FxCode() == sftp.ErrSSHFxNoSuchFile {
				return nil
			}
			return err
		}
		return nil
	})
}

func (d *sftpDestination) Probe(ctx context.Context) error {
	return probeDestination(ctx, d)
}
