package provision

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/certificates"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

const DefaultCustomTLSStagingDir = "/var/lib/nakpanel/tls-staging"

type CustomCertificateRepository interface {
	InstallCustomCertificate(context.Context, int64, string, string) (int64, error)
}

type CustomCertificateStager interface {
	Stage(context.Context, string, certificates.Bundle) (string, certificates.Result, error)
}

type FileCustomCertificateStager struct {
	Dir       string
	Validator certificates.Validator
}

type stagedCustomCertificate struct {
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	ChainPEM       string `json:"chain_pem,omitempty"`
}

func (s *FileCustomCertificateStager) Stage(_ context.Context, domain string, bundle certificates.Bundle) (path string, result certificates.Result, err error) {
	if s == nil {
		return "", certificates.Result{}, errors.New("custom certificate stager is not configured")
	}
	result, err = s.Validator.Validate(domain, bundle)
	if err != nil {
		return "", certificates.Result{}, err
	}
	dir := strings.TrimSpace(s.Dir)
	if dir == "" {
		dir = DefaultCustomTLSStagingDir
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", certificates.Result{}, fmt.Errorf("create custom TLS staging directory: %w", err)
	}
	if err = os.Chmod(dir, 0o700); err != nil {
		return "", certificates.Result{}, fmt.Errorf("secure custom TLS staging directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "custom-*.json")
	if err != nil {
		return "", certificates.Result{}, fmt.Errorf("create custom TLS staging file: %w", err)
	}
	path = file.Name()
	defer func() {
		if err != nil {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return "", certificates.Result{}, err
	}
	payload := stagedCustomCertificate{
		CertificatePEM: string(result.CertificatePEM), PrivateKeyPEM: string(result.PrivateKeyPEM), ChainPEM: string(result.ChainPEM),
	}
	encoder := json.NewEncoder(file)
	if err = encoder.Encode(payload); err != nil {
		return "", certificates.Result{}, fmt.Errorf("write custom TLS staging file: %w", err)
	}
	if err = file.Sync(); err != nil {
		return "", certificates.Result{}, err
	}
	if err = file.Close(); err != nil {
		return "", certificates.Result{}, err
	}
	if err = setStagingFileOwner(dir, path); err != nil {
		return "", certificates.Result{}, fmt.Errorf("set custom TLS staging file owner: %w", err)
	}
	return path, result, nil
}

func SweepCustomTLSStaging(dir string, olderThan time.Duration) error {
	return sweepCustomTLSStaging(dir, olderThan, nil)
}

func SweepCustomTLSStagingForJobs(ctx context.Context, db *sql.DB, dir string, olderThan time.Duration) error {
	if db == nil {
		return errors.New("database is not configured")
	}
	rows, err := db.QueryContext(ctx, `SELECT args->>'staging_path'
FROM river_job
WHERE kind = 'install_custom_cert'
  AND state IN ('available', 'pending', 'retryable', 'running', 'scheduled')`)
	if err != nil {
		return fmt.Errorf("list active custom TLS staging files: %w", err)
	}
	defer rows.Close()
	protected := make(map[string]struct{})
	for rows.Next() {
		var path sql.NullString
		if err := rows.Scan(&path); err != nil {
			return fmt.Errorf("scan active custom TLS staging file: %w", err)
		}
		if path.Valid && strings.TrimSpace(path.String) != "" {
			protected[filepath.Clean(path.String)] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list active custom TLS staging files: %w", err)
	}
	return sweepCustomTLSStaging(dir, olderThan, protected)
}

func sweepCustomTLSStaging(dir string, olderThan time.Duration, protected map[string]struct{}) error {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultCustomTLSStagingDir
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-olderThan)
	var sweepErr error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "custom-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			sweepErr = errors.Join(sweepErr, infoErr)
			continue
		}
		path := filepath.Clean(filepath.Join(dir, entry.Name()))
		if _, keep := protected[path]; keep {
			continue
		}
		if info.ModTime().Before(cutoff) {
			sweepErr = errors.Join(sweepErr, os.Remove(path))
		}
	}
	return sweepErr
}

type InstallCustomCertArgs struct {
	SiteID        int64                    `json:"site_id" river:"unique"`
	StagingPath   string                   `json:"staging_path"`
	Username      string                   `json:"username"`
	Domain        string                   `json:"domain"`
	PHPVersion    string                   `json:"php_version"`
	SharedAccount bool                     `json:"shared_account,omitempty"`
	Limits        types.SiteResourceLimits `json:"limits"`
}

func (InstallCustomCertArgs) Kind() string { return "install_custom_cert" }

func (InstallCustomCertArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type AgentCustomCertificateClient interface {
	InstallCustomCert(context.Context, types.InstallCustomCertReq) (types.Response, error)
}

type InstallCustomCertWorker struct {
	river.WorkerDefaults[InstallCustomCertArgs]
	agent       AgentCustomCertificateClient
	sites       SiteTLSStatusStore
	stagingRoot string
}

func NewInstallCustomCertWorker(agent AgentCustomCertificateClient, sites SiteTLSStatusStore, stagingRoots ...string) *InstallCustomCertWorker {
	root := DefaultCustomTLSStagingDir
	if len(stagingRoots) > 0 && strings.TrimSpace(stagingRoots[0]) != "" {
		root = stagingRoots[0]
	}
	return &InstallCustomCertWorker{agent: agent, sites: sites, stagingRoot: root}
}

func (w *InstallCustomCertWorker) Work(ctx context.Context, job *river.Job[InstallCustomCertArgs]) (err error) {
	terminal := job.JobRow != nil && job.JobRow.Attempt >= job.JobRow.MaxAttempts
	defer func() {
		if err != nil && terminal {
			w.markFailed(ctx, job.Args.SiteID, err.Error())
		}
		if err == nil || terminal {
			_ = os.Remove(job.Args.StagingPath)
		}
	}()
	payload, err := readStagedCustomCertificate(job.Args.StagingPath, w.stagingRoot)
	if err != nil {
		return err
	}
	if w.agent == nil {
		return errors.New("agent custom certificate client is not configured")
	}
	response, err := w.agent.InstallCustomCert(ctx, types.InstallCustomCertReq{
		Username: job.Args.Username, Domain: job.Args.Domain, PHPVersion: job.Args.PHPVersion,
		SharedAccount: job.Args.SharedAccount, Limits: job.Args.Limits,
		CertificatePEM: payload.CertificatePEM, PrivateKeyPEM: payload.PrivateKeyPEM, ChainPEM: payload.ChainPEM,
	})
	if err != nil {
		return err
	}
	if !response.OK {
		err = fmt.Errorf("agent install_custom_cert failed: %s", response.Error)
		return err
	}
	var result types.InstallCustomCertResult
	if err = json.Unmarshal(response.Data, &result); err != nil {
		return fmt.Errorf("decode install_custom_cert response: %w", err)
	}
	if result.Domain != job.Args.Domain || result.Issuer != types.CertIssuerCustom || result.CertPath == "" || result.KeyPath == "" || result.ExpiresAt.IsZero() {
		return errors.New("invalid install_custom_cert response")
	}
	if w.sites != nil {
		err = w.sites.MarkSiteTLSActive(ctx, job.Args.SiteID, types.IssueCertResult{
			Domain: result.Domain, Issuer: result.Issuer, CertPath: result.CertPath, KeyPath: result.KeyPath, ExpiresAt: result.ExpiresAt,
		})
	}
	return err
}

func (w *InstallCustomCertWorker) markFailed(ctx context.Context, siteID int64, message string) {
	if w.sites != nil {
		_ = w.sites.MarkSiteTLSFailed(ctx, siteID, message)
	}
}

func readStagedCustomCertificate(path string, stagingRoots ...string) (stagedCustomCertificate, error) {
	if len(stagingRoots) > 0 && strings.TrimSpace(stagingRoots[0]) != "" {
		root, err := filepath.Abs(stagingRoots[0])
		if err != nil {
			return stagedCustomCertificate{}, err
		}
		candidate, err := filepath.Abs(path)
		if err != nil {
			return stagedCustomCertificate{}, err
		}
		relative, err := filepath.Rel(root, candidate)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return stagedCustomCertificate{}, errors.New("staged custom certificate is outside the staging directory")
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return stagedCustomCertificate{}, fmt.Errorf("inspect staged custom certificate: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return stagedCustomCertificate{}, errors.New("staged custom certificate must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return stagedCustomCertificate{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return stagedCustomCertificate{}, err
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o077 != 0 {
		return stagedCustomCertificate{}, errors.New("staged custom certificate changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, certificates.MaxBundleBytes+64<<10))
	if err != nil {
		return stagedCustomCertificate{}, err
	}
	if len(data) > certificates.MaxBundleBytes+32<<10 {
		return stagedCustomCertificate{}, errors.New("staged custom certificate is too large")
	}
	var payload stagedCustomCertificate
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return stagedCustomCertificate{}, fmt.Errorf("decode staged custom certificate: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return stagedCustomCertificate{}, errors.New("staged custom certificate contains trailing data")
	}
	return payload, nil
}

func (m *Manager) InstallCustomCertificate(ctx context.Context, actor auth.SessionUser, siteID int64, bundle certificates.Bundle) (int64, error) {
	if siteID <= 0 {
		return 0, errors.New("site id is required")
	}
	store, ok := m.quotaStore.(controlquota.DomainSettingsStore)
	if !ok {
		return 0, errors.New("domain settings store is not configured")
	}
	if m.customCertificateRepo == nil || m.customCertificateStager == nil {
		return 0, errors.New("custom certificate installation is not configured")
	}
	domain, err := store.SiteDomain(ctx, siteID)
	if err != nil {
		return 0, err
	}
	domain = site.NormalizeDomain(domain)
	if err := m.canManageTLS(ctx, actor, domain); err != nil {
		return 0, err
	}
	stagingPath, _, err := m.customCertificateStager.Stage(ctx, domain, bundle)
	if err != nil {
		return 0, err
	}
	jobID, err := m.customCertificateRepo.InstallCustomCertificate(ctx, actor.ID, domain, stagingPath)
	if err != nil {
		_ = os.Remove(stagingPath)
		return 0, err
	}
	return jobID, nil
}
