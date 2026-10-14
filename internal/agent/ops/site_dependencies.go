package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/site"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type SiteServiceDependencyOptions struct {
	CertRoot, HomeRoot string
	FTPSConfigPath     string
	Paths, Hostnames   []string
}
type SiteServiceDependencyReader struct{ options SiteServiceDependencyOptions }

func NewSiteServiceDependencyReader(opts SiteServiceDependencyOptions) *SiteServiceDependencyReader {
	if opts.CertRoot == "" {
		opts.CertRoot = "/var/lib/nakpanel/certs"
	}
	if opts.HomeRoot == "" {
		opts.HomeRoot = "/home"
	}
	if opts.FTPSConfigPath == "" {
		opts.FTPSConfigPath = "/etc/nakpanel/proftpd/proftpd.conf"
	}
	return &SiteServiceDependencyReader{options: opts}
}
func (r *SiteServiceDependencyReader) SiteServiceDependencies(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	domains := append([]string(nil), r.options.Hostnames...)
	pathsToCheck := append([]string(nil), r.options.Paths...)
	activePaths, err := readActiveFTPSCertificatePaths(r.options.FTPSConfigPath)
	if err != nil {
		return nil, err
	}
	pathsToCheck = append(pathsToCheck, activePaths...)
	for _, configured := range pathsToCheck {
		if strings.TrimSpace(configured) == "" {
			continue
		}
		if !filepath.IsAbs(configured) {
			return nil, errors.New("server certificate dependency is not absolute")
		}
		paths := []string{filepath.Clean(configured)}
		resolved, err := filepath.EvalSymlinks(configured)
		if err == nil {
			paths = append(paths, resolved)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("server certificate dependency cannot be resolved")
		}
		for _, path := range paths {
			certRoot := r.options.CertRoot
			if canonical, err := filepath.EvalSymlinks(certRoot); err == nil {
				certRoot = canonical
			}
			if canonical, err := filepath.EvalSymlinks(path); err == nil {
				path = canonical
			}
			if relative, err := filepath.Rel(certRoot, path); err == nil && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && relative != ".." {
				parts := strings.Split(relative, string(filepath.Separator))
				if len(parts) > 1 {
					domains = append(domains, parts[0])
				}
			}
			homeRoot := r.options.HomeRoot
			if canonical, err := filepath.EvalSymlinks(homeRoot); err == nil {
				homeRoot = canonical
			}
			if relative, err := filepath.Rel(homeRoot, path); err == nil && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				parts := strings.Split(relative, string(filepath.Separator))
				if len(parts) >= 4 && parts[1] == "domains" {
					domains = append(domains, parts[2])
				}
			}
		}
	}
	normalized := []string{}
	for _, domain := range domains {
		domain = site.NormalizeDomain(domain)
		if site.ValidateDomain(domain) == nil {
			normalized = append(normalized, domain)
		}
	}
	slices.Sort(normalized)
	return slices.Compact(normalized), nil
}

func readActiveFTPSCertificatePaths(path string) ([]string, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("active FTPS certificate dependencies cannot be read")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return nil, errors.New("active FTPS configuration cannot be inspected safely")
	}
	paths := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "TLSRSACertificateFile", "TLSRSACertificateKeyFile", "TLSECCertificateFile", "TLSECCertificateKeyFile", "TLSCertificateChainFile":
			value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), fields[0]))
			if strings.HasPrefix(value, "\"") {
				value, err = strconv.Unquote(value)
				if err != nil {
					return nil, errors.New("active FTPS certificate dependency is invalid")
				}
			}
			if !filepath.IsAbs(value) || strings.ContainsAny(value, "\r\n") {
				return nil, errors.New("active FTPS certificate dependency is invalid")
			}
			paths = append(paths, value)
		}
	}
	return paths, nil
}
