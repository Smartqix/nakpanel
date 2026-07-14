package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var databaseIdentifierRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

type SubscriptionTeardownOptions struct {
	HomeRoot string
	Paths    SitePathConfig
	Runner   CommandRunner
}
type SubscriptionTeardownProvisioner struct {
	homeRoot string
	paths    SitePathConfig
	runner   CommandRunner
}

func NewSubscriptionTeardownProvisioner(opts SubscriptionTeardownOptions) *SubscriptionTeardownProvisioner {
	root := filepath.Clean(opts.HomeRoot)
	if opts.HomeRoot == "" {
		root = "/home"
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	paths := opts.Paths
	paths.HomeRoot = root
	return &SubscriptionTeardownProvisioner{homeRoot: root, paths: paths, runner: runner}
}

func (p *SubscriptionTeardownProvisioner) TeardownSubscription(ctx context.Context, req types.TeardownSubscriptionReq) (types.TeardownSubscriptionResult, error) {
	var result types.TeardownSubscriptionResult
	if req.SubscriptionID <= 0 || !accountUsernameRE.MatchString(req.Username) {
		return result, errors.New("invalid subscription account identity")
	}
	home := filepath.Clean(req.HomePath)
	if home != filepath.Join(p.homeRoot, req.Username) || filepath.Dir(home) != p.homeRoot {
		return result, errors.New("account home is not the direct validated home-root child")
	}
	for _, domain := range req.Domains {
		if site.ValidateDomain(site.NormalizeDomain(domain)) != nil || domain != site.NormalizeDomain(domain) {
			return result, fmt.Errorf("invalid teardown domain %q", domain)
		}
	}
	for _, name := range req.DatabaseNames {
		if !databaseIdentifierRE.MatchString(name) {
			return result, fmt.Errorf("invalid database identifier %q", name)
		}
	}
	info, err := os.Lstat(home)
	homeExists := err == nil
	if homeExists {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return result, errors.New("account home must be a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	for _, domain := range req.Domains {
		for _, php := range []string{"8.2", "8.3"} {
			plan, planErr := NewSitePlan(types.CreateSiteReq{SubscriptionID: req.SubscriptionID, Username: req.Username, Domain: domain, PHPVersion: php, SharedAccount: true}, p.paths)
			if planErr != nil {
				return result, planErr
			}
			for _, path := range []string{plan.NginxEnabled, plan.NginxConfig, plan.NginxPolicyConfig, plan.PHPFPMConfig, plan.PHPFPMConfig + ".suspended"} {
				if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return result, fmt.Errorf("remove tracked configuration: %w", err)
				}
			}
		}
		result.Removed = append(result.Removed, "domain:"+domain)
	}
	for _, name := range req.DatabaseNames {
		statement := "DROP DATABASE IF EXISTS `" + name + "`"
		output, runErr := p.runner.Run(ctx, "mariadb", "--batch", "--skip-column-names", "--execute", statement)
		if runErr != nil {
			return result, fmt.Errorf("drop database %s: %w: %s", name, runErr, strings.TrimSpace(string(output)))
		}
		result.Removed = append(result.Removed, "database:"+name)
	}
	if homeExists {
		if err = os.RemoveAll(home); err != nil {
			return result, fmt.Errorf("remove account home: %w", err)
		}
	}
	result.Removed = append(result.Removed, "home:"+home)
	if _, idErr := p.runner.Run(ctx, "id", "-u", req.Username); idErr == nil {
		output, userErr := p.runner.Run(ctx, "userdel", "--", req.Username)
		if userErr != nil {
			return result, fmt.Errorf("delete system account: %w: %s", userErr, strings.TrimSpace(string(output)))
		}
	}
	result.Removed = append(result.Removed, "user:"+req.Username)
	return result, nil
}
