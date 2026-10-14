package ops

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type removalArtifact struct {
	root, path, expectedLink string
	directory                bool
}

func (p *SiteTeardownProvisioner) removalArtifacts(req types.TeardownSiteReq) ([]removalArtifact, error) {
	opts := p.options
	paths := opts.Paths
	artifacts := []removalArtifact{}
	for _, item := range req.Snapshot.Sites {
		plan, err := p.siteRemovalPlan(item)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts,
			removalArtifact{root: paths.HomeRoot, path: filepath.Dir(plan.Docroot), directory: true},
			removalArtifact{root: paths.NginxAvailableDir, path: plan.NginxConfig},
			removalArtifact{root: paths.NginxEnabledDir, path: plan.NginxEnabled, expectedLink: plan.NginxConfig},
			removalArtifact{root: paths.NginxConfDir, path: plan.NginxPolicyConfig},
			removalArtifact{root: paths.PHPFPMDedicatedDir, path: plan.PHPFPMConfig},
			removalArtifact{root: paths.PHPFPMDedicatedDir, path: plan.PHPFPMConfig + ".suspended"},
			removalArtifact{root: paths.SystemdUnitDir, path: plan.PHPServiceUnit},
			removalArtifact{root: paths.PHPFPMDedicatedRunDir, path: plan.PHPFPMSocket},
			removalArtifact{root: paths.NginxLogDir, path: plan.NginxAccessLog},
			removalArtifact{root: paths.NginxLogDir, path: plan.NginxErrorLog},
			removalArtifact{root: paths.PHPFPMLogDir, path: plan.PHPFPMErrorLog},
			removalArtifact{root: opts.CertRoot, path: filepath.Join(opts.CertRoot, item.Domain), directory: true},
			removalArtifact{root: paths.ACMEChallengeRoot, path: plan.ACMEWebroot, directory: true},
			removalArtifact{root: paths.NginxCacheDir, path: plan.NginxCachePath, directory: true},
			removalArtifact{root: paths.NginxProtectedDir, path: filepath.Dir(plan.NginxProtectedConfig), directory: true},
			removalArtifact{root: filepath.Dir(paths.NginxProtectedDir), path: plan.NginxApplicationConfig},
			removalArtifact{root: opts.GitRoot, path: filepath.Join(opts.GitRoot, "site-"+siteRemovalID(item.SiteID)), directory: true},
		)
		legacy, err := NewSitePlan(types.CreateSiteReq{Username: item.Username, Domain: item.Domain, PHPVersion: item.PHPVersion, SharedAccount: true}, paths)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, removalArtifact{root: filepath.Dir(legacy.PHPFPMConfig), path: legacy.PHPFPMConfig}, removalArtifact{root: filepath.Dir(legacy.PHPFPMConfig), path: legacy.PHPFPMConfig + ".suspended"}, removalArtifact{root: paths.PHPRunDir, path: legacy.PHPFPMSocket})
		for _, log := range []struct{ root, path string }{{paths.NginxLogDir, plan.NginxAccessLog}, {paths.NginxLogDir, plan.NginxErrorLog}, {paths.PHPFPMLogDir, plan.PHPFPMErrorLog}} {
			rotated, err := removalMatchingPaths(log.root, regexp.MustCompile("^"+regexp.QuoteMeta(filepath.Base(log.path))+`(?:\.[1-9][0-9]*|-\d{8})(?:\.gz)?$`))
			if err != nil {
				return nil, err
			}
			for _, path := range rotated {
				artifacts = append(artifacts, removalArtifact{root: log.root, path: path})
			}
		}
		for _, candidate := range []struct{ root, pattern string }{{paths.NginxConfDir, fmt.Sprintf(`^90-nakpanel-php-candidate-%d-[1-9][0-9]*\.conf$`, item.SiteID)}, {paths.PHPFPMDedicatedRunDir, fmt.Sprintf(`^candidate-%d-[1-9][0-9]*\.sock$`, item.SiteID)}} {
			files, err := removalMatchingPaths(candidate.root, regexp.MustCompile(candidate.pattern))
			if err != nil {
				return nil, err
			}
			for _, path := range files {
				artifacts = append(artifacts, removalArtifact{root: candidate.root, path: path})
			}
		}
		reports, err := removalMatchingPaths(opts.StatisticsRoot, regexp.MustCompile(fmt.Sprintf(`^site-%d-generation-[1-9][0-9]*$`, item.SiteID)))
		if err != nil {
			return nil, err
		}
		for _, path := range reports {
			artifacts = append(artifacts, removalArtifact{root: opts.StatisticsRoot, path: path, directory: true})
		}
		appConfigRoot := filepath.Dir(plan.NginxApplicationConfig)
		artifacts = append(artifacts, removalArtifact{root: appConfigRoot, path: filepath.Join(appConfigRoot, "site-"+siteRemovalID(item.SiteID)+".d"), directory: true}, removalArtifact{root: appConfigRoot, path: filepath.Join(appConfigRoot, "site-"+siteRemovalID(item.SiteID)+".domain")})
	}
	for _, resource := range req.Snapshot.Resources {
		switch resource.Kind {
		case "php_application":
			artifacts = append(artifacts, removalArtifact{root: opts.PHPApplicationStateRoot, path: filepath.Join(opts.PHPApplicationStateRoot, "app-"+siteRemovalID(resource.ID)), directory: true}, removalArtifact{root: paths.SystemdUnitDir, path: filepath.Join(paths.SystemdUnitDir, fmt.Sprintf("nakpanel-php-app-%d.slice", resource.ID))})
		case "git":
			artifacts = append(artifacts, removalArtifact{root: opts.PHPApplicationStateRoot, path: filepath.Join(opts.PHPApplicationStateRoot, "repositories", siteRemovalID(resource.ID)+".site")})
		case "application":
			artifacts = append(artifacts, removalArtifact{root: opts.ContainerStateRoot, path: filepath.Join(opts.ContainerStateRoot, "sub-"+siteRemovalID(req.SubscriptionID), "apps", siteRemovalID(resource.ID)), directory: true})
		case "staging":
			if resource.ParentID <= 0 {
				return nil, errors.New("staging journal has no validated destination")
			}
			files, err := removalMatchingPaths(opts.StagingRoot, regexp.MustCompile(fmt.Sprintf(`^site-%d-operation-%d-[0-9]+(?:\.tar\.gz|-db-[A-Za-z0-9_]+\.sql)$`, resource.ParentID, resource.ID)))
			if err != nil {
				return nil, err
			}
			for _, path := range files {
				artifacts = append(artifacts, removalArtifact{root: opts.StagingRoot, path: path})
			}
		}
	}
	slices.SortFunc(artifacts, func(a, b removalArtifact) int { return strings.Compare(a.path, b.path) })
	artifacts = slices.CompactFunc(artifacts, func(a, b removalArtifact) bool { return a.path == b.path })
	return p.excludeSurvivingArtifacts(req, artifacts)
}

// Legacy human-readable log names can collide; shared files must survive.
func (p *SiteTeardownProvisioner) excludeSurvivingArtifacts(req types.TeardownSiteReq, artifacts []removalArtifact) ([]removalArtifact, error) {
	peers, err := p.options.IdentityRegistry.boundIdentities()
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, item := range req.Snapshot.Sites {
		selected[item.Domain] = true
	}
	account := req.Snapshot.Sites[0].Username
	domainsRoot := filepath.Join(p.options.Paths.HomeRoot, account, "domains")
	if err := ensureNoSymlinkComponents(p.options.Paths.HomeRoot, domainsRoot); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(domainsRoot)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, entry := range entries {
		if !selected[entry.Name()] && site.ValidateDomain(entry.Name()) == nil {
			peers = append(peers, types.SiteIdentity{Username: account, Domain: entry.Name(), SubscriptionID: req.SubscriptionID})
		}
	}
	protected := map[string]bool{}
	logs := []string{}
	for _, peer := range peers {
		if selected[peer.Domain] {
			continue
		}
		plan, err := NewSitePlan(types.CreateSiteReq{SiteID: peer.SiteID, SubscriptionID: peer.SubscriptionID, Username: peer.Username, Domain: peer.Domain, PHPVersion: "8.4", SharedAccount: true}, p.options.Paths)
		if err != nil {
			return nil, errors.New("surviving website paths cannot be verified")
		}
		for _, path := range []string{plan.NginxConfig, plan.NginxEnabled, plan.NginxPolicyConfig, plan.NginxCachePath, plan.NginxProtectedConfig, plan.NginxApplicationConfig, plan.PHPFPMConfig, plan.PHPFPMSocket} {
			protected[path] = true
		}
		legacy, err := NewSitePlan(types.CreateSiteReq{Username: peer.Username, Domain: peer.Domain, PHPVersion: "8.4", SharedAccount: true}, p.options.Paths)
		if err != nil {
			return nil, err
		}
		protected[legacy.PHPFPMConfig] = true
		protected[legacy.PHPFPMConfig+".suspended"] = true
		protected[legacy.PHPFPMSocket] = true
		logs = append(logs, plan.NginxAccessLog, plan.NginxErrorLog, plan.PHPFPMErrorLog)
	}
	kept := artifacts[:0]
	for _, artifact := range artifacts {
		shared := protected[artifact.path]
		for _, log := range logs {
			if artifact.path == log || strings.HasPrefix(artifact.path, log+".") || strings.HasPrefix(artifact.path, log+"-") {
				shared = true
				break
			}
		}
		if !shared {
			kept = append(kept, artifact)
		}
	}
	return kept, nil
}

func removalMatchingPaths(root string, pattern *regexp.Regexp) ([]string, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("website artifact inventory cannot be inspected")
	}
	paths := []string{}
	for _, entry := range entries {
		if pattern.MatchString(entry.Name()) {
			paths = append(paths, filepath.Join(root, entry.Name()))
		}
	}
	return paths, nil
}
func validateRemovalArtifact(artifact removalArtifact) error {
	if !filepath.IsAbs(artifact.root) || artifact.root == string(filepath.Separator) || artifact.path == artifact.root {
		return errors.New("unsafe website removal artifact root")
	}
	if err := ensureNoSymlinkComponents(artifact.root, filepath.Dir(artifact.path)); err != nil {
		return errors.New("website removal artifact has an unsafe parent")
	}
	info, err := os.Lstat(artifact.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("website removal artifact cannot be inspected")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if artifact.expectedLink == "" {
			return errors.New("website removal artifact is a symlink")
		}
		target, err := os.Readlink(artifact.path)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(artifact.path), target)
		}
		if filepath.Clean(target) != filepath.Clean(artifact.expectedLink) {
			return errors.New("website configuration link points outside its approved target")
		}
		return nil
	}
	if artifact.directory && !info.IsDir() {
		return errors.New("website removal directory is not a directory")
	}
	if !artifact.directory && !info.Mode().IsRegular() && info.Mode()&os.ModeSocket == 0 {
		return errors.New("website removal file has an unsupported type")
	}
	return nil
}
func (p *SiteTeardownProvisioner) validateRemovalArtifacts(req types.TeardownSiteReq) error {
	for _, root := range []string{p.options.Paths.HomeRoot, p.options.CertRoot, p.options.GitRoot, p.options.StagingRoot, p.options.TaskStateRoot, p.options.PHPApplicationStateRoot, p.options.ContainerStateRoot, p.options.ContainerRuntimeRoot, p.options.StatisticsRoot} {
		if !filepath.IsAbs(root) || root == string(filepath.Separator) {
			return errors.New("unsafe website removal state root")
		}
		if err := ensureNoSymlinkComponents(root, root); err != nil {
			return errors.New("website removal state root is unsafe")
		}
	}
	artifacts, err := p.removalArtifacts(req)
	if err != nil {
		return err
	}
	for _, artifact := range artifacts {
		if err := validateRemovalArtifact(artifact); err != nil {
			return err
		}
	}
	_, err = p.removalUnits(context.Background(), req, false)
	if err != nil {
		return err
	}
	return nil
}
func (p *SiteTeardownProvisioner) removeHostingArtifacts(ctx context.Context, req types.TeardownSiteReq, journalPath string, journal *siteRemovalJournal) error {
	if err := p.removeSelectedDatabases(ctx, req, journalPath, journal); err != nil {
		return err
	}
	if err := p.removalContainers(ctx, req, journalPath, journal, true); err != nil {
		return err
	}
	artifacts, err := p.removalArtifacts(req)
	if err != nil {
		return err
	}
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		checkpoint := fmt.Sprintf("artifact:%x", sha256.Sum256([]byte(artifact.path)))
		if strings.HasPrefix(filepath.Base(artifact.path), "nakpanel-") && strings.HasSuffix(artifact.path, ".conf") {
			if _, err := os.Lstat(artifact.path); err == nil {
				for _, item := range req.Snapshot.Sites {
					legacy, err := NewSitePlan(types.CreateSiteReq{Username: item.Username, Domain: item.Domain, PHPVersion: item.PHPVersion, SharedAccount: true}, p.options.Paths)
					if err != nil {
						return err
					}
					if artifact.path == legacy.PHPFPMConfig && !slices.Contains(journal.Checkpoints, "legacy-php-reload:"+item.PHPVersion) {
						journal.Checkpoints = append(journal.Checkpoints, "legacy-php-reload:"+item.PHPVersion)
						if err = p.writeRemovalJournal(journalPath, *journal); err != nil {
							return err
						}
					}
				}
			}
		}
		if err := p.removalCheckpoint(journalPath, journal, checkpoint, func() error {
			if err := validateRemovalArtifact(artifact); err != nil {
				return err
			}
			if artifact.directory {
				return os.RemoveAll(artifact.path)
			}
			err := os.Remove(artifact.path)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}); err != nil {
			return errors.New("website hosting artifact could not be removed")
		}
	}
	if err := p.removeStoppedUnitFiles(ctx, req, journalPath, journal); err != nil {
		return err
	}
	for _, checkpoint := range append([]string(nil), journal.Checkpoints...) {
		version, ok := strings.CutPrefix(checkpoint, "legacy-php-reload:")
		if !ok {
			continue
		}
		if !phpVersionDirectoryRE.MatchString(version) {
			return errors.New("invalid legacy PHP service")
		}
		if err := p.removalCheckpoint(journalPath, journal, "legacy-php-reloaded:"+version, func() error {
			if _, err := p.options.Runner.Run(ctx, "php-fpm"+version, "-t"); err != nil {
				return errors.New("legacy PHP configuration validation failed")
			}
			loaded, err := (&SubscriptionTeardownProvisioner{runner: p.options.Runner}).systemdUnitLoaded(ctx, "php"+version+"-fpm.service")
			if err != nil {
				return err
			}
			if loaded {
				if _, err = p.options.Runner.Run(ctx, "systemctl", "reload", "php"+version+"-fpm.service"); err != nil {
					return errors.New("legacy PHP service reload failed")
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
