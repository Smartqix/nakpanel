package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func (p *SiteTeardownProvisioner) sharedRemovalArtifacts(req types.TeardownSiteReq) ([]removalArtifact, error) {
	artifacts := []removalArtifact{}
	sites := map[int64]string{}
	domains := map[int64]string{}
	for _, item := range req.Snapshot.Sites {
		sites[item.SiteID] = item.Domain
	}
	for _, resource := range req.Snapshot.Resources {
		if resource.Kind == "mail_domain" {
			if resource.Name != sites[resource.SiteID] {
				return nil, errors.New("mail domain is outside its approved website")
			}
			domains[resource.ID] = resource.Name
			if p.options.Mail == nil {
				return nil, errors.New("mail signing cleanup is not configured")
			}
			artifacts = append(artifacts, removalArtifact{root: p.options.Mail.dkimDir, path: filepath.Join(p.options.Mail.dkimDir, resource.Name), directory: true})
		}
	}
	for _, resource := range req.Snapshot.Resources {
		switch resource.Kind {
		case "mailbox", "mail_alias":
			local, domain, ok := strings.Cut(resource.Name, "@")
			if !ok || !removalMailboxLocalRE.MatchString(local) || domain != domains[resource.ParentID] {
				return nil, errors.New("mail account has an unapproved domain")
			}
		case "webmail":
			if site.ValidateDomain(resource.Name) != nil || !strings.HasSuffix(resource.Name, "."+sites[resource.SiteID]) {
				return nil, errors.New("webmail hostname is outside its approved website")
			}
			config := filepath.Join(p.options.Paths.NginxAvailableDir, resource.Name+".conf")
			artifacts = append(artifacts, removalArtifact{root: p.options.Paths.NginxAvailableDir, path: config}, removalArtifact{root: p.options.Paths.NginxEnabledDir, path: filepath.Join(p.options.Paths.NginxEnabledDir, resource.Name+".conf"), expectedLink: config})
		case "dns_zone":
			if resource.Name != sites[resource.SiteID] || !slices.Contains([]string{"primary", "secondary", "disabled", "parent"}, resource.Mode) {
				return nil, errors.New("DNS zone has an unapproved domain or mode")
			}
			if resource.Mode == "primary" || resource.Mode == "secondary" {
				if p.options.DNS == nil {
					return nil, errors.New("DNS cleanup is not configured")
				}
				for _, artifact := range []removalArtifact{{root: p.options.DNS.zoneDir, path: filepath.Join(p.options.DNS.zoneDir, "db."+resource.Name)}, {root: p.options.DNS.includeDir, path: filepath.Join(p.options.DNS.includeDir, resource.Name+".conf")}} {
					if err := validateRemovalArtifact(artifact); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	for _, artifact := range artifacts {
		if err := validateRemovalArtifact(artifact); err != nil {
			return nil, err
		}
	}
	return artifacts, nil
}

func (p *SiteTeardownProvisioner) removeSharedArtifacts(ctx context.Context, req types.TeardownSiteReq, path string, journal *siteRemovalJournal) error {
	artifacts, err := p.sharedRemovalArtifacts(req)
	if err != nil {
		return err
	}
	for _, resource := range req.Snapshot.Resources {
		if resource.Kind == "mailbox" {
			if p.options.Mail == nil {
				return errors.New("mail account cleanup is not configured")
			}
			if err := p.removalCheckpoint(path, journal, "mailbox-removed:"+siteRemovalID(resource.ID), func() error { return p.options.Mail.removeMailboxPrincipal(ctx, resource.Name) }); err != nil {
				return err
			}
		}
		if resource.Kind == "dns_zone" {
			if resource.Mode == "parent" || resource.Mode == "disabled" {
				continue
			}
			if p.options.DNS == nil {
				return errors.New("DNS cleanup is not configured")
			}
			if err := p.removalCheckpoint(path, journal, "dns-zone-removed:"+siteRemovalID(resource.ID), func() error {
				_, err := p.options.DNS.ConfigureDNSZone(ctx, types.ConfigureDNSZoneReq{Domain: resource.Name, Mode: "disabled", Serial: 1})
				return err
			}); err != nil {
				return err
			}
		}
	}
	siteConfigMutationMu.Lock()
	defer siteConfigMutationMu.Unlock()
	files := []string{}
	for _, artifact := range artifacts {
		if !artifact.directory {
			files = append(files, artifact.path)
		}
	}
	snapshots, err := snapshotFiles(files)
	if err != nil {
		return err
	}
	for _, artifact := range artifacts {
		if err := validateRemovalArtifact(artifact); err != nil {
			return err
		}
		if artifact.directory {
			if err := os.RemoveAll(artifact.path); err != nil {
				return errors.New("selected signing data could not be removed")
			}
		} else if err := os.Remove(artifact.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("selected webmail route could not be removed")
		}
	}
	if _, err = p.options.Runner.Run(ctx, "nginx", "-t"); err != nil {
		_ = restoreSnapshots(snapshots)
		return errors.New("shared nginx configuration validation failed")
	}
	if _, err = p.options.Runner.Run(ctx, "systemctl", "reload", "nginx.service"); err != nil {
		_ = restoreSnapshots(snapshots)
		_, _ = p.options.Runner.Run(context.Background(), "systemctl", "reload", "nginx.service")
		return errors.New("shared nginx reload failed")
	}
	return nil
}
