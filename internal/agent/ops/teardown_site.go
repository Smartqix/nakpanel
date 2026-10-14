package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type SiteTeardownOptions struct {
	Paths            SitePathConfig
	Runner           CommandRunner
	IdentityRegistry *SiteIdentityRegistry
	MariaDB          *MariaDBEngine
	Mail             *MailProvisioner
	Dependencies     interface {
		SiteServiceDependencies(context.Context) ([]string, error)
	}
	CertRoot, GitRoot, StagingRoot, TaskStateRoot, PHPApplicationStateRoot, ContainerStateRoot, ContainerRuntimeRoot, StatisticsRoot string
}
type SiteTeardownProvisioner struct{ options SiteTeardownOptions }
type siteRemovalJournal struct {
	OperationID       int64    `json:"operation_id"`
	SubscriptionID    int64    `json:"subscription_id"`
	SnapshotDigest    string   `json:"snapshot_digest"`
	DeleteDatabaseIDs []int64  `json:"delete_database_ids"`
	Revision          int64    `json:"revision"`
	Checkpoints       []string `json:"checkpoints"`
	Complete          bool     `json:"complete"`
}

func NewSiteTeardownProvisioner(opts SiteTeardownOptions) *SiteTeardownProvisioner {
	opts.Paths = fillSitePathDefaults(opts.Paths)
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	opts.CertRoot = defaultPath(opts.CertRoot, "/var/lib/nakpanel/certs")
	opts.GitRoot = defaultPath(opts.GitRoot, "/var/lib/nakpanel/git")
	opts.StagingRoot = defaultPath(opts.StagingRoot, "/var/lib/nakpanel/staging")
	opts.TaskStateRoot = defaultPath(opts.TaskStateRoot, "/var/lib/nakpanel/tasks")
	opts.PHPApplicationStateRoot = defaultPath(opts.PHPApplicationStateRoot, "/var/lib/nakpanel/php-applications")
	opts.ContainerStateRoot = defaultPath(opts.ContainerStateRoot, "/var/lib/nakpanel/containers")
	opts.ContainerRuntimeRoot = defaultPath(opts.ContainerRuntimeRoot, "/run/nakpanel-containers")
	opts.StatisticsRoot = defaultPath(opts.StatisticsRoot, "/var/lib/nakpanel/web-statistics")
	return &SiteTeardownProvisioner{options: opts}
}

func (p *SiteTeardownProvisioner) TeardownSite(ctx context.Context, req types.TeardownSiteReq) (types.TeardownSiteResult, error) {
	result := types.TeardownSiteResult{OperationID: req.OperationID, Revision: req.Revision}
	ids, err := validateSiteTeardownRequest(req)
	if err != nil {
		return result, err
	}
	registry := p.options.IdentityRegistry
	if registry == nil {
		return result, errors.New("website removal identity registry is not configured")
	}
	if err = registry.Initialize(); err != nil {
		return result, err
	}
	journalPath := filepath.Join(registry.root, fmt.Sprintf("removal-%d.json", req.OperationID))
	journal, err := p.readRemovalJournal(journalPath, req)
	if err != nil {
		return result, err
	}
	// Completed operations never look up filesystem paths, including reused names.
	if journal.Complete {
		result.Checkpoints = journal.Checkpoints
		return result, nil
	}
	err = registry.WithRemoval(ctx, req.OperationID, req.Revision, ids, func(ctx context.Context) error {
		current, err := p.readRemovalJournal(journalPath, req)
		if err != nil {
			return err
		}
		journal = current
		if journal.Complete {
			return nil
		}
		if slices.Contains(journal.Checkpoints, string(req.Stage)) {
			return nil
		}
		if req.Stage == types.RemovalHosting && !slices.Contains(journal.Checkpoints, string(types.RemovalStopServices)) {
			return errors.New("stop website services before removing hosting")
		}
		if err = p.validateRemovalArtifacts(req); err != nil {
			return err
		}
		if err = p.validateSelectedDatabaseOwnership(req); err != nil {
			return err
		}
		if p.options.Dependencies != nil {
			dependencies, err := p.options.Dependencies.SiteServiceDependencies(ctx)
			if err != nil {
				return errors.New("server certificate dependencies cannot be verified")
			}
			for _, dependency := range dependencies {
				for _, id := range ids {
					if id.Domain == dependency || strings.HasSuffix(dependency, "."+id.Domain) {
						return errors.New("website is required by a server service")
					}
				}
			}
		}
		if err = registry.MarkRemoved(ctx, req.OperationID, req.Revision, ids); err != nil {
			return err
		}
		journal.Revision = req.Revision
		if err = p.writeRemovalJournal(journalPath, journal); err != nil {
			return err
		}
		switch req.Stage {
		case types.RemovalStopServices:
			err = p.stopRemovalServices(ctx, req, journalPath, &journal)
		case types.RemovalHosting:
			err = p.removeHostingArtifacts(ctx, req, journalPath, &journal)
		default:
			err = errors.New("requested website removal stage is not configured")
		}
		if err != nil {
			return err
		}
		journal.Checkpoints = append(journal.Checkpoints, string(req.Stage))
		return p.writeRemovalJournal(journalPath, journal)
	})
	result.Checkpoints = append([]string(nil), journal.Checkpoints...)
	return result, err
}
func (p *SiteTeardownProvisioner) readRemovalJournal(path string, req types.TeardownSiteReq) (siteRemovalJournal, error) {
	var journal siteRemovalJournal
	err := readIdentityFileLimit(path, &journal, 16<<20)
	selected := append([]int64{}, req.DeleteDatabaseIDs...)
	slices.Sort(selected)
	if errors.Is(err, os.ErrNotExist) {
		return siteRemovalJournal{OperationID: req.OperationID, SubscriptionID: req.SubscriptionID, SnapshotDigest: req.Snapshot.Digest(), DeleteDatabaseIDs: selected, Revision: req.Revision}, nil
	}
	if err != nil {
		return journal, err
	}
	if journal.OperationID != req.OperationID || journal.SubscriptionID != req.SubscriptionID || journal.SnapshotDigest != req.Snapshot.Digest() || !slices.Equal(journal.DeleteDatabaseIDs, selected) || req.Revision < journal.Revision {
		return journal, errors.New("approved website removal scope or revision differs from its journal")
	}
	return journal, nil
}
func (p *SiteTeardownProvisioner) writeRemovalJournal(path string, journal siteRemovalJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0600)
}
func (p *SiteTeardownProvisioner) removalCheckpoint(path string, journal *siteRemovalJournal, name string, work func() error) error {
	if slices.Contains(journal.Checkpoints, name) {
		return nil
	}
	if err := work(); err != nil {
		return err
	}
	journal.Checkpoints = append(journal.Checkpoints, name)
	return p.writeRemovalJournal(path, *journal)
}

func validateSiteTeardownRequest(req types.TeardownSiteReq) ([]types.SiteIdentity, error) {
	if req.OperationID <= 0 || req.Revision <= 0 || req.SubscriptionID <= 0 || req.Snapshot.SchemaVersion != 1 || len(req.Snapshot.Sites) == 0 {
		return nil, errors.New("valid approved website removal identity is required")
	}
	if !slices.Contains([]types.SiteRemovalStage{types.RemovalStopServices, types.RemovalHosting, types.RemovalShared, types.RemovalFinalize}, req.Stage) {
		return nil, errors.New("invalid website removal stage")
	}
	targets := map[int64]types.SiteRemovalSite{}
	ids := []types.SiteIdentity{}
	account := ""
	customer := int64(0)
	for _, item := range req.Snapshot.Sites {
		if item.SiteID <= 0 || item.SubscriptionID != req.SubscriptionID || item.CustomerID <= 0 || site.ValidateUsername(item.Username) != nil || site.ValidateDomain(item.Domain) != nil || site.NormalizeDomain(item.Domain) != item.Domain || !phpVersionDirectoryRE.MatchString(item.PHPVersion) {
			return nil, errors.New("website removal has inconsistent account or domain identity")
		}
		if _, exists := targets[item.SiteID]; exists {
			return nil, errors.New("duplicate website removal identity")
		}
		if account != "" && (account != item.Username || customer != item.CustomerID) {
			return nil, errors.New("website removal crosses account ownership")
		}
		account = item.Username
		customer = item.CustomerID
		targets[item.SiteID] = item
		ids = append(ids, types.SiteIdentity{SiteID: item.SiteID, SubscriptionID: item.SubscriptionID, Username: item.Username, Domain: item.Domain})
	}
	roots := 0
	for _, item := range targets {
		path := map[int64]bool{}
		current := item
		for {
			if path[current.SiteID] {
				return nil, errors.New("website removal contains a parent cycle")
			}
			path[current.SiteID] = true
			parent, exists := targets[current.ParentSiteID]
			if !exists {
				break
			}
			if !strings.HasSuffix(current.Domain, "."+parent.Domain) {
				return nil, errors.New("website removal has inconsistent parent domains")
			}
			current = parent
		}
		if _, inside := targets[item.ParentSiteID]; !inside {
			roots++
		}
	}
	if roots != 1 {
		return nil, errors.New("website removal must contain one approved target tree")
	}
	for _, resource := range req.Snapshot.Resources {
		if resource.ID <= 0 {
			return nil, errors.New("invalid removal resource identity")
		}
		_, inside := targets[resource.SiteID]
		if resource.Kind == "staging" {
			_, destination := targets[resource.ParentID]
			if !inside && !destination {
				return nil, errors.New("staging operation does not reference the removal target")
			}
			continue
		}
		if !inside {
			return nil, errors.New("removal resource is outside the selected websites")
		}
		if !slices.Contains([]string{"php_application", "php_worker", "php_deployment", "php_environment", "wordpress", "git", "git_deployment", "application", "application_generation", "application_secret", "task", "ftp", "sftp_identity", "protected_directory", "mail_domain", "mailbox", "mail_alias", "webmail", "dns_zone", "dns_record", "runtime_generation", "statistics", "site_policy"}, resource.Kind) {
			return nil, errors.New("unrecognized website removal resource")
		}
		parentKind := ""
		switch resource.Kind {
		case "php_worker", "php_deployment":
			parentKind = "php_application"
		case "application_generation", "application_secret":
			parentKind = "application"
		case "git_deployment":
			parentKind = "git"
		case "mailbox", "mail_alias":
			parentKind = "mail_domain"
		}
		if parentKind != "" {
			found := false
			for _, parent := range req.Snapshot.Resources {
				if parent.Kind == parentKind && parent.ID == resource.ParentID && parent.SiteID == resource.SiteID {
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("removal resource has an unapproved parent")
			}
		}
	}
	for _, id := range req.DeleteDatabaseIDs {
		found := false
		for _, database := range req.Snapshot.Databases {
			if database.ID == id && database.SubscriptionID == req.SubscriptionID && database.DeletionEligible && database.Provenance != "external_wordpress" {
				_, found = targets[database.SiteID]
				if !databaseIdentifierRE.MatchString(database.Name) || !databaseIdentifierRE.MatchString(database.Principal) {
					found = false
				}
			}
		}
		if !found {
			return nil, errors.New("selected database is not eligible for scoped removal")
		}
	}
	selected := append([]int64(nil), req.DeleteDatabaseIDs...)
	slices.Sort(selected)
	if len(slices.Compact(selected)) != len(req.DeleteDatabaseIDs) {
		return nil, errors.New("duplicate database removal selection")
	}
	return ids, nil
}

func (p *SiteTeardownProvisioner) siteRemovalPlan(item types.SiteRemovalSite) (SitePlan, error) {
	return NewSitePlan(types.CreateSiteReq{SiteID: item.SiteID, SubscriptionID: item.SubscriptionID, Username: item.Username, Domain: item.Domain, PHPVersion: item.PHPVersion, SharedAccount: true}, p.options.Paths)
}
func siteRemovalID(id int64) string { return strconv.FormatInt(id, 10) }
