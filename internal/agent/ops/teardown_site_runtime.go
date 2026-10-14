package ops

import (
	"context"
	"errors"
	"fmt"
	"github.com/nakroteck/nakpanel/internal/types"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

func (p *SiteTeardownProvisioner) stopRemovalServices(ctx context.Context, req types.TeardownSiteReq, journalPath string, journal *siteRemovalJournal) error {
	units, err := p.removalUnits(ctx, req, true)
	if err != nil {
		return err
	}
	inspector := &SubscriptionTeardownProvisioner{runner: p.options.Runner}
	for _, unit := range units {
		if err = p.removalCheckpoint(journalPath, journal, "stopped:"+unit, func() error {
			loaded, err := inspector.systemdUnitLoaded(ctx, unit)
			if err != nil {
				return errors.New("selected website service state cannot be inspected")
			}
			if !loaded {
				return nil
			}
			if _, err = p.options.Runner.Run(ctx, "systemctl", "disable", "--now", unit); err != nil {
				return errors.New("could not stop a selected website service")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return p.removalContainers(ctx, req, journalPath, journal, false)
}

func (p *SiteTeardownProvisioner) removalContainers(ctx context.Context, req types.TeardownSiteReq, journalPath string, journal *siteRemovalJournal, remove bool) error {
	base := filepath.Join(p.options.ContainerStateRoot, "sub-"+siteRemovalID(req.SubscriptionID))
	identity := applicationIdentity{stateHome: filepath.Join(base, "home"), dataHome: filepath.Join(base, "data"), configHome: filepath.Join(base, "config"), runtimeHome: filepath.Join(p.options.ContainerRuntimeRoot, "sub-"+siteRemovalID(req.SubscriptionID))}
	if _, err := os.Lstat(identity.dataHome); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("subscription container storage cannot be inspected")
	}
	for _, path := range []string{identity.stateHome, identity.dataHome, identity.configHome} {
		if err := ensureNoSymlinkComponents(p.options.ContainerStateRoot, path); err != nil {
			return errors.New("subscription container storage is unsafe")
		}
	}
	if err := ensureNoSymlinkComponents(p.options.ContainerRuntimeRoot, identity.runtimeHome); err != nil {
		return errors.New("subscription container runtime is unsafe")
	}
	run := (&PodmanProvisioner{binary: "/usr/bin/podman", runner: p.options.Runner}).rootlessRunner(req.Snapshot.Sites[0].Username, identity)
	for _, resource := range req.Snapshot.Resources {
		if resource.Kind != "application" {
			continue
		}
		names := []string{applicationContainerName(resource.ID), applicationContainerName(resource.ID) + "-candidate", applicationContainerName(resource.ID) + "-previous"}
		if applicationNameRE.MatchString(resource.Name) {
			names = append(names, fmt.Sprintf("nakpanel-%d-%s", resource.ID, resource.Name))
		}
		for _, generation := range req.Snapshot.Resources {
			if generation.Kind == "application_generation" && generation.ParentID == resource.ID && generation.Revision > 0 {
				names = append(names, fmt.Sprintf("nakpanel-app-%d-g%d", resource.ID, generation.Revision))
			}
		}
		output, err := run(ctx, "ps", "-a", "--filter", "label=io.nakpanel.application-id="+siteRemovalID(resource.ID), "--format", "{{.Names}}")
		if err != nil || len(output) > 65536 {
			return errors.New("selected application containers cannot be inspected")
		}
		for _, name := range applicationContainerNames(output, resource.ID) {
			if _, err := applicationContainerRevision(name, resource.ID); err != nil {
				return errors.New("selected application generation identity is invalid")
			}
			names = append(names, name)
		}
		slices.Sort(names)
		names = slices.Compact(names)
		for _, name := range names {
			action := "stop"
			pastAction := "stopped"
			if remove {
				action = "remove"
				pastAction = "removed"
			}
			if err := p.removalCheckpoint(journalPath, journal, "container-"+action+":"+name, func() error {
				var err error
				if remove {
					_, err = run(ctx, "rm", "--force", "--ignore", name)
				} else {
					_, err = run(ctx, "stop", "--ignore", name)
				}
				if err != nil {
					return errors.New("selected application container could not be " + pastAction)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *SiteTeardownProvisioner) removalUnits(ctx context.Context, req types.TeardownSiteReq, inspectLoaded bool) ([]string, error) {
	units := []string{}
	addPattern := func(pattern string, accept func(string) bool) error {
		files, err := filepath.Glob(filepath.Join(p.options.Paths.SystemdUnitDir, pattern))
		if err != nil {
			return err
		}
		for _, file := range files {
			if name := filepath.Base(file); accept(name) {
				units = append(units, name)
			}
		}
		if inspectLoaded {
			output, err := p.options.Runner.Run(ctx, "systemctl", "list-units", "--all", "--type=service", "--no-legend", "--plain", "--no-pager", pattern)
			if err != nil {
				return errors.New("selected website service generations cannot be inspected")
			}
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 && accept(fields[0]) {
					units = append(units, fields[0])
				}
			}
		}
		return nil
	}
	for _, item := range req.Snapshot.Sites {
		plan, err := p.siteRemovalPlan(item)
		if err != nil {
			return nil, err
		}
		units = append(units, plan.PHPServiceName)
		pattern := fmt.Sprintf("nakpanel-php-fpm-candidate@%d-*.service", item.SiteID)
		candidateRE := regexp.MustCompile(fmt.Sprintf(`^nakpanel-php-fpm-candidate@%d-[1-9][0-9]*\.service$`, item.SiteID))
		if err := addPattern(pattern, candidateRE.MatchString); err != nil {
			return nil, err
		}
	}
	for _, resource := range req.Snapshot.Resources {
		switch resource.Kind {
		case "php_worker":
			units = append(units, fmt.Sprintf("nakpanel-php-worker@%d.service", resource.ID))
			if err := addPattern(fmt.Sprintf("nakpanel-php-worker@%d*.service", resource.ID), func(name string) bool {
				match := phpWorkerUnitFileRE.FindStringSubmatch(name)
				return len(match) > 0 && match[1] == siteRemovalID(resource.ID)
			}); err != nil {
				return nil, err
			}
		case "php_deployment":
			units = append(units, fmt.Sprintf("nakpanel-php-fpm-candidate@%d-%d.service", resource.SiteID, resource.ID))
		case "application":
			base := fmt.Sprintf("nakpanel-app-%d", resource.ID)
			units = append(units, base+".service", base+"-candidate.service", base+"-previous.service")
			generationRE := regexp.MustCompile(fmt.Sprintf(`^nakpanel-app-%d-g[1-9][0-9]*\.service$`, resource.ID))
			if err := addPattern(base+"*.service", generationRE.MatchString); err != nil {
				return nil, err
			}
			if applicationNameRE.MatchString(resource.Name) {
				units = append(units, fmt.Sprintf("nakpanel-%d-%s.service", resource.ID, resource.Name))
			}
		case "application_generation":
			if resource.Revision > 0 {
				units = append(units, fmt.Sprintf("nakpanel-app-%d-g%d.service", resource.ParentID, resource.Revision))
			}
		case "task":
			units = append(units, fmt.Sprintf("nakpanel-task-%d.timer", resource.ID), fmt.Sprintf("nakpanel-task-%d.service", resource.ID))
		}
	}
	slices.Sort(units)
	units = slices.Compact(units)
	for _, unit := range units {
		if strings.ContainsAny(unit, "/\\\r\n\t ") || !strings.HasPrefix(unit, "nakpanel-") {
			return nil, errors.New("invalid selected website service identity")
		}
		if err := validateRemovalArtifact(removalArtifact{root: p.options.Paths.SystemdUnitDir, path: filepath.Join(p.options.Paths.SystemdUnitDir, unit)}); err != nil {
			return nil, err
		}
	}
	return units, nil
}

func (p *SiteTeardownProvisioner) removeStoppedUnitFiles(ctx context.Context, req types.TeardownSiteReq, journalPath string, journal *siteRemovalJournal) error {
	units, err := p.removalUnits(ctx, req, false)
	if err != nil {
		return err
	}
	for _, unit := range units {
		if err := p.removalCheckpoint(journalPath, journal, "unit-file:"+unit, func() error {
			path := filepath.Join(p.options.Paths.SystemdUnitDir, unit)
			err := os.Remove(path)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}); err != nil {
			return errors.New("selected website service file could not be removed")
		}
	}
	if _, err := p.options.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return errors.New("systemd could not reload after website removal")
	}
	return nil
}
