package ops

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

const (
	maxJournalOutput = 4 << 20
	maxUpdateOutput  = 4 << 20
)

var (
	operationIDRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	journalCursorRE = regexp.MustCompile(`^[A-Za-z0-9_:;=+./-]{1,512}$`)
	packageNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9-]+)?$`)

	journalAuthorizationRE = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization)\s*[:=]\s*(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	journalSecretValueRE   = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b(\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)
	journalJSONSecretRE    = regexp.MustCompile(`(?i)("(?:authorization|proxy-authorization|password|passwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key|cookie|set-cookie|dsn|database_url|smtp_url)"\s*:\s*")([^"\r\n]*)(")`)
	journalURIUserinfoRE   = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s/]+@`)
	journalJWTRE           = regexp.MustCompile(`\b[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
)

type managedServiceSpec struct {
	unit      string
	validator []string
	actions   map[string]struct{}
}

var managedServiceRegistry = map[string]managedServiceSpec{
	"web": {
		unit: "nginx", validator: []string{"nginx", "-t"},
		actions: actionSet("reload", "restart", "start", "stop"),
	},
	"dns": {
		unit: "bind9", validator: []string{"named-checkconf"},
		actions: actionSet("reload", "restart", "start", "stop"),
	},
	"mail": {
		unit:    "stalwart-mail.service",
		actions: actionSet("reload", "restart", "start", "stop"),
	},
	"php-8.1": {
		unit: "php8.1-fpm", validator: []string{"php-fpm8.1", "-t"},
		actions: actionSet("reload", "restart", "start", "stop"),
	},
	"php-8.2": {
		unit: "php8.2-fpm", validator: []string{"php-fpm8.2", "-t"},
		actions: actionSet("reload", "restart", "start", "stop"),
	},
	"php-8.3": {
		unit: "php8.3-fpm", validator: []string{"php-fpm8.3", "-t"},
		actions: actionSet("reload", "restart", "start", "stop"),
	},
	"php-8.4": {
		unit: "php8.4-fpm", validator: []string{"php-fpm8.4", "-t"},
		actions: actionSet("reload", "restart", "start", "stop"),
	},
	"php-8.5": {
		unit: "php8.5-fpm", validator: []string{"php-fpm8.5", "-t"},
		actions: actionSet("reload", "restart", "start", "stop"),
	},
}

var journalSourceRegistry = map[string][]string{
	"panel": {"nakpanel.service"},
	"agent": {"nakpanel-agent.service"},
	"web": {
		"nginx.service", "php8.1-fpm.service", "php8.2-fpm.service",
		"php8.3-fpm.service", "php8.4-fpm.service", "php8.5-fpm.service",
	},
	"dns":      {"bind9.service", "named.service"},
	"mail":     {"stalwart-mail.service"},
	"database": {"mariadb.service", "postgresql.service"},
	"system":   {"systemd-timesyncd.service", "chrony.service", "fail2ban.service"},
}

type ManagedServiceReader interface {
	InspectManagedServices(context.Context, types.InspectManagedServicesReq) ([]types.ManagedService, error)
}

type ManagedOperationsOptions struct {
	Runner   CommandRunner
	Services ManagedServiceReader
	Now      func() time.Time
}

type ManagedOperations struct {
	runner   CommandRunner
	services ManagedServiceReader
	now      func() time.Time
}

func NewManagedOperations(opts ManagedOperationsOptions) *ManagedOperations {
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &ManagedOperations{runner: runner, services: opts.Services, now: now}
}

func (m *ManagedOperations) ControlManagedService(ctx context.Context, req types.ControlManagedServiceReq) (types.ControlManagedServiceResult, error) {
	if !operationIDRE.MatchString(req.OperationID) {
		return types.ControlManagedServiceResult{}, errors.New("a valid operation id is required")
	}
	spec, ok := managedServiceRegistry[req.ServiceID]
	if !ok {
		return types.ControlManagedServiceResult{}, errors.New("managed service id is not allowed")
	}
	if _, ok := spec.actions[req.Action]; !ok {
		return types.ControlManagedServiceResult{}, errors.New("managed service action is not allowed")
	}
	var before types.ManagedService
	if m.services != nil {
		states, err := m.services.InspectManagedServices(ctx, types.InspectManagedServicesReq{ServiceIDs: []string{req.ServiceID}})
		if err != nil {
			return types.ControlManagedServiceResult{}, fmt.Errorf("inspect service before action: %w", err)
		}
		if len(states) == 1 {
			before = states[0]
		}
	}
	validation := ""
	if (req.Action == "reload" || req.Action == "restart") && len(spec.validator) > 0 {
		validateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		out, err := m.runner.Run(validateCtx, spec.validator[0], spec.validator[1:]...)
		cancel()
		if err != nil {
			return types.ControlManagedServiceResult{}, fmt.Errorf("validate %s configuration: %w: %s", req.ServiceID, err, boundedText(out, 4096))
		}
		validation = "passed"
	}
	started := time.Now()
	actionCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	out, err := m.runner.Run(actionCtx, "systemctl", req.Action, spec.unit)
	cancel()
	if err != nil {
		return types.ControlManagedServiceResult{}, fmt.Errorf("%s managed service: %w: %s", req.Action, err, boundedText(out, 4096))
	}
	var after types.ManagedService
	if m.services != nil {
		states, inspectErr := m.services.InspectManagedServices(ctx, types.InspectManagedServicesReq{ServiceIDs: []string{req.ServiceID}})
		if inspectErr != nil {
			return types.ControlManagedServiceResult{}, fmt.Errorf("inspect service after action: %w", inspectErr)
		}
		if len(states) == 1 {
			after = states[0]
		}
		if req.Action != "stop" && after.Available && after.ActiveState != "active" {
			return types.ControlManagedServiceResult{}, fmt.Errorf("managed service %s did not become active", req.ServiceID)
		}
	}
	return types.ControlManagedServiceResult{
		ServiceID: req.ServiceID, Action: req.Action, Before: before, After: after,
		Changed:    before.ActiveState != after.ActiveState || req.Action == "reload" || req.Action == "restart",
		Validation: validation, DurationMS: time.Since(started).Milliseconds(),
	}, nil
}

func (m *ManagedOperations) ReadJournal(ctx context.Context, req types.ReadJournalReq) (types.ReadJournalResult, error) {
	if req.Limit == 0 {
		req.Limit = 200
	}
	if req.Limit < 1 || req.Limit > 1000 {
		return types.ReadJournalResult{}, errors.New("journal limit must be between 1 and 1000")
	}
	if req.Since.IsZero() {
		req.Since = m.now().Add(-time.Hour)
	}
	if req.Until.IsZero() {
		req.Until = m.now()
	}
	if req.Until.Before(req.Since) || req.Until.Sub(req.Since) > 30*24*time.Hour {
		return types.ReadJournalResult{}, errors.New("journal time range must be positive and no more than 30 days")
	}
	if req.AfterCursor != "" && !journalCursorRE.MatchString(req.AfterCursor) {
		return types.ReadJournalResult{}, errors.New("journal cursor is invalid")
	}
	sourceIDs := req.SourceIDs
	if len(sourceIDs) == 0 {
		sourceIDs = []string{"panel", "agent"}
	}
	if len(sourceIDs) > len(journalSourceRegistry) {
		return types.ReadJournalResult{}, errors.New("too many journal sources")
	}
	unitToSource := make(map[string]string)
	args := []string{"--output=json", "--no-pager", "--since=" + req.Since.UTC().Format(time.RFC3339), "--until=" + req.Until.UTC().Format(time.RFC3339), "--lines=" + strconv.Itoa(req.Limit)}
	for _, sourceID := range sourceIDs {
		units, ok := journalSourceRegistry[sourceID]
		if !ok {
			return types.ReadJournalResult{}, fmt.Errorf("journal source %q is not allowed", sourceID)
		}
		for _, unit := range units {
			args = append(args, "--unit="+unit)
			unitToSource[unit] = sourceID
		}
	}
	if len(req.Priorities) > 0 {
		seen := make(map[int]struct{})
		values := make([]string, 0, len(req.Priorities))
		for _, priority := range req.Priorities {
			if priority < 0 || priority > 7 {
				return types.ReadJournalResult{}, errors.New("journal priority must be between 0 and 7")
			}
			if _, ok := seen[priority]; !ok {
				seen[priority] = struct{}{}
				values = append(values, strconv.Itoa(priority))
			}
		}
		sort.Strings(values)
		args = append(args, "--priority="+strings.Join(values, ","))
	}
	if req.AfterCursor != "" {
		args = append(args, "--after-cursor="+req.AfterCursor)
	}
	readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	output, err := m.runner.Run(readCtx, "journalctl", args...)
	cancel()
	if len(output) > maxJournalOutput {
		return types.ReadJournalResult{}, errors.New("journal output exceeded the configured limit")
	}
	if err != nil {
		return types.ReadJournalResult{}, fmt.Errorf("read managed journal: %w: %s", err, redactJournalMessage(boundedText(output, 4096)))
	}
	result := types.ReadJournalResult{Entries: make([]types.JournalEntry, 0, req.Limit)}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		var row struct {
			Cursor    string `json:"__CURSOR"`
			Timestamp string `json:"__REALTIME_TIMESTAMP"`
			Priority  string `json:"PRIORITY"`
			Message   any    `json:"MESSAGE"`
			Unit      string `json:"_SYSTEMD_UNIT"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			continue
		}
		micros, _ := strconv.ParseInt(row.Timestamp, 10, 64)
		priority, _ := strconv.Atoi(row.Priority)
		message := redactJournalMessage(fmt.Sprint(row.Message))
		if len(message) > 16*1024 {
			message = message[:16*1024]
			result.Truncated = true
		}
		entry := types.JournalEntry{
			Cursor: row.Cursor, Timestamp: time.UnixMicro(micros).UTC(), Priority: priority,
			SourceID: unitToSource[row.Unit], Message: message,
		}
		result.Entries = append(result.Entries, entry)
		result.NextCursor = row.Cursor
		if len(result.Entries) == req.Limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return types.ReadJournalResult{}, fmt.Errorf("decode managed journal: %w", err)
	}
	return result, nil
}

func redactJournalMessage(message string) string {
	message = journalURIUserinfoRE.ReplaceAllString(message, "$1[REDACTED]@")
	message = journalJSONSecretRE.ReplaceAllString(message, "$1[REDACTED]$3")
	message = journalAuthorizationRE.ReplaceAllString(message, "$1: [REDACTED]")
	message = journalSecretValueRE.ReplaceAllString(message, "$1$2[REDACTED]")
	return journalJWTRE.ReplaceAllString(message, "[REDACTED]")
}

func (m *ManagedOperations) InspectUpdates(ctx context.Context) (types.UpdateState, error) {
	inspectCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	output, err := m.runner.Run(inspectCtx, "apt-get", "-s", "-o", "APT::Get::Show-Upgraded=true", "upgrade")
	cancel()
	state := types.UpdateState{CheckedAt: m.now().UTC(), AutomaticPolicy: "unknown"}
	state.LastRefreshAt = latestAPTListModTime("/var/lib/apt/lists")
	if len(output) > maxUpdateOutput {
		return state, errors.New("update inventory exceeded the configured limit")
	}
	if err != nil {
		return state, fmt.Errorf("inspect package updates: %w: %s", err, redactJournalMessage(boundedText(output, 4096)))
	}
	state.Packages = parseAPTUpgradeSimulation(output)
	for _, item := range state.Packages {
		if item.Security {
			state.SecurityCount++
		} else {
			state.NormalCount++
		}
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		state.RebootRequired = true
	}
	return state, nil
}

func (m *ManagedOperations) ApplyUpdates(ctx context.Context, req types.ApplyUpdatesReq) (types.UpdateState, error) {
	if !operationIDRE.MatchString(req.OperationID) {
		return types.UpdateState{}, errors.New("a valid operation id is required")
	}
	available, err := m.InspectUpdates(ctx)
	if err != nil {
		return available, fmt.Errorf("verify current update inventory: %w", err)
	}
	allowed := make(map[string]types.UpdatePackage, len(available.Packages))
	for _, item := range available.Packages {
		allowed[item.Name] = item
	}
	names := append([]string(nil), req.PackageNames...)
	expected := make(map[string]types.UpdatePackage, len(req.Packages))
	for _, item := range req.Packages {
		expected[item.Name] = item
		if len(names) == 0 {
			names = append(names, item.Name)
		}
	}
	if len(names) == 0 && req.SecurityOnly {
		for _, item := range available.Packages {
			if item.Security {
				names = append(names, item.Name)
			}
		}
	}
	if len(names) == 0 || len(names) > 256 {
		return types.UpdateState{}, errors.New("between 1 and 256 package names are required")
	}
	seen := make(map[string]struct{}, len(names))
	normalized := names[:0]
	for _, name := range names {
		name = strings.TrimSpace(name)
		if !packageNameRE.MatchString(name) {
			return types.UpdateState{}, fmt.Errorf("package name %q is invalid", name)
		}
		candidate, ok := allowed[name]
		if !ok {
			return types.UpdateState{}, fmt.Errorf("package %q is not in the current managed update inventory", name)
		}
		if req.SecurityOnly && !candidate.Security {
			return types.UpdateState{}, fmt.Errorf("package %q is not a security update", name)
		}
		if bound, ok := expected[name]; ok &&
			(bound.Candidate != candidate.Candidate || bound.Origin != candidate.Origin) {
			return types.UpdateState{}, fmt.Errorf("package %q candidate changed after confirmation", name)
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			normalized = append(normalized, name)
		}
	}
	sort.Strings(normalized)
	args := []string{"--no-remove", "install", "--only-upgrade"}
	if req.DryRun {
		args = append([]string{"-s"}, args...)
	} else {
		args = append([]string{"--assume-yes"}, args...)
	}
	args = append(args, normalized...)
	applyCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	output, err := m.runner.Run(applyCtx, "apt-get", args...)
	cancel()
	if len(output) > maxUpdateOutput {
		return types.UpdateState{}, errors.New("update output exceeded the configured limit")
	}
	if err != nil {
		return types.UpdateState{}, fmt.Errorf("apply package updates: %w: %s", err, redactJournalMessage(boundedText(output, 4096)))
	}
	if req.DryRun {
		// APT simulation validates the selected, version-bound transaction but
		// does not mutate the host. Preserve the preflight inventory and its
		// real last-install timestamp.
		return available, nil
	}
	verified, verifyErr := m.InspectUpdates(ctx)
	if verifyErr != nil {
		return types.UpdateState{
			CheckedAt:      m.now().UTC(),
			LastInstallAt:  m.now().UTC(),
			RebootRequired: updateFileExists("/var/run/reboot-required"),
			LastError:      "Packages were installed, but the post-install inventory could not be refreshed.",
		}, nil
	}
	verified.LastInstallAt = m.now().UTC()
	return verified, nil
}

func updateFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func parseAPTUpgradeSimulation(output []byte) []types.UpdatePackage {
	result := make([]types.UpdatePackage, 0)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || !packageNameRE.MatchString(fields[1]) {
			continue
		}
		item := types.UpdatePackage{Name: fields[1]}
		if open := strings.Index(line, "["); open >= 0 {
			if close := strings.Index(line[open:], "]"); close > 0 {
				item.Current = line[open+1 : open+close]
			}
		}
		if open := strings.Index(line, "("); open >= 0 {
			if close := strings.LastIndex(line, ")"); close > open {
				candidateFields := strings.Fields(line[open+1 : close])
				if len(candidateFields) > 0 {
					item.Candidate = candidateFields[0]
				}
				if len(candidateFields) > 1 {
					item.Origin = candidateFields[1]
				}
			}
		}
		lower := strings.ToLower(line)
		item.Security = strings.Contains(lower, "-security") || strings.Contains(lower, "security")
		result = append(result, item)
	}
	return result
}

func latestAPTListModTime(root string) time.Time {
	entries, err := os.ReadDir(root)
	if err != nil {
		return time.Time{}
	}
	var latest time.Time
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && info.ModTime().After(latest) {
			latest = info.ModTime().UTC()
		}
	}
	return latest
}

func actionSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func boundedText(value []byte, limit int) string {
	value = bytes.TrimSpace(value)
	if len(value) > limit {
		value = value[:limit]
	}
	return string(value)
}
