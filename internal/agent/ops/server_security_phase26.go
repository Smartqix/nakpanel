package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

const (
	ServerSecurityFirewallScope = "firewall"
	securityConfirmationWindow  = 120 * time.Second
)

// ServerSecurityApplier is intentionally narrower than a generic privileged
// file or command API. Implementations may only manage table inet nakpanel.
type ServerSecurityApplier interface {
	CurrentNftables(context.Context) (SecurityPreviousConfig, error)
	ValidateAndApplyNftables(context.Context, []byte) error
	RestoreNftables(context.Context, SecurityPreviousConfig) error
	InspectServerSecurity(context.Context) (types.ServerSecurityPolicy, error)
}

type ServerSecurityControllerOptions struct {
	Stages  *SecurityStageStore
	Applier ServerSecurityApplier
}

type ServerSecurityController struct {
	stages  *SecurityStageStore
	applier ServerSecurityApplier
	mu      sync.Mutex
}

func NewServerSecurityController(opts ServerSecurityControllerOptions) *ServerSecurityController {
	stages := opts.Stages
	if stages == nil {
		stages = NewSecurityStageStore(SecurityStageStoreOptions{})
	}
	applier := opts.Applier
	if applier == nil {
		applier = &nftablesSecurityApplier{path: NftablesConfigPath, runner: ExecRunner{}}
	}
	return &ServerSecurityController{stages: stages, applier: applier}
}

func (c *ServerSecurityController) InspectServerSecurity(ctx context.Context) (types.ServerSecurityPolicy, error) {
	if c == nil || c.applier == nil {
		return types.ServerSecurityPolicy{}, errors.New("server security inspection is not configured")
	}
	return c.applier.InspectServerSecurity(ctx)
}

// StageServerSecurity applies only the managed Nakpanel firewall table. SSH,
// Fail2Ban, and TLS requests are rejected until their own transition and
// rollback implementations are enabled.
func (c *ServerSecurityController) StageServerSecurity(ctx context.Context, req types.StageServerSecurityReq) (types.StagedSecurityResult, error) {
	if c == nil || c.stages == nil || c.applier == nil {
		return types.StagedSecurityResult{}, errors.New("server security staging is not configured")
	}
	if req.Scope != ServerSecurityFirewallScope {
		return types.StagedSecurityResult{}, errors.New("only the managed firewall scope is available")
	}
	if req.Policy.Revision < 0 {
		return types.StagedSecurityResult{}, errors.New("security policy revision must not be negative")
	}
	if err := validateFirewallOnlyRequest(req.Policy); err != nil {
		return types.StagedSecurityResult{}, err
	}
	policy, err := translateFirewallPolicy(req.Policy)
	if err != nil {
		return types.StagedSecurityResult{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, loadErr := c.stages.Load(SecurityStageNftables, req.OperationID); loadErr == nil {
		return stagedSecurityResult(existing, req.Policy.Revision), nil
	} else if !errors.Is(loadErr, ErrSecurityStageNotFound) {
		return types.StagedSecurityResult{}, loadErr
	}
	previous, err := c.applier.CurrentNftables(ctx)
	if err != nil {
		return types.StagedSecurityResult{}, fmt.Errorf("snapshot managed firewall: %w", err)
	}
	record, err := c.stages.StageNftables(req.OperationID, previous, policy, securityConfirmationWindow)
	if err != nil {
		return types.StagedSecurityResult{}, err
	}
	candidate, err := c.stages.Candidate(SecurityStageNftables, req.OperationID)
	if err != nil {
		return types.StagedSecurityResult{}, err
	}
	if err := c.applier.ValidateAndApplyNftables(ctx, candidate.Candidate); err != nil {
		rollbackErr := c.rollbackLocked(ctx, req.OperationID, true)
		if rollbackErr != nil {
			return types.StagedSecurityResult{}, fmt.Errorf("apply managed firewall: %w (rollback: %v)", err, rollbackErr)
		}
		return types.StagedSecurityResult{}, fmt.Errorf("apply managed firewall: %w", err)
	}
	return stagedSecurityResult(record, req.Policy.Revision), nil
}

func (c *ServerSecurityController) ConfirmServerSecurity(_ context.Context, operationID string) (types.StagedSecurityResult, error) {
	if c == nil || c.stages == nil {
		return types.StagedSecurityResult{}, errors.New("server security confirmation is not configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record, err := c.stages.Confirm(SecurityStageNftables, operationID)
	if err != nil {
		return types.StagedSecurityResult{}, err
	}
	return stagedSecurityResult(record, 0), nil
}

func (c *ServerSecurityController) RevertServerSecurity(ctx context.Context, operationID string) (types.StagedSecurityResult, error) {
	if c == nil || c.stages == nil || c.applier == nil {
		return types.StagedSecurityResult{}, errors.New("server security rollback is not configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.rollbackLocked(ctx, operationID, true); err != nil {
		if errors.Is(err, ErrSecurityStageRolledBack) {
			record, loadErr := c.stages.Load(SecurityStageNftables, operationID)
			if loadErr == nil {
				return stagedSecurityResult(record, 0), nil
			}
		}
		return types.StagedSecurityResult{}, err
	}
	record, err := c.stages.Load(SecurityStageNftables, operationID)
	if err != nil {
		return types.StagedSecurityResult{}, err
	}
	return stagedSecurityResult(record, 0), nil
}

// RecoverDue rolls back every expired or interrupted firewall stage. Calling it
// repeatedly is safe and is intended for both boot recovery and a short timer.
func (c *ServerSecurityController) RecoverDue(ctx context.Context) error {
	if c == nil || c.stages == nil || c.applier == nil {
		return errors.New("server security recovery is not configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	records, err := c.stages.RollbacksDue()
	if err != nil {
		return err
	}
	var failures []string
	for _, record := range records {
		if record.Kind != SecurityStageNftables {
			continue
		}
		if err := c.rollbackLocked(ctx, record.OperationID, false); err != nil &&
			!errors.Is(err, ErrSecurityStageRolledBack) &&
			!errors.Is(err, ErrSecurityStageConfirmed) {
			failures = append(failures, record.OperationID+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (c *ServerSecurityController) RunRecovery(ctx context.Context, onError func(error)) {
	if err := c.RecoverDue(ctx); err != nil && onError != nil {
		onError(err)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.RecoverDue(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (c *ServerSecurityController) rollbackLocked(ctx context.Context, operationID string, force bool) error {
	var material SecurityRollbackMaterial
	var err error
	if force {
		material, err = c.stages.ForceRollback(SecurityStageNftables, operationID)
	} else {
		material, err = c.stages.BeginRollback(SecurityStageNftables, operationID)
	}
	if err != nil {
		return err
	}
	if err := c.applier.RestoreNftables(ctx, material.Previous); err != nil {
		return err
	}
	_, err = c.stages.CompleteRollback(SecurityStageNftables, operationID)
	return err
}

func stagedSecurityResult(record SecurityStageRecord, revision int64) types.StagedSecurityResult {
	return types.StagedSecurityResult{
		OperationID: record.OperationID, Scope: ServerSecurityFirewallScope,
		Revision: revision, RollbackDeadline: record.ConfirmBy, State: string(record.Status),
		Validation: []string{
			"nft syntax checked before activation",
			"only table inet nakpanel was changed",
			"automatic rollback is armed for 120 seconds",
		},
	}
}

func translateFirewallPolicy(policy types.ServerSecurityPolicy) (NftablesPolicy, error) {
	defaultInput := NftablesInputPolicy(strings.ToLower(strings.TrimSpace(policy.Firewall.DefaultInbound)))
	if !policy.Firewall.Enabled {
		defaultInput = NftablesInputAccept
	}
	if policy.SSH.Port < 1 || policy.SSH.Port > 65535 {
		return NftablesPolicy{}, errors.New("the active SSH recovery port must be between 1 and 65535")
	}
	result := NftablesPolicy{
		DefaultInput: defaultInput,
		PanelPort:    7443,
		SSHPorts:     []uint16{uint16(policy.SSH.Port)},
	}
	for _, rule := range policy.Firewall.Rules {
		if !rule.Enabled {
			continue
		}
		if strings.ToLower(strings.TrimSpace(rule.Direction)) != "inbound" {
			return NftablesPolicy{}, fmt.Errorf("firewall rule %q must be inbound", rule.ID)
		}
		if len(rule.Ports) == 0 {
			return NftablesPolicy{}, fmt.Errorf("firewall rule %q requires at least one port", rule.ID)
		}
		for index, port := range rule.Ports {
			if port < 1 || port > 65535 {
				return NftablesPolicy{}, fmt.Errorf("firewall rule %q has an invalid port", rule.ID)
			}
			id := rule.ID
			if len(rule.Ports) > 1 {
				id += "-" + strconv.Itoa(index+1)
			}
			result.Rules = append(result.Rules, NftablesRule{
				ID: id, Action: NftablesRuleAction(strings.ToLower(strings.TrimSpace(rule.Action))),
				Transport: NftablesTransport(strings.ToLower(strings.TrimSpace(rule.Protocol))),
				PortStart: uint16(port), SourceCIDRs: append([]string(nil), rule.Sources...),
			})
		}
	}
	if err := ValidateNftablesPolicy(result); err != nil {
		return NftablesPolicy{}, err
	}
	return result, nil
}

func validateFirewallOnlyRequest(policy types.ServerSecurityPolicy) error {
	if len(policy.Firewall.ManagementCIDRs) != 0 {
		return errors.New("management CIDR mutation is not available in the firewall-only scope")
	}
	if policy.Fail2Ban.Enabled || len(policy.Fail2Ban.TrustedCIDRs) != 0 || len(policy.Fail2Ban.Jails) != 0 {
		return errors.New("Fail2Ban mutation requires its own staged operation")
	}
	if policy.SSH.PermitRootLogin || policy.SSH.PasswordAuthentication ||
		policy.SSH.PublicKeyAuthentication || policy.SSH.AllowTCPForwarding {
		return errors.New("SSH mutation requires its own staged operation")
	}
	if strings.TrimSpace(policy.TLS.Profile) != "" {
		return errors.New("TLS mutation requires its own staged operation")
	}
	return nil
}

type nftablesSecurityApplier struct {
	path   string
	runner CommandRunner
}

func (a *nftablesSecurityApplier) CurrentNftables(_ context.Context) (SecurityPreviousConfig, error) {
	path := a.path
	if path == "" {
		path = NftablesConfigPath
	}
	data, err := readRegularFile(path, maxSecurityStageFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return SecurityPreviousConfig{}, nil
	}
	if err != nil {
		return SecurityPreviousConfig{}, err
	}
	return SecurityPreviousConfig{Exists: true, Data: data}, nil
}

func (a *nftablesSecurityApplier) ValidateAndApplyNftables(ctx context.Context, candidate []byte) error {
	path := a.path
	if path == "" {
		path = NftablesConfigPath
	}
	previous, err := a.CurrentNftables(ctx)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(os.TempDir(), "nakpanel-nft-*.nft")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(candidate); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if output, err := a.runner.Run(ctx, "nft", "-c", "-f", tmpPath); err != nil {
		return fmt.Errorf("validate nftables candidate: %w: %s", err, boundedSecurityOutput(output))
	}
	if err := rejectUnsafeSecurityTarget(path); err != nil {
		return err
	}
	if err := writeFileAtomic(path, candidate, 0o600); err != nil {
		return fmt.Errorf("install nftables candidate: %w", err)
	}
	if output, err := a.runner.Run(ctx, "nft", "-f", path); err != nil {
		restoreErr := a.restore(ctx, path, previous)
		return fmt.Errorf("activate nftables candidate: %w: %s (restore: %v)", err, boundedSecurityOutput(output), restoreErr)
	}
	if output, err := a.runner.Run(ctx, "nft", "list", "table", "inet", NftablesTableName); err != nil {
		restoreErr := a.restore(ctx, path, previous)
		return fmt.Errorf("health-check nftables candidate: %w: %s (restore: %v)", err, boundedSecurityOutput(output), restoreErr)
	}
	return nil
}

func (a *nftablesSecurityApplier) RestoreNftables(ctx context.Context, previous SecurityPreviousConfig) error {
	path := a.path
	if path == "" {
		path = NftablesConfigPath
	}
	return a.restore(ctx, path, previous)
}

func (a *nftablesSecurityApplier) restore(ctx context.Context, path string, previous SecurityPreviousConfig) error {
	if previous.Exists {
		if err := writeFileAtomic(path, previous.Data, 0o600); err != nil {
			return fmt.Errorf("restore previous nftables file: %w", err)
		}
		if output, err := a.runner.Run(ctx, "nft", "-f", path); err != nil {
			return fmt.Errorf("restore previous nftables policy: %w: %s", err, boundedSecurityOutput(output))
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove managed nftables file: %w", err)
	}
	if _, err := a.runner.Run(ctx, "nft", "list", "table", "inet", NftablesTableName); err != nil {
		return nil
	}
	if output, err := a.runner.Run(ctx, "nft", "delete", "table", "inet", NftablesTableName); err != nil {
		return fmt.Errorf("remove managed nftables table: %w: %s", err, boundedSecurityOutput(output))
	}
	return nil
}

func (a *nftablesSecurityApplier) InspectServerSecurity(ctx context.Context) (types.ServerSecurityPolicy, error) {
	policy := types.ServerSecurityPolicy{
		Firewall: types.FirewallPolicy{DefaultInbound: string(NftablesInputAccept)},
		SSH: types.SSHSecurityPolicy{
			PublicKeyAuthentication: true,
			Port:                    22,
		},
		TLS: types.TLSSecurityPolicy{Profile: "balanced"},
	}
	current, err := a.CurrentNftables(ctx)
	if err != nil {
		return policy, err
	}
	if current.Exists {
		policy.Firewall.Enabled = true
		if strings.Contains(string(current.Data), "policy drop;") {
			policy.Firewall.DefaultInbound = string(NftablesInputDrop)
		}
	}
	output, sshErr := a.runner.Run(ctx, "sshd", "-T")
	if sshErr == nil {
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			switch fields[0] {
			case "port":
				if port, parseErr := strconv.Atoi(fields[1]); parseErr == nil && port > 0 && port <= 65535 {
					policy.SSH.Port = port
				}
			case "permitrootlogin":
				policy.SSH.PermitRootLogin = fields[1] != "no"
			case "passwordauthentication":
				policy.SSH.PasswordAuthentication = fields[1] == "yes"
			case "pubkeyauthentication":
				policy.SSH.PublicKeyAuthentication = fields[1] == "yes"
			case "allowtcpforwarding":
				policy.SSH.AllowTCPForwarding = fields[1] != "no"
			}
		}
	}
	if _, fail2BanErr := a.runner.Run(ctx, "fail2ban-client", "ping"); fail2BanErr == nil {
		policy.Fail2Ban.Enabled = true
	}
	return policy, nil
}

func rejectUnsafeSecurityTarget(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("managed nftables target is not a regular file")
	}
	return nil
}

func boundedSecurityOutput(output []byte) string {
	const limit = 2048
	value := strings.TrimSpace(string(output))
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}
