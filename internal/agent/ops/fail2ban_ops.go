package ops

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

// Fail2BanController applies the managed jail policy directly (validate ->
// atomic write -> reload, restoring the previous file when the reload fails)
// and exposes ban listing and unbanning. Unlike the firewall path there is no
// timed confirmation window: a bad jail policy cannot cut off SSH or the
// panel, and fail2ban-client recovers it in place.
type Fail2BanController struct {
	configPath string
	runner     CommandRunner
}

type Fail2BanControllerOptions struct {
	ConfigPath string
	Runner     CommandRunner
}

func NewFail2BanController(opts Fail2BanControllerOptions) *Fail2BanController {
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = Fail2BanConfigPath
	}
	runner := opts.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	return &Fail2BanController{configPath: configPath, runner: runner}
}

func fail2BanPolicyFromWire(wire types.Fail2BanPolicy, sshPorts []int) (Fail2BanPolicy, error) {
	policy := Fail2BanPolicy{
		BanTime:     time.Hour,
		FindTime:    10 * time.Minute,
		MaxRetry:    5,
		IgnoreCIDRs: append([]string(nil), wire.TrustedCIDRs...),
	}
	for _, port := range sshPorts {
		if port < 1 || port > 65535 {
			return policy, fmt.Errorf("invalid SSH port %d", port)
		}
		policy.SSHPorts = append(policy.SSHPorts, uint16(port))
	}
	if len(policy.SSHPorts) == 0 {
		policy.SSHPorts = []uint16{22}
	}
	for _, jail := range wire.Jails {
		if jail.BanTime > 0 {
			policy.BanTime = time.Duration(jail.BanTime) * time.Second
		}
		if jail.FindTime > 0 {
			policy.FindTime = time.Duration(jail.FindTime) * time.Second
		}
		policy.Jails = append(policy.Jails, Fail2BanJailPolicy{
			ID:       Fail2BanJailID(jail.ID),
			Enabled:  jail.Enabled,
			MaxRetry: jail.MaxRetry,
		})
	}
	if len(policy.Jails) == 0 {
		policy.Jails = []Fail2BanJailPolicy{
			{ID: Fail2BanSSHD, Enabled: true},
			{ID: Fail2BanPanelLogin, Enabled: true},
		}
	}
	return policy, nil
}

func (c *Fail2BanController) ApplyFail2BanPolicy(ctx context.Context, req types.ApplyFail2BanPolicyReq) (types.ApplyFail2BanPolicyResult, error) {
	var result types.ApplyFail2BanPolicyResult
	policy, err := fail2BanPolicyFromWire(req.Policy, req.SSHPorts)
	if err != nil {
		return result, err
	}
	rendered, err := RenderFail2BanPolicy(policy)
	if err != nil {
		return result, err
	}
	previous, previousErr := os.ReadFile(c.configPath)
	hadPrevious := previousErr == nil

	if err := os.MkdirAll(filepath.Dir(c.configPath), 0o755); err != nil {
		return result, err
	}
	if err := writeFileAtomic(c.configPath, []byte(rendered), 0o644); err != nil {
		return result, err
	}
	if out, err := c.runner.Run(ctx, "fail2ban-client", "reload"); err != nil {
		// Self-contained rollback: restore the previous file and reload again
		// so the daemon never stays on a config we could not activate.
		if hadPrevious {
			_ = writeFileAtomic(c.configPath, previous, 0o644)
		} else {
			_ = os.Remove(c.configPath)
		}
		_, _ = c.runner.Run(ctx, "fail2ban-client", "reload")
		return result, fmt.Errorf("fail2ban reload rejected the policy: %s", strings.TrimSpace(string(out)))
	}
	result.ConfigPath = c.configPath
	result.Reloaded = true
	return result, nil
}

func (c *Fail2BanController) ListSecurityBans(ctx context.Context) (types.SecurityBansResult, error) {
	result := types.SecurityBansResult{}
	if _, err := c.runner.Run(ctx, "fail2ban-client", "ping"); err != nil {
		return result, nil
	}
	result.Running = true
	out, err := c.runner.Run(ctx, "fail2ban-client", "status")
	if err != nil {
		return result, fmt.Errorf("fail2ban-client status: %w", err)
	}
	for _, jail := range parseFail2BanJailList(string(out)) {
		entry := types.JailBans{Jail: jail, Enabled: true}
		jailOut, err := c.runner.Run(ctx, "fail2ban-client", "status", jail)
		if err == nil {
			entry.Banned = parseFail2BanBannedIPs(string(jailOut))
		}
		result.Jails = append(result.Jails, entry)
	}
	return result, nil
}

// parseFail2BanJailList extracts the "Jail list:" line, stable across
// fail2ban 0.11 and 1.x.
func parseFail2BanJailList(output string) []string {
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, "Jail list:"); idx >= 0 {
			raw := strings.TrimSpace(line[idx+len("Jail list:"):])
			if raw == "" {
				return nil
			}
			parts := strings.Split(raw, ",")
			jails := make([]string, 0, len(parts))
			for _, part := range parts {
				if part = strings.TrimSpace(part); part != "" {
					jails = append(jails, part)
				}
			}
			return jails
		}
	}
	return nil
}

func parseFail2BanBannedIPs(output string) []string {
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, "Banned IP list:"); idx >= 0 {
			raw := strings.TrimSpace(line[idx+len("Banned IP list:"):])
			if raw == "" {
				return nil
			}
			return strings.Fields(raw)
		}
	}
	return nil
}

var fail2BanJailNameRE = securityRuleIDRE

func (c *Fail2BanController) UnbanSecurityAddress(ctx context.Context, req types.UnbanSecurityAddressReq) (types.UnbanSecurityAddressResult, error) {
	result := types.UnbanSecurityAddressResult{JailID: req.JailID, Address: req.Address}
	jail := strings.TrimSpace(req.JailID)
	if !fail2BanJailNameRE.MatchString(jail) {
		return result, errors.New("invalid jail id")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(req.Address))
	if err != nil {
		return result, errors.New("a valid IP address is required")
	}
	out, err := c.runner.Run(ctx, "fail2ban-client", "set", jail, "unbanip", address.String())
	if err != nil {
		detail := strings.TrimSpace(string(out))
		// "not banned" is the one benign outcome. Everything else (socket
		// permission denied, jail stopped, fail2ban not running) must surface
		// as an error: reporting success for those tells an operator an
		// address was released when it is still blocked. A substring test for
		// "0" would match almost any error text, including timestamps and
		// addresses, so match the phrase only.
		if strings.Contains(detail, "is not banned") || strings.Contains(detail, "not banned") {
			result.Unbanned = false
			return result, nil
		}
		return result, fmt.Errorf("fail2ban unban: %s", detail)
	}
	result.Unbanned = true
	return result, nil
}
