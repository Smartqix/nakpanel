package ops

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	NftablesConfigPath = "/etc/nftables.d/nakpanel.nft"
	NftablesTableName  = "nakpanel"
	Fail2BanConfigPath = "/etc/fail2ban/jail.d/nakpanel.local"
	SSHConfigPath      = "/etc/ssh/sshd_config.d/90-nakpanel.conf"
)

type NftablesInputPolicy string

const (
	NftablesInputAccept NftablesInputPolicy = "accept"
	NftablesInputDrop   NftablesInputPolicy = "drop"
)

type NftablesRuleAction string

const (
	NftablesRuleAccept NftablesRuleAction = "accept"
	NftablesRuleDrop   NftablesRuleAction = "drop"
	NftablesRuleReject NftablesRuleAction = "reject"
)

type NftablesTransport string

const (
	NftablesTCP NftablesTransport = "tcp"
	NftablesUDP NftablesTransport = "udp"
)

type NftablesRule struct {
	ID          string
	Action      NftablesRuleAction
	Transport   NftablesTransport
	PortStart   uint16
	PortEnd     uint16
	SourceCIDRs []string
}

// NftablesPolicy intentionally describes only Nakpanel's input chain. The
// applier owns table replacement and must never flush tables owned by Podman,
// Fail2Ban, or an operator.
type NftablesPolicy struct {
	DefaultInput NftablesInputPolicy
	PanelPort    uint16
	SSHPorts     []uint16
	Rules        []NftablesRule
}

var securityRuleIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func ValidateNftablesPolicy(policy NftablesPolicy) error {
	if policy.DefaultInput != NftablesInputAccept && policy.DefaultInput != NftablesInputDrop {
		return errors.New("nftables input policy must be accept or drop")
	}
	if policy.PanelPort == 0 {
		return errors.New("panel recovery port is required")
	}
	if len(policy.SSHPorts) == 0 || len(policy.SSHPorts) > 2 {
		return errors.New("one or two SSH recovery ports are required")
	}
	if err := validateUniquePorts(policy.SSHPorts); err != nil {
		return fmt.Errorf("SSH recovery ports: %w", err)
	}
	if len(policy.Rules) > 256 {
		return errors.New("nftables policy exceeds 256 custom rules")
	}
	ids := make(map[string]struct{}, len(policy.Rules))
	for i, rule := range policy.Rules {
		if !securityRuleIDRE.MatchString(rule.ID) {
			return fmt.Errorf("nftables rule %d has an invalid id", i)
		}
		if _, exists := ids[rule.ID]; exists {
			return fmt.Errorf("nftables rule id %q is duplicated", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		switch rule.Action {
		case NftablesRuleAccept, NftablesRuleDrop, NftablesRuleReject:
		default:
			return fmt.Errorf("nftables rule %q has an invalid action", rule.ID)
		}
		if rule.Transport != NftablesTCP && rule.Transport != NftablesUDP {
			return fmt.Errorf("nftables rule %q has an invalid transport", rule.ID)
		}
		if rule.PortStart == 0 {
			return fmt.Errorf("nftables rule %q requires a port", rule.ID)
		}
		if rule.PortEnd != 0 && rule.PortEnd < rule.PortStart {
			return fmt.Errorf("nftables rule %q has an invalid port range", rule.ID)
		}
		if len(rule.SourceCIDRs) > 64 {
			return fmt.Errorf("nftables rule %q exceeds 64 source networks", rule.ID)
		}
		if _, _, err := canonicalCIDRs(rule.SourceCIDRs); err != nil {
			return fmt.Errorf("nftables rule %q: %w", rule.ID, err)
		}
	}
	return nil
}

func RenderNftablesPolicy(policy NftablesPolicy) (string, error) {
	if err := ValidateNftablesPolicy(policy); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# Managed by Nakpanel. Local rules belong outside table inet nakpanel.\n")
	b.WriteString("table inet " + NftablesTableName + " {\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority 0; policy " + string(policy.DefaultInput) + ";\n")
	b.WriteString("    iifname \"lo\" accept comment \"nakpanel-loopback\"\n")
	b.WriteString("    ct state established,related accept comment \"nakpanel-established\"\n")
	b.WriteString("    meta l4proto { icmp, ipv6-icmp } accept comment \"nakpanel-control-traffic\"\n")
	b.WriteString("    tcp dport " + strconv.Itoa(int(policy.PanelPort)) + " accept comment \"nakpanel-panel-recovery\"\n")
	b.WriteString("    tcp dport " + renderPortSet(policy.SSHPorts) + " accept comment \"nakpanel-ssh-recovery\"\n")

	for _, rule := range policy.Rules {
		v4, v6, _ := canonicalCIDRs(rule.SourceCIDRs)
		if len(v4) == 0 && len(v6) == 0 {
			renderNftablesRuleLine(&b, rule, "", nil)
			continue
		}
		if len(v4) > 0 {
			renderNftablesRuleLine(&b, rule, "ip saddr", v4)
		}
		if len(v6) > 0 {
			renderNftablesRuleLine(&b, rule, "ip6 saddr", v6)
		}
	}

	b.WriteString("  }\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy accept;\n")
	b.WriteString("  }\n")
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority 0; policy accept;\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func renderNftablesRuleLine(b *strings.Builder, rule NftablesRule, sourceKeyword string, sources []string) {
	b.WriteString("    ")
	if sourceKeyword != "" {
		b.WriteString(sourceKeyword)
		b.WriteByte(' ')
		if len(sources) == 1 {
			b.WriteString(sources[0])
		} else {
			b.WriteString("{ ")
			b.WriteString(strings.Join(sources, ", "))
			b.WriteString(" }")
		}
		b.WriteByte(' ')
	}
	b.WriteString(string(rule.Transport))
	b.WriteString(" dport ")
	end := rule.PortEnd
	if end == 0 {
		end = rule.PortStart
	}
	if end == rule.PortStart {
		b.WriteString(strconv.Itoa(int(rule.PortStart)))
	} else {
		b.WriteString(strconv.Itoa(int(rule.PortStart)))
		b.WriteByte('-')
		b.WriteString(strconv.Itoa(int(end)))
	}
	b.WriteByte(' ')
	b.WriteString(string(rule.Action))
	b.WriteString(" comment \"nakpanel-rule-")
	b.WriteString(rule.ID)
	b.WriteString("\"\n")
}

func renderPortSet(ports []uint16) string {
	values := append([]uint16(nil), ports...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	if len(values) == 1 {
		return strconv.Itoa(int(values[0]))
	}
	rendered := make([]string, 0, len(values))
	for _, port := range values {
		rendered = append(rendered, strconv.Itoa(int(port)))
	}
	return "{ " + strings.Join(rendered, ", ") + " }"
}

func validateUniquePorts(ports []uint16) error {
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			return errors.New("port must be between 1 and 65535")
		}
		if _, exists := seen[port]; exists {
			return fmt.Errorf("port %d is duplicated", port)
		}
		seen[port] = struct{}{}
	}
	return nil
}

func canonicalCIDRs(values []string) (v4 []string, v6 []string, err error) {
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		if value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t ") {
			return nil, nil, fmt.Errorf("invalid source network %q", value)
		}
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || !prefix.IsValid() {
			return nil, nil, fmt.Errorf("invalid source network %q", value)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			return nil, nil, fmt.Errorf("source network %q is duplicated", prefix)
		}
		seen[prefix] = struct{}{}
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix.String())
		} else {
			v6 = append(v6, prefix.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, nil
}

type Fail2BanJailID string

const (
	Fail2BanSSHD          Fail2BanJailID = "sshd"
	Fail2BanNginxHTTPAuth Fail2BanJailID = "nginx-http-auth"
	Fail2BanNginxBot      Fail2BanJailID = "nginx-botsearch"
	Fail2BanPanelLogin    Fail2BanJailID = "nakpanel-login"
)

type Fail2BanJailPolicy struct {
	ID       Fail2BanJailID
	Enabled  bool
	MaxRetry int
}

type Fail2BanPolicy struct {
	BanTime     time.Duration
	FindTime    time.Duration
	MaxRetry    int
	SSHPorts    []uint16
	IgnoreCIDRs []string
	Jails       []Fail2BanJailPolicy
}

type fail2BanJailDefinition struct {
	filter  string
	port    string
	logPath string
	backend string
}

var fail2BanJailRegistry = map[Fail2BanJailID]fail2BanJailDefinition{
	Fail2BanSSHD:          {filter: "sshd", port: "ssh", backend: "systemd"},
	Fail2BanNginxHTTPAuth: {filter: "nginx-http-auth", port: "http,https", logPath: "/var/log/nginx/error.log"},
	Fail2BanNginxBot:      {filter: "nginx-botsearch", port: "http,https", logPath: "/var/log/nginx/access.log"},
	// The panel logs auth failures to stderr -> journald; the filter's
	// journalmatch pins _SYSTEMD_UNIT=nakpanel.service, so no log file is
	// needed (see deploy/fail2ban/nakpanel-login.conf).
	Fail2BanPanelLogin: {filter: "nakpanel-login", port: "7443", backend: "systemd"},
}

func ValidateFail2BanPolicy(policy Fail2BanPolicy) error {
	if policy.BanTime < time.Minute || policy.BanTime > 365*24*time.Hour {
		return errors.New("Fail2Ban ban time must be between 1 minute and 365 days")
	}
	if policy.FindTime < time.Minute || policy.FindTime > 30*24*time.Hour {
		return errors.New("Fail2Ban find time must be between 1 minute and 30 days")
	}
	if policy.MaxRetry < 1 || policy.MaxRetry > 20 {
		return errors.New("Fail2Ban max retry must be between 1 and 20")
	}
	if len(policy.IgnoreCIDRs) > 64 {
		return errors.New("Fail2Ban policy exceeds 64 ignored networks")
	}
	if _, err := canonicalAddressesAndCIDRs(policy.IgnoreCIDRs); err != nil {
		return err
	}
	if len(policy.Jails) == 0 || len(policy.Jails) > len(fail2BanJailRegistry) {
		return errors.New("Fail2Ban policy requires at least one known jail")
	}
	seen := make(map[Fail2BanJailID]struct{}, len(policy.Jails))
	hasSSHD := false
	for _, jail := range policy.Jails {
		if _, exists := fail2BanJailRegistry[jail.ID]; !exists {
			return fmt.Errorf("Fail2Ban jail %q is not managed by Nakpanel", jail.ID)
		}
		if _, exists := seen[jail.ID]; exists {
			return fmt.Errorf("Fail2Ban jail %q is duplicated", jail.ID)
		}
		seen[jail.ID] = struct{}{}
		if jail.MaxRetry < 0 || jail.MaxRetry > 20 {
			return fmt.Errorf("Fail2Ban jail %q max retry must be 0 or between 1 and 20", jail.ID)
		}
		hasSSHD = hasSSHD || jail.ID == Fail2BanSSHD
	}
	if hasSSHD {
		if len(policy.SSHPorts) == 0 || len(policy.SSHPorts) > 2 {
			return errors.New("Fail2Ban SSH jail requires one or two SSH ports")
		}
		if err := validateUniquePorts(policy.SSHPorts); err != nil {
			return fmt.Errorf("Fail2Ban SSH ports: %w", err)
		}
	}
	return nil
}

func RenderFail2BanPolicy(policy Fail2BanPolicy) (string, error) {
	if err := ValidateFail2BanPolicy(policy); err != nil {
		return "", err
	}
	ignored, _ := canonicalAddressesAndCIDRs(policy.IgnoreCIDRs)
	ignored = append([]string{"127.0.0.1/8", "::1/128"}, ignored...)
	ignored = uniqueSortedStrings(ignored)

	var b strings.Builder
	b.WriteString("# Managed by Nakpanel. Only registered jails are rendered.\n")
	b.WriteString("[DEFAULT]\n")
	b.WriteString("bantime = " + strconv.FormatInt(int64(policy.BanTime/time.Second), 10) + "\n")
	b.WriteString("findtime = " + strconv.FormatInt(int64(policy.FindTime/time.Second), 10) + "\n")
	b.WriteString("maxretry = " + strconv.Itoa(policy.MaxRetry) + "\n")
	b.WriteString("ignoreip = " + strings.Join(ignored, " ") + "\n")
	b.WriteString("banaction = nftables-multiport\n")
	b.WriteString("banaction_allports = nftables-allports\n")

	jails := append([]Fail2BanJailPolicy(nil), policy.Jails...)
	sort.Slice(jails, func(i, j int) bool { return jails[i].ID < jails[j].ID })
	for _, jail := range jails {
		definition := fail2BanJailRegistry[jail.ID]
		b.WriteString("\n[" + string(jail.ID) + "]\n")
		b.WriteString("enabled = " + yesNo(jail.Enabled) + "\n")
		b.WriteString("filter = " + definition.filter + "\n")
		if jail.ID == Fail2BanSSHD {
			b.WriteString("port = " + renderCommaPorts(policy.SSHPorts) + "\n")
		} else {
			b.WriteString("port = " + definition.port + "\n")
		}
		if definition.backend != "" {
			b.WriteString("backend = " + definition.backend + "\n")
		}
		if definition.logPath != "" {
			b.WriteString("logpath = " + definition.logPath + "\n")
		}
		if jail.MaxRetry > 0 {
			b.WriteString("maxretry = " + strconv.Itoa(jail.MaxRetry) + "\n")
		}
	}
	return b.String(), nil
}

func renderCommaPorts(ports []uint16) string {
	values := append([]uint16(nil), ports...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	rendered := make([]string, 0, len(values))
	for _, port := range values {
		rendered = append(rendered, strconv.Itoa(int(port)))
	}
	return strings.Join(rendered, ",")
}

func canonicalAddressesAndCIDRs(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t ") {
			return nil, fmt.Errorf("invalid address or network %q", value)
		}
		canonical := ""
		if address, err := netip.ParseAddr(value); err == nil {
			canonical = address.String()
		} else if prefix, err := netip.ParsePrefix(value); err == nil {
			canonical = prefix.Masked().String()
		} else {
			return nil, fmt.Errorf("invalid address or network %q", value)
		}
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("address or network %q is duplicated", canonical)
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func yesNo(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

type SSHRootLoginPolicy string

const (
	SSHRootLoginDisabled SSHRootLoginPolicy = "disabled"
	SSHRootLoginKeyOnly  SSHRootLoginPolicy = "key-only"
)

type SSHPolicy struct {
	Ports                  []uint16
	RootLogin              SSHRootLoginPolicy
	PasswordAuthentication bool
	MaxAuthTries           uint8
	LoginGraceSeconds      uint16
	ClientAliveSeconds     uint16
	AllowTCPForwarding     bool
	AllowAgentForwarding   bool
}

func ValidateSSHPolicy(policy SSHPolicy) error {
	if len(policy.Ports) == 0 || len(policy.Ports) > 2 {
		return errors.New("SSH policy requires one port, or two during a staged port change")
	}
	if err := validateUniquePorts(policy.Ports); err != nil {
		return fmt.Errorf("SSH ports: %w", err)
	}
	if policy.RootLogin != SSHRootLoginDisabled && policy.RootLogin != SSHRootLoginKeyOnly {
		return errors.New("SSH root login must be disabled or key-only")
	}
	if policy.MaxAuthTries < 1 || policy.MaxAuthTries > 10 {
		return errors.New("SSH max authentication tries must be between 1 and 10")
	}
	if policy.LoginGraceSeconds < 10 || policy.LoginGraceSeconds > 120 {
		return errors.New("SSH login grace time must be between 10 and 120 seconds")
	}
	if policy.ClientAliveSeconds < 30 || policy.ClientAliveSeconds > 3600 {
		return errors.New("SSH client-alive interval must be between 30 and 3600 seconds")
	}
	return nil
}

func RenderSSHPolicy(policy SSHPolicy) (string, error) {
	if err := ValidateSSHPolicy(policy); err != nil {
		return "", err
	}
	ports := append([]uint16(nil), policy.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })

	var b strings.Builder
	b.WriteString("# Managed by Nakpanel. Validate with sshd -t before activation.\n")
	for _, port := range ports {
		b.WriteString("Port " + strconv.Itoa(int(port)) + "\n")
	}
	b.WriteString("Protocol 2\n")
	b.WriteString("PubkeyAuthentication yes\n")
	b.WriteString("PasswordAuthentication " + sshYesNo(policy.PasswordAuthentication) + "\n")
	b.WriteString("KbdInteractiveAuthentication no\n")
	b.WriteString("PermitEmptyPasswords no\n")
	if policy.RootLogin == SSHRootLoginKeyOnly {
		b.WriteString("PermitRootLogin prohibit-password\n")
	} else {
		b.WriteString("PermitRootLogin no\n")
	}
	b.WriteString("MaxAuthTries " + strconv.Itoa(int(policy.MaxAuthTries)) + "\n")
	b.WriteString("LoginGraceTime " + strconv.Itoa(int(policy.LoginGraceSeconds)) + "\n")
	b.WriteString("ClientAliveInterval " + strconv.Itoa(int(policy.ClientAliveSeconds)) + "\n")
	b.WriteString("ClientAliveCountMax 3\n")
	b.WriteString("AllowTcpForwarding " + sshYesNo(policy.AllowTCPForwarding) + "\n")
	b.WriteString("AllowAgentForwarding " + sshYesNo(policy.AllowAgentForwarding) + "\n")
	b.WriteString("X11Forwarding no\n")
	b.WriteString("PermitTunnel no\n")
	return b.String(), nil
}

func sshYesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
