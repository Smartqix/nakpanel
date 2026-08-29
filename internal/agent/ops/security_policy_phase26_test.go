package ops

import (
	"strings"
	"testing"
	"time"
)

func TestRenderNftablesPolicyKeepsManagementRecoveryAndTypedRules(t *testing.T) {
	rendered, err := RenderNftablesPolicy(NftablesPolicy{
		DefaultInput: NftablesInputDrop,
		PanelPort:    7443,
		SSHPorts:     []uint16{2222, 22},
		Rules: []NftablesRule{
			{ID: "web", Action: NftablesRuleAccept, Transport: NftablesTCP, PortStart: 80, PortEnd: 443},
			{
				ID: "dns", Action: NftablesRuleAccept, Transport: NftablesUDP, PortStart: 53,
				SourceCIDRs: []string{"2001:db8::/32", "192.0.2.0/24"},
			},
		},
	})
	if err != nil {
		t.Fatalf("RenderNftablesPolicy returned error: %v", err)
	}
	for _, want := range []string{
		"table inet nakpanel {",
		"policy drop;",
		`tcp dport 7443 accept comment "nakpanel-panel-recovery"`,
		`tcp dport { 22, 2222 } accept comment "nakpanel-ssh-recovery"`,
		`tcp dport 80-443 accept comment "nakpanel-rule-web"`,
		`ip saddr 192.0.2.0/24 udp dport 53 accept comment "nakpanel-rule-dns"`,
		`ip6 saddr 2001:db8::/32 udp dport 53 accept comment "nakpanel-rule-dns"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered nftables policy missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "flush ruleset") {
		t.Fatalf("renderer must not flush operator-owned tables:\n%s", rendered)
	}
}

func TestValidateNftablesPolicyRejectsUntypedOrInjectableValues(t *testing.T) {
	valid := NftablesPolicy{
		DefaultInput: NftablesInputDrop, PanelPort: 7443, SSHPorts: []uint16{22},
		Rules: []NftablesRule{{ID: "web", Action: NftablesRuleAccept, Transport: NftablesTCP, PortStart: 443}},
	}
	tests := []struct {
		name   string
		mutate func(*NftablesPolicy)
	}{
		{"default action", func(p *NftablesPolicy) { p.DefaultInput = "drop; include /tmp/evil" }},
		{"duplicate SSH port", func(p *NftablesPolicy) { p.SSHPorts = []uint16{22, 22} }},
		{"rule id injection", func(p *NftablesPolicy) { p.Rules[0].ID = "web\"\nflush ruleset" }},
		{"action injection", func(p *NftablesPolicy) { p.Rules[0].Action = "accept; counter" }},
		{"protocol injection", func(p *NftablesPolicy) { p.Rules[0].Transport = "tcp dport 22 accept" }},
		{"invalid range", func(p *NftablesPolicy) { p.Rules[0].PortStart, p.Rules[0].PortEnd = 443, 80 }},
		{"source injection", func(p *NftablesPolicy) { p.Rules[0].SourceCIDRs = []string{"192.0.2.0/24\naccept"} }},
		{"bare source address", func(p *NftablesPolicy) { p.Rules[0].SourceCIDRs = []string{"192.0.2.1"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := valid
			policy.SSHPorts = append([]uint16(nil), valid.SSHPorts...)
			policy.Rules = append([]NftablesRule(nil), valid.Rules...)
			test.mutate(&policy)
			if err := ValidateNftablesPolicy(policy); err == nil {
				t.Fatalf("ValidateNftablesPolicy accepted invalid policy: %+v", policy)
			}
		})
	}
}

func TestRenderFail2BanPolicyUsesOnlyRegisteredJails(t *testing.T) {
	rendered, err := RenderFail2BanPolicy(Fail2BanPolicy{
		BanTime: 15 * time.Minute, FindTime: 10 * time.Minute, MaxRetry: 5,
		SSHPorts:    []uint16{2222, 22},
		IgnoreCIDRs: []string{"2001:db8::/48", "192.0.2.10"},
		Jails: []Fail2BanJailPolicy{
			{ID: Fail2BanPanelLogin, Enabled: true, MaxRetry: 4},
			{ID: Fail2BanSSHD, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("RenderFail2BanPolicy returned error: %v", err)
	}
	for _, want := range []string{
		"bantime = 900",
		"findtime = 600",
		"ignoreip = ",
		"127.0.0.1/8",
		"::1/128",
		"[nakpanel-login]",
		"filter = nakpanel-login",
		"[sshd]",
		"backend = systemd",
		"port = 22,2222",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered Fail2Ban policy missing %q:\n%s", want, rendered)
		}
	}
	// The panel jail reads journald via its filter's journalmatch; a log file
	// must never be referenced.
	if strings.Contains(rendered, "logpath = /var/log/nakpanel/panel.log") {
		t.Fatalf("nakpanel-login jail still references the unwritten panel log file:\n%s", rendered)
	}
}

func TestValidateFail2BanPolicyRejectsUnknownJailsAndInjection(t *testing.T) {
	base := Fail2BanPolicy{
		BanTime: time.Hour, FindTime: 10 * time.Minute, MaxRetry: 5,
		SSHPorts: []uint16{22},
		Jails:    []Fail2BanJailPolicy{{ID: Fail2BanSSHD, Enabled: true}},
	}
	tests := []Fail2BanPolicy{
		{BanTime: time.Second, FindTime: base.FindTime, MaxRetry: 5, SSHPorts: base.SSHPorts, Jails: base.Jails},
		{BanTime: base.BanTime, FindTime: base.FindTime, MaxRetry: 0, SSHPorts: base.SSHPorts, Jails: base.Jails},
		{BanTime: base.BanTime, FindTime: base.FindTime, MaxRetry: 5, SSHPorts: base.SSHPorts, Jails: []Fail2BanJailPolicy{{ID: "sshd]\naction = evil", Enabled: true}}},
		{BanTime: base.BanTime, FindTime: base.FindTime, MaxRetry: 5, SSHPorts: base.SSHPorts, IgnoreCIDRs: []string{"127.0.0.1\nignorecommand=x"}, Jails: base.Jails},
		{BanTime: base.BanTime, FindTime: base.FindTime, MaxRetry: 5, SSHPorts: base.SSHPorts, Jails: []Fail2BanJailPolicy{{ID: Fail2BanSSHD}, {ID: Fail2BanSSHD}}},
		{BanTime: base.BanTime, FindTime: base.FindTime, MaxRetry: 5, Jails: base.Jails},
	}
	for i, policy := range tests {
		if err := ValidateFail2BanPolicy(policy); err == nil {
			t.Fatalf("invalid Fail2Ban policy #%d was accepted: %+v", i, policy)
		}
	}
}

func TestRenderSSHPolicySupportsSafeDualPortTransition(t *testing.T) {
	rendered, err := RenderSSHPolicy(SSHPolicy{
		Ports: []uint16{2222, 22}, RootLogin: SSHRootLoginKeyOnly,
		PasswordAuthentication: false, MaxAuthTries: 4, LoginGraceSeconds: 30,
		ClientAliveSeconds: 300, AllowTCPForwarding: false, AllowAgentForwarding: false,
	})
	if err != nil {
		t.Fatalf("RenderSSHPolicy returned error: %v", err)
	}
	wantOrder := []string{
		"Port 22\n",
		"Port 2222\n",
		"PasswordAuthentication no\n",
		"PermitRootLogin prohibit-password\n",
		"AllowTcpForwarding no\n",
		"PermitTunnel no\n",
	}
	previous := -1
	for _, want := range wantOrder {
		index := strings.Index(rendered, want)
		if index == -1 {
			t.Fatalf("rendered SSH policy missing %q:\n%s", want, rendered)
		}
		if index <= previous {
			t.Fatalf("SSH setting %q rendered out of deterministic order:\n%s", want, rendered)
		}
		previous = index
	}
}

func TestValidateSSHPolicyRejectsLockoutAndUnsupportedModes(t *testing.T) {
	base := SSHPolicy{
		Ports: []uint16{22}, RootLogin: SSHRootLoginDisabled,
		MaxAuthTries: 4, LoginGraceSeconds: 30, ClientAliveSeconds: 300,
	}
	tests := []SSHPolicy{
		{Ports: nil, RootLogin: base.RootLogin, MaxAuthTries: 4, LoginGraceSeconds: 30, ClientAliveSeconds: 300},
		{Ports: []uint16{22, 2222, 2200}, RootLogin: base.RootLogin, MaxAuthTries: 4, LoginGraceSeconds: 30, ClientAliveSeconds: 300},
		{Ports: []uint16{22, 22}, RootLogin: base.RootLogin, MaxAuthTries: 4, LoginGraceSeconds: 30, ClientAliveSeconds: 300},
		{Ports: base.Ports, RootLogin: "yes\nMatch all", MaxAuthTries: 4, LoginGraceSeconds: 30, ClientAliveSeconds: 300},
		{Ports: base.Ports, RootLogin: base.RootLogin, MaxAuthTries: 0, LoginGraceSeconds: 30, ClientAliveSeconds: 300},
		{Ports: base.Ports, RootLogin: base.RootLogin, MaxAuthTries: 4, LoginGraceSeconds: 1, ClientAliveSeconds: 300},
	}
	for i, policy := range tests {
		if err := ValidateSSHPolicy(policy); err == nil {
			t.Fatalf("invalid SSH policy #%d was accepted: %+v", i, policy)
		}
	}
}
