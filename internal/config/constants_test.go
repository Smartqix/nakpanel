package config

import "testing"

func TestPanelBoundaryConstants(t *testing.T) {
	if PanelPort != 7443 {
		t.Fatalf("PanelPort = %d, want 7443", PanelPort)
	}

	if AgentSocket != "/run/nakpanel/agent.sock" {
		t.Fatalf("AgentSocket = %q, want /run/nakpanel/agent.sock", AgentSocket)
	}

	if PanelUser != "nakpanel" {
		t.Fatalf("PanelUser = %q, want nakpanel", PanelUser)
	}
}
