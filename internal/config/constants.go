package config

const (
	PanelPort          = 7443
	AgentSocket        = "/run/nakpanel/agent.sock"
	PanelUser          = "nakpanel"
	PanelTLSDir        = "/var/lib/nakpanel/tls"
	DefaultDatabaseURL = "postgres://postgres@localhost:5432/nakpanel?sslmode=disable"
)
