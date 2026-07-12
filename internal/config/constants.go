package config

const (
	PanelPort                       = 7443
	AgentSocket                     = "/run/nakpanel/agent.sock"
	PanelUser                       = "nakpanel"
	PanelTLSDir                     = "/var/lib/nakpanel/tls"
	FileTransferDir                 = "/var/lib/nakpanel/transfers"
	DefaultFileUploadMaxBytes int64 = 512 << 20
	DefaultDatabaseURL              = "postgres://postgres@localhost:5432/nakpanel?sslmode=disable"
)
