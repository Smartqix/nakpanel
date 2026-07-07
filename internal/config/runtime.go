package config

import (
	"fmt"
	"os"
)

type PanelRuntimeConfig struct {
	HTTPSAddr   string
	DatabaseURL string
	TLSDir      string
}

func PanelRuntimeConfigFromEnv() PanelRuntimeConfig {
	databaseURL := os.Getenv("NAKPANEL_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = DefaultDatabaseURL
	}

	tlsDir := os.Getenv("NAKPANEL_TLS_DIR")
	if tlsDir == "" {
		tlsDir = PanelTLSDir
	}

	return PanelRuntimeConfig{
		HTTPSAddr:   fmt.Sprintf(":%d", PanelPort),
		DatabaseURL: databaseURL,
		TLSDir:      tlsDir,
	}
}
