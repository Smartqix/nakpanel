package config

import "testing"

func TestPanelRuntimeConfigDefaults(t *testing.T) {
	t.Setenv("NAKPANEL_DATABASE_URL", "")
	t.Setenv("NAKPANEL_TLS_DIR", "")

	cfg := PanelRuntimeConfigFromEnv()

	if cfg.HTTPSAddr != ":7443" {
		t.Fatalf("HTTPSAddr = %q, want :7443", cfg.HTTPSAddr)
	}
	if cfg.DatabaseURL != DefaultDatabaseURL {
		t.Fatalf("DatabaseURL = %q, want default", cfg.DatabaseURL)
	}
	if cfg.TLSDir != PanelTLSDir {
		t.Fatalf("TLSDir = %q, want %q", cfg.TLSDir, PanelTLSDir)
	}
	if cfg.FileTransferDir != FileTransferDir || cfg.FileUploadMaxBytes != DefaultFileUploadMaxBytes {
		t.Fatalf("file manager defaults = %q %d", cfg.FileTransferDir, cfg.FileUploadMaxBytes)
	}
}

func TestPanelRuntimeConfigEnvOverrides(t *testing.T) {
	t.Setenv("NAKPANEL_DATABASE_URL", "postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable")
	t.Setenv("NAKPANEL_TLS_DIR", "/tmp/nakpanel-tls")
	t.Setenv("NAKPANEL_FILE_TRANSFER_DIR", "/tmp/nakpanel-files")
	t.Setenv("NAKPANEL_FILE_UPLOAD_MAX_BYTES", "1048576")

	cfg := PanelRuntimeConfigFromEnv()

	if cfg.DatabaseURL != "postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable" {
		t.Fatalf("DatabaseURL = %q", cfg.DatabaseURL)
	}
	if cfg.TLSDir != "/tmp/nakpanel-tls" {
		t.Fatalf("TLSDir = %q", cfg.TLSDir)
	}
	if cfg.FileTransferDir != "/tmp/nakpanel-files" || cfg.FileUploadMaxBytes != 1048576 {
		t.Fatalf("file manager overrides = %q %d", cfg.FileTransferDir, cfg.FileUploadMaxBytes)
	}
}
