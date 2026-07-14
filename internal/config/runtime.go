package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type PanelRuntimeConfig struct {
	HTTPSAddr            string
	DatabaseURL          string
	TLSDir               string
	SMTPHost             string
	SMTPPort             int
	SMTPUsername         string
	SMTPPassword         string
	SMTPFrom             string
	SMTPTLSMode          string
	FileTransferDir      string
	FileUploadMaxBytes   int64
	PublicURL            string
	BillingWebhookURL    string
	BillingWebhookSecret string
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

	smtpPort, err := strconv.Atoi(strings.TrimSpace(os.Getenv("NAKPANEL_SMTP_PORT")))
	if err != nil || smtpPort <= 0 || smtpPort > 65535 {
		smtpPort = 587
	}
	tlsMode := strings.ToLower(strings.TrimSpace(os.Getenv("NAKPANEL_SMTP_TLS_MODE")))
	if tlsMode == "" {
		tlsMode = "starttls"
	}
	return PanelRuntimeConfig{
		HTTPSAddr:            fmt.Sprintf(":%d", PanelPort),
		DatabaseURL:          databaseURL,
		TLSDir:               tlsDir,
		SMTPHost:             strings.TrimSpace(os.Getenv("NAKPANEL_SMTP_HOST")),
		SMTPPort:             smtpPort,
		SMTPUsername:         strings.TrimSpace(os.Getenv("NAKPANEL_SMTP_USERNAME")),
		SMTPPassword:         os.Getenv("NAKPANEL_SMTP_PASSWORD"),
		SMTPFrom:             strings.TrimSpace(os.Getenv("NAKPANEL_SMTP_FROM")),
		SMTPTLSMode:          tlsMode,
		FileTransferDir:      firstConfigured(os.Getenv("NAKPANEL_FILE_TRANSFER_DIR"), FileTransferDir),
		FileUploadMaxBytes:   positiveInt64(os.Getenv("NAKPANEL_FILE_UPLOAD_MAX_BYTES"), DefaultFileUploadMaxBytes),
		PublicURL:            strings.TrimRight(strings.TrimSpace(os.Getenv("NAKPANEL_PUBLIC_URL")), "/"),
		BillingWebhookURL:    strings.TrimSpace(os.Getenv("NAKPANEL_BILLING_WEBHOOK_URL")),
		BillingWebhookSecret: os.Getenv("NAKPANEL_BILLING_WEBHOOK_SECRET"),
	}
}

func firstConfigured(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func positiveInt64(value string, fallback int64) int64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
