package types

import (
	"encoding/json"
	"time"
)

type Request struct {
	Op   string          `json:"op"`
	ID   string          `json:"id"`
	Data json.RawMessage `json:"data"`
}

type Response struct {
	ID    string          `json:"id"`
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

const (
	OpPing             = "ping"
	OpReloadService    = "reload_service"
	OpCreateSystemUser = "create_system_user"
	OpCreateSite       = "create_site"
	OpIssueCert        = "issue_cert"
	OpCreateDatabase   = "create_database"
	OpCreateBackup     = "create_backup"
	OpRestoreBackup    = "restore_backup"
	OpConfigureWebmail = "configure_webmail"
	OpConfigureDNSZone = "configure_dns_zone"
	OpReconcileSystem  = "reconcile_system"
)

type CreateSiteReq struct {
	Username   string             `json:"username"`
	Domain     string             `json:"domain"`
	PHPVersion string             `json:"php_version"`
	Docroot    string             `json:"docroot"`
	Limits     SiteResourceLimits `json:"limits"`
}

type SiteResourceLimits struct {
	DiskQuotaMB       int `json:"disk_quota_mb"`
	PHPFPMMaxChildren int `json:"php_max_children"`
	PHPMemoryMB       int `json:"php_memory_mb"`
}

type ReloadServiceReq struct {
	Name string `json:"name"`
}

type DBEngine string

const (
	EngineMariaDB DBEngine = "mariadb"
	EngineMySQL   DBEngine = "mysql"
	EnginePgSQL   DBEngine = "pgsql"
)

type CreateDatabaseReq struct {
	Engine   DBEngine `json:"engine"`
	DBName   string   `json:"db_name"`
	DBUser   string   `json:"db_user"`
	Password string   `json:"password"`
}

type CertIssuer string

const (
	CertIssuerLocalSelfSigned CertIssuer = "local-self-signed"
	CertIssuerACME            CertIssuer = "acme"
)

type IssueCertReq struct {
	Username   string     `json:"username"`
	Domain     string     `json:"domain"`
	PHPVersion string     `json:"php_version"`
	Issuer     CertIssuer `json:"issuer"`
}

type IssueCertResult struct {
	Domain    string     `json:"domain"`
	Issuer    CertIssuer `json:"issuer"`
	CertPath  string     `json:"cert_path"`
	KeyPath   string     `json:"key_path"`
	ExpiresAt time.Time  `json:"expires_at"`
}

type CreateBackupReq struct {
	Domain    string   `json:"domain"`
	Username  string   `json:"username"`
	Docroot   string   `json:"docroot"`
	Databases []string `json:"databases"`
	OutputDir string   `json:"output_dir"`
}

type CreateBackupResult struct {
	ArchivePath string `json:"archive_path"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}

type RestoreBackupReq struct {
	Domain      string   `json:"domain"`
	Username    string   `json:"username"`
	Docroot     string   `json:"docroot"`
	ArchivePath string   `json:"archive_path"`
	Databases   []string `json:"databases"`
}

type RestoreBackupResult struct {
	Domain            string   `json:"domain"`
	RestoredFiles     int      `json:"restored_files"`
	RestoredDatabases []string `json:"restored_databases"`
	PreviousDocroot   string   `json:"previous_docroot"`
}

type ConfigureWebmailReq struct {
	Domain        string `json:"domain"`
	Hostname      string `json:"hostname"`
	RoundcubeRoot string `json:"roundcube_root"`
}

type ConfigureWebmailResult struct {
	Hostname    string `json:"hostname"`
	ConfigPath  string `json:"config_path"`
	EnabledPath string `json:"enabled_path"`
}

type ConfigureDNSZoneReq struct {
	Domain  string `json:"domain"`
	Address string `json:"address"`
	Serial  int64  `json:"serial"`
	ZoneDir string `json:"zone_dir"`
}

type ConfigureDNSZoneResult struct {
	Domain      string `json:"domain"`
	ZonePath    string `json:"zone_path"`
	IncludePath string `json:"include_path"`
	Serial      int64  `json:"serial"`
}

type ReconcileSiteReq struct {
	Username      string `json:"username"`
	Domain        string `json:"domain"`
	PHPVersion    string `json:"php_version"`
	EnableWebmail bool   `json:"enable_webmail"`
	EnableDNS     bool   `json:"enable_dns"`
	Address       string `json:"address"`
}

type ReconcileSystemReq struct {
	Sites []ReconcileSiteReq `json:"sites"`
}

type ReconcileSystemResult struct {
	SitesTotal int `json:"sites_total"`
	SitesOK    int `json:"sites_ok"`
}

type AdminerSSO struct {
	Token         string `json:"token"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}
