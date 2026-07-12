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
	OpPing                = "ping"
	OpReloadService       = "reload_service"
	OpCreateSystemUser    = "create_system_user"
	OpCreateSite          = "create_site"
	OpIssueCert           = "issue_cert"
	OpCreateDatabase      = "create_database"
	OpCreateBackup        = "create_backup"
	OpRestoreBackup       = "restore_backup"
	OpConfigureWebmail    = "configure_webmail"
	OpConfigureDNSZone    = "configure_dns_zone"
	OpReconcileSystem     = "reconcile_system"
	OpSetHostingState     = "set_hosting_state"
	OpApplySiteRuntime    = "apply_site_runtime"
	OpCollectUsage        = "collect_usage"
	OpRuntimeCapabilities = "runtime_capabilities"
	OpListFiles           = "list_files"
	OpSearchFiles         = "search_files"
	OpReadFile            = "read_file"
	OpWriteFile           = "write_file"
	OpCreateFileEntry     = "create_file_entry"
	OpCopyFiles           = "copy_files"
	OpMoveFiles           = "move_files"
	OpDeleteFiles         = "delete_files"
	OpArchiveFiles        = "archive_files"
	OpExtractArchive      = "extract_archive"
	OpSetFileMode         = "set_file_mode"
	OpImportFileTransfer  = "import_file_transfer"
	OpExportFileTransfer  = "export_file_transfer"
)

type FileKind string

const (
	FileKindFile      FileKind = "file"
	FileKindDirectory FileKind = "directory"
	FileKindSymlink   FileKind = "symlink"
)

type FileEntry struct {
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	Kind         FileKind  `json:"kind"`
	Size         int64     `json:"size"`
	Mode         uint32    `json:"mode"`
	ModifiedAt   time.Time `json:"modified_at"`
	Owner        string    `json:"owner"`
	Group        string    `json:"group"`
	Editable     bool      `json:"editable"`
	Downloadable bool      `json:"downloadable"`
	Writable     bool      `json:"writable"`
	Renamable    bool      `json:"renamable"`
	Deletable    bool      `json:"deletable"`
	Chmod        bool      `json:"chmod"`
	Archive      bool      `json:"archive"`
}

type FileListReq struct {
	Username string `json:"username"`
	Path     string `json:"path"`
	Page     int    `json:"page"`
	PerPage  int    `json:"per_page"`
	Sort     string `json:"sort"`
	Order    string `json:"order"`
}

type FileListResult struct {
	Path        string      `json:"path"`
	Entries     []FileEntry `json:"entries"`
	Directories []FileEntry `json:"directories"`
	Total       int         `json:"total"`
	Page        int         `json:"page"`
	PerPage     int         `json:"per_page"`
}

type FileSearchReq struct {
	Username string `json:"username"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Limit    int    `json:"limit"`
	Sort     string `json:"sort"`
	Order    string `json:"order"`
}

type FileSearchResult struct {
	Entries   []FileEntry `json:"entries"`
	Truncated bool        `json:"truncated"`
}

type FileReadReq struct {
	Username string `json:"username"`
	Path     string `json:"path"`
}

type FileReadResult struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
	Mode    uint32 `json:"mode"`
}

type FileWriteReq struct {
	Username       string `json:"username"`
	Path           string `json:"path"`
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type FileCreateReq struct {
	Username string   `json:"username"`
	Path     string   `json:"path"`
	Kind     FileKind `json:"kind"`
}

type FileBatchReq struct {
	Username    string   `json:"username"`
	Paths       []string `json:"paths"`
	Destination string   `json:"destination"`
	NewName     string   `json:"new_name,omitempty"`
	Overwrite   bool     `json:"overwrite"`
}

type FileArchiveReq struct {
	Username    string   `json:"username"`
	Paths       []string `json:"paths"`
	Destination string   `json:"destination"`
}

type FileExtractReq struct {
	Username    string `json:"username"`
	Path        string `json:"path"`
	Destination string `json:"destination"`
	Overwrite   bool   `json:"overwrite"`
}

type FileModeReq struct {
	Username  string `json:"username"`
	Path      string `json:"path"`
	Mode      uint32 `json:"mode"`
	Recursive bool   `json:"recursive"`
}

type FileTransferImportReq struct {
	Username      string `json:"username"`
	TransferToken string `json:"transfer_token"`
	Destination   string `json:"destination"`
	Overwrite     bool   `json:"overwrite"`
}

type FileTransferExportReq struct {
	Username string `json:"username"`
	Path     string `json:"path"`
}

type FileTransferResult struct {
	TransferToken string    `json:"transfer_token"`
	Name          string    `json:"name"`
	Size          int64     `json:"size"`
	ModifiedAt    time.Time `json:"modified_at"`
}

type FileMutationResult struct {
	Paths []string `json:"paths"`
}

type CreateSiteReq struct {
	SubscriptionID int64              `json:"subscription_id"`
	Username       string             `json:"username"`
	Domain         string             `json:"domain"`
	PHPVersion     string             `json:"php_version"`
	Docroot        string             `json:"docroot"`
	Limits         SiteResourceLimits `json:"limits"`
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
	SubscriptionID int64    `json:"subscription_id"`
	SiteID         int64    `json:"site_id,omitempty"`
	Engine         DBEngine `json:"engine"`
	DBName         string   `json:"db_name"`
	DBUser         string   `json:"db_user"`
	Password       string   `json:"password"`
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
	SubscriptionID int64    `json:"subscription_id"`
	Domain         string   `json:"domain"`
	Username       string   `json:"username"`
	Docroot        string   `json:"docroot"`
	Databases      []string `json:"databases"`
	OutputDir      string   `json:"output_dir"`
}

type Customer struct {
	ID          int64     `json:"id"`
	LoginUserID int64     `json:"login_user_id,omitempty"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Company     string    `json:"company"`
	Status      string    `json:"status"`
	Notes       string    `json:"notes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ResellerID  int64     `json:"reseller_id,omitempty"`
}

type CreateCustomerReq struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Company     string `json:"company"`
	Notes       string `json:"notes"`
	EnableLogin bool   `json:"enable_login"`
	Password    string `json:"password,omitempty"`
	ResellerID  int64  `json:"reseller_id,omitempty"`
}

type CreateSubscriptionReq struct {
	ID               int64                    `json:"id,omitempty"`
	CustomerID       int64                    `json:"customer_id"`
	PlanID           int64                    `json:"plan_id"`
	SubscriptionName string                   `json:"subscription_name"`
	Status           string                   `json:"status"`
	SyncMode         string                   `json:"sync_mode,omitempty"`
	Entitlements     SubscriptionEntitlements `json:"entitlements,omitempty"`
}

type ProviderScope struct {
	ActorUserID int64  `json:"actor_user_id"`
	Role        string `json:"role"`
	ResellerID  int64  `json:"reseller_id,omitempty"`
}

type Reseller struct {
	ID          int64     `json:"id"`
	LoginUserID int64     `json:"login_user_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Company     string    `json:"company"`
	Status      string    `json:"status"`
	Notes       string    `json:"notes"`
	PlanName    string    `json:"plan_name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ResellerPlan struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	MaxCustomers     int       `json:"max_customers"`
	MaxSubscriptions int       `json:"max_subscriptions"`
	DiskMB           int       `json:"disk_mb"`
	MaxSites         int       `json:"max_sites"`
	MaxSubdomains    int       `json:"max_subdomains"`
	MaxDomainAliases int       `json:"max_domain_aliases"`
	MaxDatabases     int       `json:"max_databases"`
	BandwidthMB      int       `json:"bandwidth_mb"`
	MaxMailboxes     int       `json:"max_mailboxes"`
	MaxFTPAccounts   int       `json:"max_ftp_accounts"`
	MaxBackups       int       `json:"max_backups"`
	BackupStorageMB  int       `json:"backup_storage_mb"`
	AllowCustomPlans bool      `json:"allow_custom_plans"`
	AllowSSH         bool      `json:"allow_ssh"`
	AllowDNS         bool      `json:"allow_dns"`
	AllowTLS         bool      `json:"allow_tls"`
	AllowBackups     bool      `json:"allow_backups"`
	AllowPHPSettings bool      `json:"allow_php_settings"`
	IsActive         bool      `json:"is_active"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type ResellerSubscription struct {
	ID             int64     `json:"id"`
	ResellerID     int64     `json:"reseller_id"`
	ResellerPlanID int64     `json:"reseller_plan_id"`
	PlanName       string    `json:"plan_name"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SubscriptionEntitlements struct {
	SubscriptionID        int64              `json:"subscription_id"`
	PlanName              string             `json:"plan_name"`
	DiskMB                int                `json:"disk_mb"`
	MaxSites              int                `json:"max_sites"`
	MaxDatabases          int                `json:"max_databases"`
	BandwidthMB           int                `json:"bandwidth_mb"`
	MaxMailboxes          int                `json:"max_mailboxes"`
	AllowSSH              bool               `json:"allow_ssh"`
	AllowDNS              bool               `json:"allow_dns"`
	BackupRetentionDays   int                `json:"backup_retention_days"`
	PHPAllowlist          string             `json:"php_allowlist"`
	PHPFPMMaxChildren     int                `json:"php_fpm_max_children"`
	PHPMemoryMB           int                `json:"php_memory_mb"`
	SiteDiskQuotaMB       int                `json:"site_disk_quota_mb"`
	MaxBackups            int                `json:"max_backups"`
	BackupStorageMB       int                `json:"backup_storage_mb"`
	SourceRevision        int                `json:"source_revision"`
	OverusePolicy         PlanOverusePolicy  `json:"overuse_policy"`
	DiskWarningPercent    int                `json:"disk_warning_percent"`
	TrafficWarningPercent int                `json:"traffic_warning_percent"`
	MaxSubdomains         int                `json:"max_subdomains"`
	MaxDomainAliases      int                `json:"max_domain_aliases"`
	MaxFTPAccounts        int                `json:"max_ftp_accounts"`
	ValidityDays          int                `json:"validity_days"`
	HostingEnabled        bool               `json:"hosting_enabled"`
	DefaultPHPVersion     string             `json:"default_php_version"`
	AllowTLS              bool               `json:"allow_tls"`
	AllowBackups          bool               `json:"allow_backups"`
	AllowPHPSettings      bool               `json:"allow_php_settings"`
	ServicePresets        PlanServicePresets `json:"service_presets"`
}

type PlanOverusePolicy string

const (
	PlanOveruseBlock            PlanOverusePolicy = "block"
	PlanOveruseNormal           PlanOverusePolicy = "normal"
	PlanOveruseNotify           PlanOverusePolicy = "notify"
	PlanOveruseNotSuspend       PlanOverusePolicy = "not_suspend"
	PlanOveruseNotSuspendNotify PlanOverusePolicy = "not_suspend_notify"
)

type PlanDefinition struct {
	ID          int64              `json:"id,omitempty"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	PriceCents  *int64             `json:"price_cents,omitempty"`
	Resources   PlanResources      `json:"resources"`
	Permissions PlanPermissions    `json:"permissions"`
	Presets     PlanServicePresets `json:"presets"`
	IsActive    bool               `json:"is_active"`
	Revision    int                `json:"revision"`
}

type PlanPreview struct {
	SyncedSubscriptions int    `json:"synced_subscriptions"`
	LockedSubscriptions int    `json:"locked_subscriptions"`
	CustomSubscriptions int    `json:"custom_subscriptions"`
	CommittedDiskMB     int    `json:"committed_disk_mb"`
	ServerCapacityMB    int    `json:"server_capacity_mb"`
	ResellerCommittedMB int    `json:"reseller_committed_disk_mb"`
	ResellerCapacityMB  int    `json:"reseller_capacity_mb"`
	HasResellerCapacity bool   `json:"has_reseller_capacity"`
	Allowed             bool   `json:"allowed"`
	Warning             string `json:"warning,omitempty"`
}

type PlanResources struct {
	DiskMB                int               `json:"disk_mb"`
	TrafficMB             int               `json:"traffic_mb"`
	MaxSites              int               `json:"max_sites"`
	MaxDatabases          int               `json:"max_databases"`
	MaxMailboxes          int               `json:"max_mailboxes"`
	MaxBackups            int               `json:"max_backups"`
	BackupStorageMB       int               `json:"backup_storage_mb"`
	MaxSubdomains         int               `json:"max_subdomains"`
	MaxDomainAliases      int               `json:"max_domain_aliases"`
	MaxFTPAccounts        int               `json:"max_ftp_accounts"`
	ValidityDays          int               `json:"validity_days"`
	OverusePolicy         PlanOverusePolicy `json:"overuse_policy"`
	DiskWarningPercent    int               `json:"disk_warning_percent"`
	TrafficWarningPercent int               `json:"traffic_warning_percent"`
}

type PlanPermissions struct {
	HostingEnabled   bool `json:"hosting_enabled"`
	AllowSSH         bool `json:"allow_ssh"`
	AllowDNS         bool `json:"allow_dns"`
	AllowTLS         bool `json:"allow_tls"`
	AllowBackups     bool `json:"allow_backups"`
	AllowPHPSettings bool `json:"allow_php_settings"`
}

type PlanServicePresets struct {
	SchemaVersion int                `json:"schema_version"`
	Hosting       HostingPreset      `json:"hosting"`
	PHP           PHPPreset          `json:"php"`
	Mail          MailPreset         `json:"mail"`
	DNS           DNSPreset          `json:"dns"`
	Performance   PerformancePreset  `json:"performance"`
	Logs          LogsPreset         `json:"logs"`
	Applications  ApplicationsPreset `json:"applications"`
}

type HostingPreset struct {
	WebServer          string   `json:"web_server"`
	PreferredDomain    string   `json:"preferred_domain"`
	DefaultPHPVersion  string   `json:"default_php_version"`
	AllowedPHPVersions []string `json:"allowed_php_versions"`
}

type PHPPreset struct {
	MaxExecutionSeconds int  `json:"max_execution_seconds"`
	MaxInputSeconds     int  `json:"max_input_seconds"`
	PostMaxMB           int  `json:"post_max_mb"`
	UploadMaxMB         int  `json:"upload_max_mb"`
	FPMMaxRequests      int  `json:"fpm_max_requests"`
	DisplayErrors       bool `json:"display_errors"`
	LogErrors           bool `json:"log_errors"`
	AllowURLFOpen       bool `json:"allow_url_fopen"`
}

type MailPreset struct {
	WebmailEnabled bool   `json:"webmail_enabled"`
	SpamFilter     bool   `json:"spam_filter"`
	DKIM           bool   `json:"dkim"`
	DMARCPolicy    string `json:"dmarc_policy"`
}

type DNSPreset struct {
	Mode       string `json:"mode"`
	DefaultTTL int    `json:"default_ttl"`
}

type PerformancePreset struct {
	MaxConnections  int  `json:"max_connections"`
	StaticFileCache bool `json:"static_file_cache"`
}

type LogsPreset struct {
	RotationEnabled   bool `json:"rotation_enabled"`
	RetentionDays     int  `json:"retention_days"`
	StatisticsEnabled bool `json:"statistics_enabled"`
}

type ApplicationsPreset struct {
	CatalogEnabled bool     `json:"catalog_enabled"`
	Allowed        []string `json:"allowed"`
}

type SubscriptionUsage struct {
	SubscriptionID int64     `json:"subscription_id"`
	PeriodStart    time.Time `json:"period_start"`
	SiteBytes      int64     `json:"site_bytes"`
	DatabaseBytes  int64     `json:"database_bytes"`
	BackupBytes    int64     `json:"backup_bytes"`
	DiskBytes      int64     `json:"disk_bytes"`
	TrafficBytes   int64     `json:"traffic_bytes"`
	Complete       bool      `json:"complete"`
	CollectedAt    time.Time `json:"collected_at"`
	LastError      string    `json:"last_error,omitempty"`
}

type UsageAlert struct {
	ID             int64     `json:"id"`
	SubscriptionID int64     `json:"subscription_id"`
	Kind           string    `json:"kind"`
	Severity       string    `json:"severity"`
	Title          string    `json:"title"`
	Body           string    `json:"body"`
	ReadAt         time.Time `json:"read_at,omitempty"`
	ResolvedAt     time.Time `json:"resolved_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type UsageCursor struct {
	DeviceID int64 `json:"device_id"`
	Inode    int64 `json:"inode"`
	Offset   int64 `json:"offset"`
}

type SiteUsageInput struct {
	SiteID    int64       `json:"site_id"`
	Username  string      `json:"username"`
	AccessLog string      `json:"access_log"`
	Cursor    UsageCursor `json:"cursor"`
}

type CollectUsageReq struct {
	Sites       []SiteUsageInput `json:"sites"`
	Databases   []string         `json:"databases"`
	PeriodStart time.Time        `json:"period_start"`
}

type SiteUsageResult struct {
	SiteID       int64       `json:"site_id"`
	HomeBytes    int64       `json:"home_bytes"`
	TrafficBytes int64       `json:"traffic_bytes"`
	Cursor       UsageCursor `json:"cursor"`
}

type CollectUsageResult struct {
	Sites         []SiteUsageResult `json:"sites"`
	DatabaseBytes int64             `json:"database_bytes"`
}

type RuntimeCapabilities struct {
	PHPVersions []string `json:"php_versions"`
	DiskQuota   bool     `json:"disk_quota"`
}

type AddonPlan struct {
	ID           int64                    `json:"id"`
	ResellerID   int64                    `json:"reseller_id,omitempty"`
	Name         string                   `json:"name"`
	Description  string                   `json:"description"`
	Entitlements SubscriptionEntitlements `json:"entitlements"`
	IsActive     bool                     `json:"is_active"`
	Revision     int                      `json:"revision"`
}

type SetHostingStateReq struct {
	Username   string `json:"username"`
	Domain     string `json:"domain"`
	PHPVersion string `json:"php_version"`
	State      string `json:"state"`
}

type ApplySiteRuntimeReq struct {
	Username          string             `json:"username"`
	Domain            string             `json:"domain"`
	CurrentPHPVersion string             `json:"current_php_version"`
	DesiredPHPVersion string             `json:"desired_php_version"`
	State             string             `json:"state"`
	HTTPSRedirect     bool               `json:"https_redirect"`
	TLSCertPath       string             `json:"tls_cert_path,omitempty"`
	TLSKeyPath        string             `json:"tls_key_path,omitempty"`
	Limits            SiteResourceLimits `json:"limits"`
}

type UpdateSiteSettingsReq struct {
	SiteID               int64  `json:"site_id"`
	Section              string `json:"-"`
	DesiredStatus        string `json:"desired_status"`
	DesiredPHPVersion    string `json:"desired_php_version"`
	DesiredHTTPSRedirect bool   `json:"desired_https_redirect"`
}

type DNSRecord struct {
	ID       int64  `json:"id,omitempty"`
	ZoneID   int64  `json:"zone_id,omitempty"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl"`
}

type OnboardSubscriptionReq struct {
	CustomerMode     string            `json:"customer_mode"`
	CustomerID       int64             `json:"customer_id,omitempty"`
	Customer         CreateCustomerReq `json:"customer"`
	PlanID           int64             `json:"plan_id"`
	SubscriptionName string            `json:"subscription_name"`
	CreateSite       bool              `json:"create_site"`
	Site             CreateSiteReq     `json:"site"`
}

type SearchResult struct {
	Kind   string `json:"kind"`
	ID     int64  `json:"id"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
	URL    string `json:"url"`
}

type AuditEvent struct {
	ID             int64           `json:"id"`
	ActorUserID    int64           `json:"actor_user_id"`
	ActorEmail     string          `json:"actor_email"`
	CustomerID     int64           `json:"customer_id,omitempty"`
	SubscriptionID int64           `json:"subscription_id,omitempty"`
	Action         string          `json:"action"`
	TargetType     string          `json:"target_type"`
	TargetID       int64           `json:"target_id,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type SubscriptionSummary struct {
	ID                    int64              `json:"id"`
	CustomerID            int64              `json:"customer_id"`
	CustomerUserID        int64              `json:"customer_user_id,omitempty"`
	CustomerEmail         string             `json:"customer_email"`
	CustomerName          string             `json:"customer_name"`
	CustomerCompany       string             `json:"customer_company"`
	PlanID                int64              `json:"plan_id"`
	PlanName              string             `json:"plan_name"`
	SubscriptionName      string             `json:"subscription_name"`
	Status                string             `json:"status"`
	MaxSites              int                `json:"max_sites"`
	MaxDatabases          int                `json:"max_databases"`
	DiskMB                int                `json:"disk_mb"`
	MaxBackups            int                `json:"max_backups"`
	BackupStorageMB       int                `json:"backup_storage_mb"`
	SitesUsed             int                `json:"sites_used"`
	DatabasesUsed         int                `json:"databases_used"`
	BackupsUsed           int                `json:"backups_used"`
	BackupBytesUsed       int64              `json:"backup_bytes_used"`
	Warning               string             `json:"warning,omitempty"`
	CreatedAt             time.Time          `json:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at"`
	ResellerID            int64              `json:"reseller_id,omitempty"`
	SyncMode              string             `json:"sync_mode"`
	SyncStatus            string             `json:"sync_status"`
	PlanRevision          int                `json:"plan_revision"`
	SyncError             string             `json:"sync_error,omitempty"`
	AllowDNS              bool               `json:"allow_dns"`
	AllowSSH              bool               `json:"allow_ssh"`
	PHPAllowlist          string             `json:"php_allowlist"`
	PHPFPMMaxChildren     int                `json:"php_fpm_max_children"`
	PHPMemoryMB           int                `json:"php_memory_mb"`
	SiteDiskQuotaMB       int                `json:"site_disk_quota_mb"`
	BandwidthMB           int                `json:"bandwidth_mb"`
	MaxMailboxes          int                `json:"max_mailboxes"`
	BackupRetentionDays   int                `json:"backup_retention_days"`
	MaxSubdomains         int                `json:"max_subdomains"`
	MaxDomainAliases      int                `json:"max_domain_aliases"`
	MaxFTPAccounts        int                `json:"max_ftp_accounts"`
	ValidityDays          int                `json:"validity_days"`
	HostingEnabled        bool               `json:"hosting_enabled"`
	DefaultPHPVersion     string             `json:"default_php_version"`
	AllowTLS              bool               `json:"allow_tls"`
	AllowBackups          bool               `json:"allow_backups"`
	AllowPHPSettings      bool               `json:"allow_php_settings"`
	OverusePolicy         PlanOverusePolicy  `json:"overuse_policy"`
	DiskWarningPercent    int                `json:"disk_warning_percent"`
	TrafficWarningPercent int                `json:"traffic_warning_percent"`
	ServicePresets        PlanServicePresets `json:"service_presets"`
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
	Domain  string      `json:"domain"`
	Address string      `json:"address"`
	Serial  int64       `json:"serial"`
	ZoneDir string      `json:"zone_dir"`
	Records []DNSRecord `json:"records,omitempty"`
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
