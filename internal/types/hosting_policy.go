package types

import (
	"encoding/json"
	"time"
)

// HostingPolicy is the versioned, typed desired-state contract shared by
// plans, subscriptions, sites, the control plane, and the privileged agent.
// Limits use Nakpanel semantics: -1 is unlimited, 0 is disabled, and positive
// values are finite.
type HostingPolicy struct {
	SchemaVersion int                      `json:"schema_version"`
	Resources     HostingResourcePolicy    `json:"resources"`
	Permissions   HostingPermissionPolicy  `json:"permissions"`
	Web           HostingWebPolicy         `json:"web"`
	PHP           HostingPHPPolicy         `json:"php"`
	Mail          HostingMailPolicy        `json:"mail"`
	DNS           HostingDNSPolicy         `json:"dns"`
	Access        HostingAccessPolicy      `json:"access"`
	Backups       HostingBackupPolicy      `json:"backups"`
	Applications  HostingApplicationPolicy `json:"applications"`
	Valkey        HostingValkeyPolicy      `json:"valkey"`
}

type HostingResourcePolicy struct {
	DiskMB             int `json:"disk_mb"`
	TrafficMB          int `json:"traffic_mb"`
	CPUPercent         int `json:"cpu_percent"`
	MemoryMB           int `json:"memory_mb"`
	IOReadMBPS         int `json:"io_read_mbps"`
	IOWriteMBPS        int `json:"io_write_mbps"`
	MaxTasks           int `json:"max_tasks"`
	MaxSites           int `json:"max_sites"`
	MaxDatabases       int `json:"max_databases"`
	MaxDatabaseUsers   int `json:"max_database_users"`
	MaxMailboxes       int `json:"max_mailboxes"`
	MaxMailAliases     int `json:"max_mail_aliases"`
	MaxSFTPIdentities  int `json:"max_sftp_identities"`
	MaxScheduledTasks  int `json:"max_scheduled_tasks"`
	MaxBackups         int `json:"max_backups"`
	BackupStorageMB    int `json:"backup_storage_mb"`
	MaxApplications    int `json:"max_applications"`
	ContainerStorageMB int `json:"container_storage_mb"`
	MaxFTPAccounts     int `json:"max_ftp_accounts"`
	ValkeyMemoryMB     int `json:"valkey_memory_mb"`
}

type HostingPermissionPolicy struct {
	Hosting           bool `json:"hosting"`
	SSH               bool `json:"ssh"`
	SFTP              bool `json:"sftp"`
	ScheduledTasks    bool `json:"scheduled_tasks"`
	DNS               bool `json:"dns"`
	TLS               bool `json:"tls"`
	Mail              bool `json:"mail"`
	Databases         bool `json:"databases"`
	Backups           bool `json:"backups"`
	PHPSettings       bool `json:"php_settings"`
	CGI               bool `json:"cgi"`
	Applications      bool `json:"applications"`
	CustomOCIImages   bool `json:"custom_oci_images"`
	ApplicationEgress bool `json:"application_egress"`
	FTPS              bool `json:"ftps"`
	Logs              bool `json:"logs"`
	Git               bool `json:"git"`
	Staging           bool `json:"staging"`
	Valkey            bool `json:"valkey"`
}

type HostingWebPolicy struct {
	PreferredDomain      string   `json:"preferred_domain"`
	HTTPSRedirect        bool     `json:"https_redirect"`
	RequestRatePerSecond int      `json:"request_rate_per_second"`
	RequestBurst         int      `json:"request_burst"`
	MaxConnections       int      `json:"max_connections"`
	StaticCache          bool     `json:"static_cache"`
	FastCGIMicrocache    bool     `json:"fastcgi_microcache"`
	IndexFiles           string   `json:"index_files"`
	RequestBodyLimitMB   int      `json:"request_body_limit_mb"`
	Compression          bool     `json:"compression"`
	CacheTTLSeconds      int      `json:"cache_ttl_seconds"`
	RateLimitPerSecond   int      `json:"rate_limit_per_second"`
	RateLimitBurst       int      `json:"rate_limit_burst"`
	ConnectTimeoutSecs   int      `json:"connect_timeout_seconds"`
	ReadTimeoutSecs      int      `json:"read_timeout_seconds"`
	SecurityHeaderPreset string   `json:"security_header_preset"`
	AllowedCIDRs         []string `json:"allowed_cidrs"`
	ErrorDocument404     string   `json:"error_document_404"`
	ErrorDocument50X     string   `json:"error_document_50x"`
}

type HostingPHPPolicy struct {
	DefaultVersion       string   `json:"default_version"`
	AllowedVersions      []string `json:"allowed_versions"`
	FPMMaxChildren       int      `json:"fpm_max_children"`
	FPMMaxRequests       int      `json:"fpm_max_requests"`
	MemoryLimitMB        int      `json:"memory_limit_mb"`
	MaxExecutionSeconds  int      `json:"max_execution_seconds"`
	MaxInputSeconds      int      `json:"max_input_seconds"`
	PostMaxMB            int      `json:"post_max_mb"`
	UploadMaxMB          int      `json:"upload_max_mb"`
	DisplayErrors        bool     `json:"display_errors"`
	LogErrors            bool     `json:"log_errors"`
	AllowURLFOpen        bool     `json:"allow_url_fopen"`
	ExecEnabled          bool     `json:"exec_enabled"`
	FPMMode              string   `json:"fpm_mode"`
	FPMIdleTimeoutSecs   int      `json:"fpm_idle_timeout_seconds"`
	RequestTerminateSecs int      `json:"request_terminate_timeout_seconds"`
	OPcacheEnabled       bool     `json:"opcache_enabled"`
	OPcacheMemoryMB      int      `json:"opcache_memory_mb"`
}

type HostingMailPolicy struct {
	Enabled        bool   `json:"enabled"`
	MailboxQuotaMB int    `json:"mailbox_quota_mb"`
	DKIM           bool   `json:"dkim"`
	DMARCPolicy    string `json:"dmarc_policy"`
	SpamFilter     bool   `json:"spam_filter"`
	Webmail        bool   `json:"webmail"`
	Autoresponders bool   `json:"autoresponders"`
	CatchAll       bool   `json:"catch_all"`
}

type HostingDNSPolicy struct {
	Enabled    bool   `json:"enabled"`
	Mode       string `json:"mode"`
	DefaultTTL int    `json:"default_ttl"`
	DNSSEC     bool   `json:"dnssec"`
}

type HostingAccessPolicy struct {
	ShellMode          string `json:"shell_mode"`
	NspawnImage        string `json:"nspawn_image"`
	SFTPOnly           bool   `json:"sftp_only"`
	SSHIdleTimeoutMins int    `json:"ssh_idle_timeout_minutes"`
	FTPSEnabled        bool   `json:"ftps_enabled"`
	FTPSPassiveStart   int    `json:"ftps_passive_start"`
	FTPSPassiveEnd     int    `json:"ftps_passive_end"`
}

type HostingBackupPolicy struct {
	Enabled       bool   `json:"enabled"`
	RetentionDays int    `json:"retention_days"`
	Schedule      string `json:"schedule"`
	RemoteTarget  string `json:"remote_target"`
}

type HostingApplicationPolicy struct {
	CatalogEnabled      bool     `json:"catalog_enabled"`
	AllowedCatalogSlugs []string `json:"allowed_catalog_slugs"`
	AllowedRegistries   []string `json:"allowed_registries"`
	AllowedRuntimes     []string `json:"allowed_runtimes"`
	Rootless            bool     `json:"rootless"`
	EgressEnabled       bool     `json:"egress_enabled"`
}

type HostingValkeyPolicy struct {
	Enabled            bool   `json:"enabled"`
	MemoryMB           int    `json:"memory_mb"`
	MaxClients         int    `json:"max_clients"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
	EvictionPolicy     string `json:"eviction_policy"`
	CPUPercent         int    `json:"cpu_percent"`
	ProcessLimit       int    `json:"process_limit"`
}

type SubscriptionSystemAccount struct {
	ID                int64         `json:"id"`
	SubscriptionID    int64         `json:"subscription_id"`
	Username          string        `json:"username"`
	HomePath          string        `json:"home_path"`
	LinuxUID          int           `json:"linux_uid,omitempty"`
	ShellMode         string        `json:"shell_mode"`
	DesiredState      string        `json:"desired_state"`
	AppliedState      string        `json:"applied_state"`
	ConvergenceStatus string        `json:"convergence_status"`
	LastError         string        `json:"last_error,omitempty"`
	MigrationStatus   string        `json:"migration_status"`
	MigrationError    string        `json:"migration_error,omitempty"`
	EffectivePolicy   HostingPolicy `json:"effective_policy"`
}

type EnsureSubscriptionAccountReq struct {
	SubscriptionID int64                `json:"subscription_id"`
	Username       string               `json:"username"`
	HomePath       string               `json:"home_path"`
	State          string               `json:"state"`
	Policy         HostingPolicy        `json:"policy"`
	Domains        []SubscriptionDomain `json:"domains"`
	SFTPIdentities []SFTPAccessIdentity `json:"sftp_identities"`
	Tasks          []ScheduledTask      `json:"scheduled_tasks"`
}

type SubscriptionDomain struct {
	SiteID       int64         `json:"site_id"`
	Domain       string        `json:"domain"`
	DocumentRoot string        `json:"document_root"`
	State        string        `json:"state"`
	Policy       HostingPolicy `json:"policy"`
}

type SFTPAccessIdentity struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	RelativeRoot string `json:"relative_root"`
	Enabled      bool   `json:"enabled"`
}

type ScheduledTask struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	Schedule         string `json:"schedule"`
	Command          string `json:"command"`
	WorkingDirectory string `json:"working_directory"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	Enabled          bool   `json:"enabled"`
	SiteID           int64  `json:"site_id,omitempty"`
	Domain           string `json:"domain,omitempty"`
	Kind             string `json:"kind"`
	URL              string `json:"url,omitempty"`
	Script           string `json:"script,omitempty"`
	Timezone         string `json:"timezone"`
}

type EnsureSubscriptionAccountResult struct {
	Username string `json:"username"`
	HomePath string `json:"home_path"`
	LinuxUID int    `json:"linux_uid"`
	Changed  bool   `json:"changed"`
}

type EnsureApplicationReq struct {
	ApplicationID   int64                   `json:"application_id"`
	SubscriptionID  int64                   `json:"subscription_id"`
	SiteID          int64                   `json:"site_id"`
	DesiredRevision int64                   `json:"desired_revision"`
	Username        string                  `json:"username"`
	Domain          string                  `json:"domain"`
	Name            string                  `json:"name"`
	Runtime         string                  `json:"runtime"`
	ImageRef        string                  `json:"image_ref"`
	DesiredState    string                  `json:"desired_state"`
	Remove          bool                    `json:"remove,omitempty"`
	Environment     map[string]string       `json:"environment"`
	Secrets         map[string]string       `json:"secrets,omitempty"`
	Endpoint        ApplicationEndpointSpec `json:"endpoint"`
	Health          ApplicationHealthSpec   `json:"health"`
	Volumes         []ApplicationVolumeSpec `json:"volumes,omitempty"`
	Policy          HostingPolicy           `json:"policy"`
}

// ConfigureMailReq carries the full desired mail state for the node. The
// agent renders Stalwart's configuration deterministically from it, ensures
// per-domain DKIM keys exist, and reloads the service. Mailboxes and aliases
// never appear here: Stalwart reads them live from the panel database.
type ConfigureMailReq struct {
	Hostname          string               `json:"hostname"`
	Domains           []MailDomainConfig   `json:"domains,omitempty"`
	Smarthost         *MailSmarthostConfig `json:"smarthost,omitempty"`
	OutboundRateLimit string               `json:"outbound_rate_limit,omitempty"`
}

type MailDomainConfig struct {
	MailDomainID int64  `json:"mail_domain_id"`
	Domain       string `json:"domain"`
	DKIM         bool   `json:"dkim"`
}

// MailSmarthostConfig routes all external outbound mail through a relay
// instead of delivering from the shared host IP.
type MailSmarthostConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type ConfigureMailResult struct {
	ConfigPath string           `json:"config_path"`
	Changed    bool             `json:"changed"`
	DKIM       []MailDomainDKIM `json:"dkim,omitempty"`
}

// MailDomainDKIM carries only the public half of a DKIM keypair; the private
// key never leaves the host.
type MailDomainDKIM struct {
	MailDomainID int64  `json:"mail_domain_id"`
	Domain       string `json:"domain"`
	Selector     string `json:"selector"`
	Record       string `json:"record"`
}

// CollectMailQueueResult summarizes Stalwart's outbound queue backlog per
// sender domain so the control plane can alert on spikes.
type CollectMailQueueResult struct {
	TotalQueued   int            `json:"total_queued"`
	SenderDomains map[string]int `json:"sender_domains,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
}

type ApplyScheduledTasksReq struct {
	SubscriptionID int64           `json:"subscription_id"`
	Username       string          `json:"username"`
	HomePath       string          `json:"home_path"`
	Tasks          []ScheduledTask `json:"tasks"`
}

type PolicyPatchReq struct {
	Patch json.RawMessage `json:"patch"`
}

type SFTPIdentityInput struct {
	ID           int64  `json:"id,omitempty"`
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	RelativeRoot string `json:"relative_root"`
	Enabled      bool   `json:"enabled"`
}

type ScheduledTaskInput struct {
	ID               int64  `json:"id,omitempty"`
	SiteID           int64  `json:"site_id,omitempty"`
	Name             string `json:"name"`
	Schedule         string `json:"schedule"`
	Command          string `json:"command"`
	WorkingDirectory string `json:"working_directory"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	Enabled          bool   `json:"enabled"`
	Kind             string `json:"kind"`
	URL              string `json:"url,omitempty"`
	Script           string `json:"script,omitempty"`
	Timezone         string `json:"timezone"`
}

type MailDomainInput struct {
	ID          int64  `json:"id,omitempty"`
	SiteID      int64  `json:"site_id,omitempty"`
	Domain      string `json:"domain"`
	Enabled     bool   `json:"enabled"`
	DKIM        bool   `json:"dkim"`
	DMARCPolicy string `json:"dmarc_policy"`
	CatchAll    string `json:"catch_all"`
}

// MailboxInput carries a mailbox mutation. Password is plaintext only in
// memory: the store hashes it with argon2id before it touches the database,
// and an empty password on update keeps the existing hash.
type MailboxInput struct {
	ID           int64  `json:"id,omitempty"`
	MailDomainID int64  `json:"mail_domain_id"`
	LocalPart    string `json:"local_part"`
	Password     string `json:"-"`
	QuotaMB      int    `json:"quota_mb"`
	Enabled      bool   `json:"enabled"`
}

// MailAliasInput carries an alias/forwarder mutation. Every destination must
// resolve to a mailbox owned by the same subscription; external forwarding is
// a documented follow-up.
type MailAliasInput struct {
	ID           int64    `json:"id,omitempty"`
	MailDomainID int64    `json:"mail_domain_id"`
	LocalPart    string   `json:"local_part"`
	Destinations []string `json:"destinations"`
}

type ApplicationInput struct {
	ID                   int64                   `json:"id,omitempty"`
	SiteID               int64                   `json:"site_id,omitempty"`
	Name                 string                  `json:"name"`
	Runtime              string                  `json:"runtime"`
	CatalogSlug          string                  `json:"catalog_slug"`
	ImageRef             string                  `json:"image_ref"`
	DesiredState         string                  `json:"desired_state"`
	RouteMode            string                  `json:"route_mode"`
	RoutePrefix          string                  `json:"route_prefix"`
	ContainerPort        int                     `json:"container_port"`
	HealthKind           string                  `json:"health_kind"`
	HealthPath           string                  `json:"health_path"`
	HealthTimeoutSeconds int                     `json:"health_timeout_seconds"`
	Environment          map[string]string       `json:"environment"`
	Secrets              map[string]string       `json:"-"`
	Volumes              []ApplicationVolumeSpec `json:"volumes,omitempty"`
}

type ApplicationPreset struct {
	ID         int64     `json:"id"`
	ResellerID int64     `json:"reseller_id,omitempty"`
	Slug       string    `json:"slug"`
	Name       string    `json:"name"`
	Runtime    string    `json:"runtime"`
	ImageRef   string    `json:"image_ref"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
}

type ApplicationPresetInput struct {
	ID       int64                       `json:"id,omitempty"`
	Slug     string                      `json:"slug"`
	Name     string                      `json:"name"`
	Runtime  string                      `json:"runtime"`
	ImageRef string                      `json:"image_ref"`
	Active   bool                        `json:"active"`
	Manifest ApplicationManifestRevision `json:"manifest"`
}

type LegacySiteMigration struct {
	SiteID         int64  `json:"site_id"`
	Domain         string `json:"domain"`
	LegacyUsername string `json:"legacy_username"`
	LegacyHome     string `json:"legacy_home"`
	LegacyDocroot  string `json:"legacy_docroot"`
	TargetDocroot  string `json:"target_docroot"`
	PHPVersion     string `json:"php_version"`
}

type MigrateSubscriptionAccountReq struct {
	SubscriptionID int64                 `json:"subscription_id"`
	Username       string                `json:"username"`
	HomePath       string                `json:"home_path"`
	Policy         HostingPolicy         `json:"policy"`
	Sites          []LegacySiteMigration `json:"sites"`
	SnapshotRoot   string                `json:"snapshot_root,omitempty"`
}

type MigrateSubscriptionAccountResult struct {
	SubscriptionID int64    `json:"subscription_id"`
	Username       string   `json:"username"`
	HomePath       string   `json:"home_path"`
	SnapshotPath   string   `json:"snapshot_path"`
	LegacyHomes    []string `json:"legacy_homes"`
}

type CleanupLegacyHomesReq struct {
	SubscriptionID int64    `json:"subscription_id"`
	ActiveHome     string   `json:"active_home"`
	LegacyHomes    []string `json:"legacy_homes"`
}

type CleanupLegacyHomesResult struct {
	Deleted []string `json:"deleted"`
}
