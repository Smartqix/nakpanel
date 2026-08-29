package types

import "time"

const (
	OpInspectServer          = "inspect_server"
	OpInspectManagedServices = "inspect_managed_services"
	OpControlManagedService  = "control_managed_service"
	OpInspectTime            = "inspect_time"
	OpConfigureTime          = "configure_time"
	OpInspectPHP             = "inspect_php"
	OpApplyPHPProfile        = "apply_php_profile"
	OpReadJournal            = "read_journal"
	OpInspectUpdates         = "inspect_updates"
	OpApplyUpdates           = "apply_updates"
	OpInspectServerSecurity  = "inspect_server_security"
	OpStageServerSecurity    = "stage_server_security"
	OpConfirmServerSecurity  = "confirm_server_security"
	OpRevertServerSecurity   = "revert_server_security"
	OpApplyFail2BanPolicy    = "apply_fail2ban_policy"
	OpListSecurityBans       = "list_security_bans"
	OpUnbanSecurityAddress   = "unban_security_address"
)

const (
	ServerStateHealthy     = "healthy"
	ServerStateWarning     = "warning"
	ServerStateCritical    = "critical"
	ServerStatePending     = "pending"
	ServerStateUnavailable = "unavailable"
	ServerStateUnknown     = "unknown"
)

type InspectServerReq struct{}

type ServerInventory struct {
	Hostname        string            `json:"hostname"`
	OperatingSystem string            `json:"operating_system"`
	Kernel          string            `json:"kernel"`
	Architecture    string            `json:"architecture"`
	UptimeSeconds   int64             `json:"uptime_seconds"`
	LoadAverage     []float64         `json:"load_average,omitempty"`
	CPUCount        int               `json:"cpu_count"`
	Memory          MemoryInventory   `json:"memory"`
	Filesystems     []FilesystemState `json:"filesystems,omitempty"`
	Listeners       []ListenerState   `json:"listeners,omitempty"`
	Time            TimeState         `json:"time"`
	Services        []ManagedService  `json:"services,omitempty"`
	PHPHandlers     []PHPHandlerState `json:"php_handlers,omitempty"`
	Components      []ComponentState  `json:"components,omitempty"`
	Status          string            `json:"status"`
	CheckedAt       time.Time         `json:"checked_at"`
	LastError       string            `json:"last_error,omitempty"`
}

type MemoryInventory struct {
	TotalBytes     int64 `json:"total_bytes"`
	AvailableBytes int64 `json:"available_bytes"`
	SwapTotalBytes int64 `json:"swap_total_bytes"`
	SwapFreeBytes  int64 `json:"swap_free_bytes"`
}

type FilesystemState struct {
	Mountpoint      string `json:"mountpoint"`
	Filesystem      string `json:"filesystem"`
	TotalBytes      int64  `json:"total_bytes"`
	AvailableBytes  int64  `json:"available_bytes"`
	TotalInodes     int64  `json:"total_inodes"`
	AvailableInodes int64  `json:"available_inodes"`
}

type ListenerState struct {
	ServiceID string `json:"service_id"`
	Protocol  string `json:"protocol"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
}

type ComponentState struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
	State     string `json:"state"`
}

type InspectManagedServicesReq struct {
	ServiceIDs []string `json:"service_ids,omitempty"`
}

type ManagedService struct {
	ID             string    `json:"id"`
	DisplayName    string    `json:"display_name"`
	LoadState      string    `json:"load_state"`
	ActiveState    string    `json:"active_state"`
	SubState       string    `json:"sub_state"`
	UnitFileState  string    `json:"unit_file_state"`
	Result         string    `json:"result,omitempty"`
	MainPID        int       `json:"main_pid,omitempty"`
	RestartCount   int       `json:"restart_count,omitempty"`
	MemoryBytes    int64     `json:"memory_bytes,omitempty"`
	CPUUsageNSec   int64     `json:"cpu_usage_nsec,omitempty"`
	ActiveSince    time.Time `json:"active_since,omitempty"`
	Available      bool      `json:"available"`
	AllowedActions []string  `json:"allowed_actions,omitempty"`
	CheckedAt      time.Time `json:"checked_at"`
	LastError      string    `json:"last_error,omitempty"`
}

type ControlManagedServiceReq struct {
	ServiceID   string `json:"service_id"`
	Action      string `json:"action"`
	OperationID string `json:"operation_id"`
	ActorUserID int64  `json:"-"`
}

type ControlManagedServiceResult struct {
	OperationID string         `json:"operation_id,omitempty"`
	ServiceID   string         `json:"service_id"`
	Action      string         `json:"action"`
	Before      ManagedService `json:"before"`
	After       ManagedService `json:"after"`
	Changed     bool           `json:"changed"`
	Validation  string         `json:"validation,omitempty"`
	DurationMS  int64          `json:"duration_ms"`
}

type InspectTimeReq struct{}

type TimeState struct {
	LocalTime     time.Time `json:"local_time,omitempty"`
	UniversalTime time.Time `json:"universal_time,omitempty"`
	Timezone      string    `json:"timezone"`
	Synchronized  bool      `json:"synchronized"`
	SyncEnabled   bool      `json:"sync_enabled"`
	Backend       string    `json:"backend,omitempty"`
	Source        string    `json:"source,omitempty"`
	OffsetMillis  float64   `json:"offset_millis,omitempty"`
	LastSyncAt    time.Time `json:"last_sync_at,omitempty"`
	RTCLocal      bool      `json:"rtc_local"`
	Available     bool      `json:"available"`
	CheckedAt     time.Time `json:"checked_at"`
	LastError     string    `json:"last_error,omitempty"`
}

type ConfigureTimeReq struct {
	Timezone    string   `json:"timezone"`
	SyncEnabled bool     `json:"sync_enabled"`
	NTPServers  []string `json:"ntp_servers,omitempty"`
}

type InspectPHPReq struct{}

type PHPHandlerState struct {
	ID            string              `json:"id"`
	Version       string              `json:"version"`
	FullVersion   string              `json:"full_version,omitempty"`
	SAPI          string              `json:"sapi"`
	PackageSource string              `json:"package_source,omitempty"`
	ServiceID     string              `json:"service_id"`
	State         string              `json:"state"`
	Default       bool                `json:"default"`
	ConfigValid   bool                `json:"config_valid"`
	UsageCount    int                 `json:"usage_count,omitempty"`
	Extensions    []PHPExtensionState `json:"extensions,omitempty"`
	CheckedAt     time.Time           `json:"checked_at"`
	LastError     string              `json:"last_error,omitempty"`
}

type PHPExtensionState struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Protected bool   `json:"protected"`
}

type ApplyPHPProfileReq struct {
	HandlerID         string           `json:"handler_id"`
	State             string           `json:"state"`
	Default           bool             `json:"default"`
	EnabledExtensions []string         `json:"enabled_extensions,omitempty"`
	Settings          PHPServerProfile `json:"settings"`
	OperationID       string           `json:"operation_id"`
}

type PHPServerProfile struct {
	MemoryLimitMB         int    `json:"memory_limit_mb"`
	MaxExecutionSeconds   int    `json:"max_execution_seconds"`
	MaxInputSeconds       int    `json:"max_input_seconds"`
	MaxInputVars          int    `json:"max_input_vars"`
	PostMaxMB             int    `json:"post_max_mb"`
	UploadMaxMB           int    `json:"upload_max_mb"`
	MaxFileUploads        int    `json:"max_file_uploads"`
	DefaultTimezone       string `json:"default_timezone,omitempty"`
	DisplayErrors         bool   `json:"display_errors"`
	LogErrors             bool   `json:"log_errors"`
	AllowURLFOpen         bool   `json:"allow_url_fopen"`
	OPCacheEnabled        bool   `json:"opcache_enabled"`
	FPMMaxChildren        int    `json:"fpm_max_children"`
	FPMMaxRequests        int    `json:"fpm_max_requests"`
	FPMIdleTimeoutSeconds int    `json:"fpm_idle_timeout_seconds"`
}

type ReadJournalReq struct {
	SourceIDs   []string  `json:"source_ids,omitempty"`
	Priorities  []int     `json:"priorities,omitempty"`
	Since       time.Time `json:"since,omitempty"`
	Until       time.Time `json:"until,omitempty"`
	AfterCursor string    `json:"after_cursor,omitempty"`
	Limit       int       `json:"limit,omitempty"`
}

type JournalEntry struct {
	Cursor    string    `json:"cursor"`
	Timestamp time.Time `json:"timestamp"`
	Priority  int       `json:"priority"`
	SourceID  string    `json:"source_id"`
	Message   string    `json:"message"`
}

type ReadJournalResult struct {
	Entries    []JournalEntry `json:"entries"`
	NextCursor string         `json:"next_cursor,omitempty"`
	Truncated  bool           `json:"truncated"`
}

type InspectUpdatesReq struct{}

type UpdatePackage struct {
	Name      string `json:"name"`
	Current   string `json:"current"`
	Candidate string `json:"candidate"`
	Origin    string `json:"origin,omitempty"`
	Security  bool   `json:"security"`
	Held      bool   `json:"held"`
}

type UpdateState struct {
	Packages        []UpdatePackage `json:"packages,omitempty"`
	SecurityCount   int             `json:"security_count"`
	NormalCount     int             `json:"normal_count"`
	RebootRequired  bool            `json:"reboot_required"`
	AutomaticPolicy string          `json:"automatic_policy"`
	LastRefreshAt   time.Time       `json:"last_refresh_at,omitempty"`
	LastInstallAt   time.Time       `json:"last_install_at,omitempty"`
	CheckedAt       time.Time       `json:"checked_at"`
	LastError       string          `json:"last_error,omitempty"`
}

type ApplyUpdatesReq struct {
	PackageNames []string        `json:"package_names,omitempty"`
	Packages     []UpdatePackage `json:"packages,omitempty"`
	SecurityOnly bool            `json:"security_only"`
	DryRun       bool            `json:"dry_run"`
	OperationID  string          `json:"operation_id"`
}

type ServerSecurityPolicy struct {
	Revision int64             `json:"revision"`
	Firewall FirewallPolicy    `json:"firewall"`
	Fail2Ban Fail2BanPolicy    `json:"fail2ban"`
	SSH      SSHSecurityPolicy `json:"ssh"`
	TLS      TLSSecurityPolicy `json:"tls"`
}

type FirewallPolicy struct {
	Enabled         bool           `json:"enabled"`
	DefaultInbound  string         `json:"default_inbound"`
	ManagementCIDRs []string       `json:"management_cidrs,omitempty"`
	Rules           []FirewallRule `json:"rules,omitempty"`
}

type FirewallRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Direction string   `json:"direction"`
	Action    string   `json:"action"`
	Protocol  string   `json:"protocol"`
	Ports     []int    `json:"ports,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	Order     int      `json:"order"`
}

type Fail2BanPolicy struct {
	Enabled      bool           `json:"enabled"`
	TrustedCIDRs []string       `json:"trusted_cidrs,omitempty"`
	Jails        []Fail2BanJail `json:"jails,omitempty"`
}

type Fail2BanJail struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	BanTime  int    `json:"ban_time_seconds"`
	FindTime int    `json:"find_time_seconds"`
	MaxRetry int    `json:"max_retry"`
}

type SSHSecurityPolicy struct {
	PermitRootLogin         bool `json:"permit_root_login"`
	PasswordAuthentication  bool `json:"password_authentication"`
	PublicKeyAuthentication bool `json:"public_key_authentication"`
	AllowTCPForwarding      bool `json:"allow_tcp_forwarding"`
	Port                    int  `json:"port"`
}

type TLSSecurityPolicy struct {
	Profile string `json:"profile"`
}

type StageServerSecurityReq struct {
	Scope         string               `json:"scope"`
	Policy        ServerSecurityPolicy `json:"policy"`
	OperationID   string               `json:"operation_id"`
	ClientAddress string               `json:"client_address"`
}

type StagedSecurityResult struct {
	OperationID      string    `json:"operation_id"`
	Scope            string    `json:"scope"`
	Revision         int64     `json:"revision"`
	Validation       []string  `json:"validation,omitempty"`
	RollbackDeadline time.Time `json:"rollback_deadline"`
	State            string    `json:"state"`
}

type SecurityOperationReq struct {
	OperationID string `json:"operation_id"`
}

type SecurityBan struct {
	Address   string    `json:"address"`
	JailID    string    `json:"jail_id"`
	BannedAt  time.Time `json:"banned_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type UnbanSecurityAddressReq struct {
	JailID  string `json:"jail_id"`
	Address string `json:"address"`
}

type UnbanSecurityAddressResult struct {
	JailID   string `json:"jail_id"`
	Address  string `json:"address"`
	Unbanned bool   `json:"unbanned"`
}

type ApplyFail2BanPolicyReq struct {
	Policy      Fail2BanPolicy `json:"policy"`
	SSHPorts    []int          `json:"ssh_ports,omitempty"`
	OperationID string         `json:"operation_id,omitempty"`
}

type ApplyFail2BanPolicyResult struct {
	ConfigPath string `json:"config_path"`
	Reloaded   bool   `json:"reloaded"`
}

type JailBans struct {
	Jail    string   `json:"jail"`
	Enabled bool     `json:"enabled"`
	Banned  []string `json:"banned,omitempty"`
}

type SecurityBansResult struct {
	Running bool       `json:"running"`
	Jails   []JailBans `json:"jails,omitempty"`
}

type ListSecurityBansReq struct{}
