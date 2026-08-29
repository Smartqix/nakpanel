package types

import "time"

type FTPAccount struct {
	ID                int64     `json:"id"`
	SubscriptionID    int64     `json:"subscription_id"`
	SiteID            int64     `json:"site_id,omitempty"`
	Name              string    `json:"name"`
	HomeLabel         string    `json:"home_label"`
	Enabled           bool      `json:"enabled"`
	ConvergenceStatus string    `json:"convergence_status"`
	LastError         string    `json:"last_error,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

type FTPAccountInput struct {
	ID       int64  `json:"id,omitempty"`
	SiteID   int64  `json:"site_id,omitempty"`
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type FTPSStatus struct {
	Running       bool   `json:"running"`
	TLSRequired   bool   `json:"tls_required"`
	PassiveStart  int    `json:"passive_start"`
	PassiveEnd    int    `json:"passive_end"`
	PublicAddress string `json:"public_address,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

type EnsureFTPSAccount struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	SiteID       int64  `json:"site_id,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Name         string `json:"name"`
	PasswordHash string `json:"password_hash"`
	Enabled      bool   `json:"enabled"`
}

type EnsureFTPSReq struct {
	Revision      int64               `json:"revision"`
	State         string              `json:"state"`
	Accounts      []EnsureFTPSAccount `json:"accounts"`
	PublicAddress string              `json:"public_address,omitempty"`
	TLSCertPath   string              `json:"tls_cert_path"`
	TLSKeyPath    string              `json:"tls_key_path"`
}

type EnsureFTPSResult struct {
	Changed bool `json:"changed"`
}

type SiteRuntimeSpec struct {
	SiteID      int64               `json:"site_id"`
	Username    string              `json:"username"`
	Domain      string              `json:"domain"`
	PHPVersion  string              `json:"php_version"`
	State       string              `json:"state"`
	Policy      HostingPolicy       `json:"policy"`
	Limits      SiteResourceLimits  `json:"limits"`
	HostingMode HostingMode         `json:"hosting_mode,omitempty"`
	Application *PHPApplicationSpec `json:"php_application,omitempty"`
}

type SiteLogSource string

const (
	SiteLogNginxAccess SiteLogSource = "nginx_access"
	SiteLogNginxError  SiteLogSource = "nginx_error"
	SiteLogPHPFPM      SiteLogSource = "php_fpm"
	SiteLogApplication SiteLogSource = "application"
	SiteLogTask        SiteLogSource = "task"
)

type SiteLogRequest struct {
	SiteID    int64         `json:"site_id"`
	Username  string        `json:"username"`
	Domain    string        `json:"domain"`
	Source    SiteLogSource `json:"source"`
	Cursor    int64         `json:"cursor"`
	LineLimit int           `json:"line_limit"`
	ByteLimit int           `json:"byte_limit"`
	Search    string        `json:"search,omitempty"`
	Severity  string        `json:"severity,omitempty"`
}

type SiteLogResult struct {
	Source     SiteLogSource `json:"source"`
	Lines      []string      `json:"lines"`
	NextCursor int64         `json:"next_cursor"`
	Rotated    bool          `json:"rotated"`
	Truncated  bool          `json:"truncated"`
}

type ScheduledTaskRun struct {
	ID           int64     `json:"id"`
	TaskID       int64     `json:"task_id"`
	Status       string    `json:"status"`
	ExitCode     *int      `json:"exit_code,omitempty"`
	Output       string    `json:"output"`
	StartedAt    time.Time `json:"started_at,omitempty"`
	FinishedAt   time.Time `json:"finished_at,omitempty"`
	ScheduledFor time.Time `json:"scheduled_for,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type RunScheduledTaskReq struct {
	TaskID           int64  `json:"task_id"`
	SubscriptionID   int64  `json:"subscription_id"`
	SiteID           int64  `json:"site_id"`
	Username         string `json:"username"`
	Domain           string `json:"domain"`
	PHPVersion       string `json:"php_version,omitempty"`
	Kind             string `json:"kind"`
	Command          string `json:"command"`
	URL              string `json:"url,omitempty"`
	Script           string `json:"script,omitempty"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	WorkingDirectory string `json:"working_directory"`
}

type RunScheduledTaskResult struct {
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

type GitRepository struct {
	ID                int64     `json:"id"`
	SiteID            int64     `json:"site_id"`
	Mode              string    `json:"mode"`
	RemoteURL         string    `json:"remote_url,omitempty"`
	Branch            string    `json:"branch"`
	DeployTarget      string    `json:"deploy_target"`
	Automatic         bool      `json:"automatic"`
	ConvergenceStatus string    `json:"convergence_status"`
	LastRevision      string    `json:"last_revision,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	KnownHostKey      string    `json:"known_host_key,omitempty"`
	DeployPublicKey   string    `json:"deploy_public_key,omitempty"`
	WebhookConfigured bool      `json:"webhook_configured"`
	CreatedAt         time.Time `json:"created_at"`
}

type GitRepositoryInput struct {
	ID           int64  `json:"id,omitempty"`
	Mode         string `json:"mode"`
	RemoteURL    string `json:"remote_url,omitempty"`
	Branch       string `json:"branch"`
	DeployTarget string `json:"deploy_target"`
	Automatic    bool   `json:"automatic"`
	KnownHostKey string `json:"known_host_key,omitempty"`
}

type EnsureGitRepositoryReq struct {
	RepositoryID int64  `json:"repository_id"`
	SiteID       int64  `json:"site_id"`
	Username     string `json:"username"`
	Domain       string `json:"domain"`
	Mode         string `json:"mode"`
	RemoteURL    string `json:"remote_url,omitempty"`
	Branch       string `json:"branch"`
	DeployTarget string `json:"deploy_target"`
	Automatic    bool   `json:"automatic"`
	Deploy       bool   `json:"deploy"`
	KnownHostKey string `json:"known_host_key,omitempty"`
	State        string `json:"state"`
}

type EnsureGitRepositoryResult struct {
	RepositoryPath  string `json:"repository_path"`
	Revision        string `json:"revision,omitempty"`
	DeployPublicKey string `json:"deploy_public_key,omitempty"`
	Changed         bool   `json:"changed"`
}

type GitDeployment struct {
	ID               int64     `json:"id"`
	RepositoryID     int64     `json:"repository_id"`
	Revision         string    `json:"revision"`
	Status           string    `json:"status"`
	Output           string    `json:"output,omitempty"`
	RollbackRevision string    `json:"rollback_revision,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	FinishedAt       time.Time `json:"finished_at,omitempty"`
}

type ProtectedDirectory struct {
	ID        int64     `json:"id"`
	SiteID    int64     `json:"site_id"`
	Path      string    `json:"path"`
	Realm     string    `json:"realm"`
	Username  string    `json:"username"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type ProtectedDirectoryInput struct {
	ID       int64  `json:"id,omitempty"`
	SiteID   int64  `json:"site_id"`
	Path     string `json:"path"`
	Realm    string `json:"realm"`
	Username string `json:"username"`
	Password string `json:"-"`
	Enabled  bool   `json:"enabled"`
}

type EnsureProtectedDirectory struct {
	ID           int64  `json:"id"`
	Path         string `json:"path"`
	Realm        string `json:"realm"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Enabled      bool   `json:"enabled"`
}

type EnsureProtectedDirectoriesReq struct {
	SiteID      int64                      `json:"site_id"`
	Username    string                     `json:"username"`
	Domain      string                     `json:"domain"`
	Directories []EnsureProtectedDirectory `json:"directories"`
}

type EnsureProtectedDirectoriesResult struct {
	ConfigPath string `json:"config_path"`
	Changed    bool   `json:"changed"`
}

type ValkeyInstance struct {
	ID                 int64     `json:"id"`
	SubscriptionID     int64     `json:"subscription_id"`
	DesiredState       string    `json:"desired_state"`
	AppliedState       string    `json:"applied_state"`
	MemoryMB           int       `json:"memory_mb"`
	MaxClients         int       `json:"max_clients"`
	IdleTimeoutSeconds int       `json:"idle_timeout_seconds"`
	CPUPercent         int       `json:"cpu_percent"`
	ProcessLimit       int       `json:"process_limit"`
	SocketPath         string    `json:"socket_path"`
	CredentialSet      bool      `json:"credential_set"`
	ConvergenceStatus  string    `json:"convergence_status"`
	LastError          string    `json:"last_error,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type ValkeyInput struct {
	DesiredState       string `json:"desired_state"`
	MemoryMB           int    `json:"memory_mb"`
	MaxClients         int    `json:"max_clients"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
	CPUPercent         int    `json:"cpu_percent"`
	ProcessLimit       int    `json:"process_limit"`
	RotateCredential   bool   `json:"rotate_credential"`
	Flush              bool   `json:"flush"`
}

type StagingOperationInput struct {
	SourceSiteID    int64  `json:"source_site_id"`
	TargetSiteID    int64  `json:"target_site_id"`
	Direction       string `json:"direction"`
	IncludeDatabase bool   `json:"include_database"`
}

type StagingOperation struct {
	ID              int64     `json:"id"`
	SourceSiteID    int64     `json:"source_site_id"`
	TargetSiteID    int64     `json:"target_site_id"`
	SourceDomain    string    `json:"source_domain"`
	TargetDomain    string    `json:"target_domain"`
	Direction       string    `json:"direction"`
	IncludeDatabase bool      `json:"include_database"`
	Status          string    `json:"status"`
	SnapshotPath    string    `json:"snapshot_path,omitempty"`
	CopiedBytes     int64     `json:"copied_bytes"`
	LastError       string    `json:"last_error,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
}

type RunStagingOperationReq struct {
	OperationID  int64                 `json:"operation_id"`
	SourceSiteID int64                 `json:"source_site_id"`
	TargetSiteID int64                 `json:"target_site_id"`
	Username     string                `json:"username"`
	SourceDomain string                `json:"source_domain"`
	TargetDomain string                `json:"target_domain"`
	Direction    string                `json:"direction"`
	Databases    []StagingDatabaseCopy `json:"databases,omitempty"`
}

type StagingDatabaseCopy struct {
	SourceName string `json:"source_name"`
	TargetName string `json:"target_name"`
}

type RunStagingOperationResult struct {
	SnapshotPath      string   `json:"snapshot_path"`
	DatabaseSnapshots []string `json:"database_snapshots,omitempty"`
	CopiedBytes       int64    `json:"copied_bytes"`
	Changed           bool     `json:"changed"`
}

type ValkeyStatus struct {
	Running     bool   `json:"running"`
	SocketPath  string `json:"socket_path"`
	MemoryBytes int64  `json:"memory_bytes"`
	Clients     int    `json:"clients"`
	UptimeSecs  int64  `json:"uptime_seconds"`
	LastError   string `json:"last_error,omitempty"`
}

type ValkeyStatusReq struct {
	SubscriptionID int64 `json:"subscription_id"`
}

type EnsureValkeyReq struct {
	SubscriptionID int64  `json:"subscription_id"`
	Username       string `json:"username"`
	State          string `json:"state"`
	MemoryMB       int    `json:"memory_mb"`
	MaxClients     int    `json:"max_clients"`
	IdleTimeout    int    `json:"idle_timeout_seconds"`
	CPUPercent     int    `json:"cpu_percent"`
	ProcessLimit   int    `json:"process_limit"`
	ACLHash        string `json:"acl_hash"`
	Flush          bool   `json:"flush,omitempty"`
}

type EnsureValkeyResult struct {
	SocketPath string `json:"socket_path"`
	Changed    bool   `json:"changed"`
	Running    bool   `json:"running"`
	Flushed    bool   `json:"flushed,omitempty"`
}
