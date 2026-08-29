package types

import "time"

type PHPHostingMode string

const (
	PHPHostingModeClassic PHPHostingMode = "classic"
	PHPHostingModeManaged PHPHostingMode = "managed"

	HostingModeClassic = PHPHostingModeClassic
	HostingModeManaged = PHPHostingModeManaged
)

// HostingMode remains an alias for compatibility with early Phase 30 callers.
type HostingMode = PHPHostingMode

type PHPSupportStatus string

const (
	PHPSupportActive            PHPSupportStatus = "active"
	PHPSupportSecuritySupported PHPSupportStatus = "security_supported"
	PHPSupportUnsupported       PHPSupportStatus = "unsupported"
)

// PHPRuntimeCapability records each independently checked part of a PHP
// runtime. Ready is true only when the CLI, FPM configuration, required
// extensions, and OPcache checks all pass.
type PHPRuntimeCapability struct {
	Version           string           `json:"version"`
	Ready             bool             `json:"ready"`
	SupportStatus     PHPSupportStatus `json:"support_status"`
	CLIPath           string           `json:"cli_path,omitempty"`
	FPMPath           string           `json:"fpm_path,omitempty"`
	CLIAvailable      bool             `json:"cli_available"`
	FPMAvailable      bool             `json:"fpm_available"`
	FPMConfigValid    bool             `json:"fpm_config_valid"`
	OPcacheAvailable  bool             `json:"opcache_available"`
	Extensions        []string         `json:"extensions,omitempty"`
	MissingExtensions []string         `json:"missing_extensions,omitempty"`
	ValidationErrors  []string         `json:"validation_errors,omitempty"`
}

type PHPComposerSpec struct {
	Install      bool `json:"install"`
	AllowScripts bool `json:"allow_scripts"`
	AllowPlugins bool `json:"allow_plugins"`
}

type PHPWorkerSpec struct {
	WorkerID     int64    `json:"worker_id,omitempty"`
	Name         string   `json:"name"`
	Script       string   `json:"script"`
	Arguments    []string `json:"arguments,omitempty"`
	Processes    int      `json:"processes"`
	DesiredState string   `json:"desired_state,omitempty"`
}

type PHPApplicationSpec struct {
	ApplicationID    int64           `json:"application_id"`
	SubscriptionID   int64           `json:"subscription_id"`
	SiteID           int64           `json:"site_id"`
	DesiredRevision  int64           `json:"desired_revision,omitempty"`
	Username         string          `json:"username,omitempty"`
	Domain           string          `json:"domain,omitempty"`
	HostingMode      PHPHostingMode  `json:"hosting_mode"`
	PHPVersion       string          `json:"php_version"`
	RepositoryID     int64           `json:"repository_id,omitempty"`
	RepositoryRef    string          `json:"repository_ref,omitempty"`
	PublicPath       string          `json:"public_path,omitempty"`
	DesiredState     string          `json:"desired_state,omitempty"`
	ReleaseRetention int             `json:"release_retention,omitempty"`
	Composer         PHPComposerSpec `json:"composer"`
	Workers          []PHPWorkerSpec `json:"workers,omitempty"`
	Policy           HostingPolicy   `json:"policy,omitempty"`
}

type PHPDeployment struct {
	ID                   int64     `json:"id"`
	SubscriptionID       int64     `json:"subscription_id,omitempty"`
	ApplicationID        int64     `json:"application_id"`
	RequestedByUserID    int64     `json:"requested_by_user_id,omitempty"`
	RequestedRevision    string    `json:"requested_revision"`
	ResolvedRevision     string    `json:"resolved_revision,omitempty"`
	ReleaseNumber        int64     `json:"release_number,omitempty"`
	PreviousDeploymentID int64     `json:"previous_deployment_id,omitempty"`
	Status               string    `json:"status"`
	HealthMessage        string    `json:"health_message,omitempty"`
	LastError            string    `json:"last_error,omitempty"`
	ComposerAudit        string    `json:"composer_audit,omitempty"`
	StartedAt            time.Time `json:"started_at,omitempty"`
	FinishedAt           time.Time `json:"finished_at,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// PHPEnvironmentVariable is the API-safe environment binding. Secret values
// are represented only by their service-secret reference.
type PHPEnvironmentVariable struct {
	ID            int64     `json:"id,omitempty"`
	ApplicationID int64     `json:"application_id,omitempty"`
	Name          string    `json:"name"`
	Value         string    `json:"value,omitempty"`
	SecretID      int64     `json:"secret_id,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// PHPEnvironmentPayload is used only by protected control-plane-to-agent RPC
// contracts. The control plane populates Secret immediately before transport;
// it must never be used in HTTP views, audit metadata, or River arguments.
type PHPEnvironmentPayload struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Secret string `json:"secret,omitempty"`
}

type PHPWorker struct {
	ID                int64     `json:"id"`
	SubscriptionID    int64     `json:"subscription_id"`
	ApplicationID     int64     `json:"application_id"`
	Name              string    `json:"name"`
	Script            string    `json:"script"`
	Arguments         []string  `json:"arguments,omitempty"`
	Processes         int       `json:"processes"`
	DesiredState      string    `json:"desired_state"`
	ObservedState     string    `json:"observed_state"`
	DesiredRevision   int64     `json:"desired_revision"`
	AppliedRevision   int64     `json:"applied_revision"`
	ConvergenceStatus string    `json:"convergence_status"`
	LastError         string    `json:"last_error,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type DeployPHPApplicationReq struct {
	Application PHPApplicationSpec      `json:"application"`
	Deployment  PHPDeployment           `json:"deployment"`
	Environment []PHPEnvironmentPayload `json:"environment,omitempty"`
}

type DeployPHPApplicationResult struct {
	DeploymentID         int64  `json:"deployment_id"`
	ResolvedRevision     string `json:"resolved_revision"`
	ReleasePath          string `json:"release_path"`
	PreviousDeploymentID int64  `json:"previous_deployment_id,omitempty"`
	HealthMessage        string `json:"health_message,omitempty"`
	ComposerAudit        string `json:"composer_audit,omitempty"`
	Changed              bool   `json:"changed"`
}

type RollbackPHPApplicationReq struct {
	Application      PHPApplicationSpec      `json:"application"`
	DeploymentID     int64                   `json:"deployment_id"`
	TargetDeployment PHPDeployment           `json:"target_deployment"`
	Environment      []PHPEnvironmentPayload `json:"environment,omitempty"`
}

type RollbackPHPApplicationResult struct {
	DeploymentID       int64  `json:"deployment_id"`
	ActiveDeploymentID int64  `json:"active_deployment_id"`
	ResolvedRevision   string `json:"resolved_revision"`
	HealthMessage      string `json:"health_message,omitempty"`
	Changed            bool   `json:"changed"`
}

type ReconcilePHPApplicationReq struct {
	Application        PHPApplicationSpec      `json:"application"`
	ActiveDeployment   *PHPDeployment          `json:"active_deployment,omitempty"`
	PreviousDeployment *PHPDeployment          `json:"previous_deployment,omitempty"`
	Environment        []PHPEnvironmentPayload `json:"environment,omitempty"`
}

type ReconcilePHPApplicationResult struct {
	ApplicationID      int64  `json:"application_id"`
	ActiveDeploymentID int64  `json:"active_deployment_id,omitempty"`
	ObservedState      string `json:"observed_state"`
	Message            string `json:"message,omitempty"`
	Changed            bool   `json:"changed"`
}

type ReconcilePHPWorkersReq struct {
	Application PHPApplicationSpec      `json:"application"`
	Workers     []PHPWorker             `json:"workers"`
	Environment []PHPEnvironmentPayload `json:"environment,omitempty"`
}

type ReconcilePHPWorkersResult struct {
	ApplicationID int64    `json:"application_id"`
	Changed       bool     `json:"changed"`
	Reconciled    []int64  `json:"reconciled,omitempty"`
	Removed       []int64  `json:"removed,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

// River arguments intentionally carry identifiers and revision fences only.
type DeployPHPApplicationArgs struct {
	ApplicationID   int64 `json:"application_id" river:"unique"`
	DeploymentID    int64 `json:"deployment_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

type RollbackPHPApplicationArgs struct {
	ApplicationID      int64 `json:"application_id" river:"unique"`
	DeploymentID       int64 `json:"deployment_id" river:"unique"`
	TargetDeploymentID int64 `json:"target_deployment_id" river:"unique"`
	DesiredRevision    int64 `json:"desired_revision" river:"unique"`
}

type ReconcilePHPApplicationArgs struct {
	ApplicationID   int64 `json:"application_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

type ReconcilePHPWorkersArgs struct {
	ApplicationID   int64 `json:"application_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}
