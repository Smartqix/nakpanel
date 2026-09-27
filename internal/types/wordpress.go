package types

import "time"

type WordPressAction string

const (
	WordPressActionInstall       WordPressAction = "install"
	WordPressActionInspect       WordPressAction = "inspect"
	WordPressActionDiscover      WordPressAction = "discover"
	WordPressActionRefresh       WordPressAction = "refresh"
	WordPressActionUpdate        WordPressAction = "update"
	WordPressActionVerify        WordPressAction = "verify"
	WordPressActionHarden        WordPressAction = "harden"
	WordPressActionMaintenance   WordPressAction = "maintenance"
	WordPressActionPasswordReset WordPressAction = "password_reset"
	WordPressActionUninstall     WordPressAction = "uninstall"
)

type WordPressTargetType string

const (
	WordPressTargetCore   WordPressTargetType = "core"
	WordPressTargetPlugin WordPressTargetType = "plugin"
	WordPressTargetTheme  WordPressTargetType = "theme"
	WordPressTargetAll    WordPressTargetType = "all"
)

type WordPressSiteSpec struct {
	InstanceID      int64          `json:"instance_id"`
	SubscriptionID  int64          `json:"subscription_id"`
	SiteID          int64          `json:"site_id"`
	DesiredRevision int64          `json:"desired_revision"`
	Username        string         `json:"username"`
	Domain          string         `json:"domain"`
	PHPVersion      string         `json:"php_version"`
	TLSActive       bool           `json:"tls_active"`
	HostingMode     PHPHostingMode `json:"hosting_mode"`
	Policy          HostingPolicy  `json:"policy"`
}

type WordPressCredentials struct {
	DatabaseName     string `json:"database_name"`
	DatabaseUser     string `json:"database_user"`
	DatabasePassword string `json:"database_password"`
	AdminUser        string `json:"admin_user"`
	AdminEmail       string `json:"admin_email"`
	AdminPassword    string `json:"admin_password"`
	SiteTitle        string `json:"site_title"`
}

type WordPressOperationReq struct {
	OperationID      int64                 `json:"operation_id"`
	Action           WordPressAction       `json:"action"`
	Site             WordPressSiteSpec     `json:"site"`
	TargetType       WordPressTargetType   `json:"target_type,omitempty"`
	TargetSlug       string                `json:"target_slug,omitempty"`
	RequestedVersion string                `json:"requested_version,omitempty"`
	Maintenance      bool                  `json:"maintenance,omitempty"`
	Credentials      *WordPressCredentials `json:"credentials,omitempty"`
	Removal          *WordPressRemovalSpec `json:"removal,omitempty"`
}

type WordPressRemovalSpec struct {
	DeleteDatabase bool   `json:"delete_database"`
	DatabaseName   string `json:"database_name,omitempty"`
	DatabaseUser   string `json:"database_user,omitempty"`
	Finalize       bool   `json:"finalize,omitempty"`
}

type WordPressRemovalResult struct {
	FilesRemoved      bool  `json:"files_removed"`
	DatabaseRemoved   bool  `json:"database_removed"`
	DatabasePreserved bool  `json:"database_preserved"`
	BackupID          int64 `json:"backup_id,omitempty"`
}

type WordPressComponent struct {
	Slug          string `json:"slug"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	Update        string `json:"update,omitempty"`
	UpdateVersion string `json:"update_version,omitempty"`
	AutoUpdate    string `json:"auto_update,omitempty"`
}

type WordPressInventory struct {
	CoreVersion      string               `json:"core_version"`
	CoreUpdate       string               `json:"core_update,omitempty"`
	SiteTitle        string               `json:"site_title"`
	AdminUser        string               `json:"admin_user"`
	AdminEmail       string               `json:"admin_email"`
	SiteURL          string               `json:"site_url"`
	HomeURL          string               `json:"home_url"`
	PHPVersion       string               `json:"php_version"`
	Plugins          []WordPressComponent `json:"plugins"`
	Themes           []WordPressComponent `json:"themes"`
	UpdatesAvailable int                  `json:"updates_available"`
	CollectedAt      time.Time            `json:"collected_at"`
}

type WordPressSecurityState struct {
	CoreChecksumsValid  bool     `json:"core_checksums_valid"`
	FilePermissionsSafe bool     `json:"file_permissions_safe"`
	FileEditingDisabled bool     `json:"file_editing_disabled"`
	DebugDisabled       bool     `json:"debug_disabled"`
	HTTPSConfigured     bool     `json:"https_configured"`
	Score               int      `json:"score"`
	Findings            []string `json:"findings,omitempty"`
}

type WordPressOperationResult struct {
	Action    WordPressAction         `json:"action"`
	Changed   bool                    `json:"changed"`
	Inventory WordPressInventory      `json:"inventory"`
	Security  WordPressSecurityState  `json:"security"`
	Output    string                  `json:"output,omitempty"`
	Removal   *WordPressRemovalResult `json:"removal,omitempty"`
}

// WordPressOperationArgs is the public identifier-only job contract. The
// concrete River type in the control plane intentionally has the same shape.
type WordPressOperationArgs struct {
	InstanceID      int64 `json:"instance_id"`
	OperationID     int64 `json:"operation_id"`
	DesiredRevision int64 `json:"desired_revision"`
}
