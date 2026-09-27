package wordpress

import (
	"context"
	"errors"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ErrNotFound      = errors.New("WordPress site not found")
	ErrDisabled      = errors.New("WordPress Toolkit is disabled by the subscription")
	ErrInactive      = errors.New("WordPress site is inactive")
	ErrNotClassic    = errors.New("WordPress Toolkit requires Classic PHP hosting")
	ErrLimitReached  = errors.New("WordPress site limit reached")
	ErrDatabaseLimit = errors.New("WordPress database limit reached")
	ErrBusy          = errors.New("another WordPress operation is already running")
	ErrInvalidInput  = errors.New("invalid WordPress input")
)

type SiteIdentity struct {
	SiteID, SubscriptionID, CustomerID int64
	Username, Domain, PHPVersion       string
	TLSActive                          bool
	HostingMode                        types.PHPHostingMode
}

type Instance struct {
	ID, SubscriptionID, SiteID, DatabaseID int64
	AdminUser, AdminEmail, SiteTitle       string
	InstalledVersion, UpdatePolicy         string
	MaintenanceMode                        bool
	DatabaseManaged                        bool
	Inventory                              types.WordPressInventory
	Security                               types.WordPressSecurityState
	ChecksumStatus                         string
	DesiredState, ObservedState            string
	DesiredRevision, AppliedRevision       int64
	ConvergenceStatus, LastError           string
	LastScannedAt                          time.Time
	CreatedAt, UpdatedAt                   time.Time
}

type Operation struct {
	ID, SubscriptionID, InstanceID, RequestedByUserID, BackupID int64
	Kind                                                        types.WordPressAction
	TargetType                                                  types.WordPressTargetType
	TargetSlug, RequestedVersion, Status, Output, LastError     string
	Maintenance                                                 bool
	BackupRequested, DatabaseRemovalRequested                   bool
	DesiredRevision                                             int64
	Result                                                      types.WordPressOperationResult
	StartedAt, FinishedAt, CreatedAt                            time.Time
}

type Workspace struct {
	Site       SiteIdentity
	Policy     types.HostingPolicy
	Instance   *Instance
	Operations []Operation
	Available  bool
	Reason     string
	LoadedAt   time.Time
}

type InstallInput struct {
	Title, AdminUser, AdminEmail, AdminPassword, Version string
}

type OperationInput struct {
	Action           types.WordPressAction
	TargetType       types.WordPressTargetType
	TargetSlug       string
	RequestedVersion string
	Maintenance      bool
	AdminPassword    string
}

type UninstallInput struct {
	CreateBackup   bool
	DeleteDatabase bool
	ConfirmDomain  string
}

type AccessPolicy interface {
	CanManageDomain(context.Context, auth.SessionUser, string) (bool, error)
	CanManageSubscription(context.Context, auth.SessionUser, int64) (bool, error)
}

type Provisioner interface {
	CreateDatabaseForSubscription(context.Context, auth.SessionUser, int64, types.CreateDatabaseReq) (int64, error)
	CreateBackupForSubscription(context.Context, auth.SessionUser, int64, types.CreateBackupReq) (int64, error)
}

type ManagerStore interface {
	PreflightNewSite(context.Context, int64) error
	SiteIdentity(context.Context, int64) (SiteIdentity, error)
	Workspace(context.Context, int64) (Workspace, error)
	ReserveInstall(context.Context, int64, SiteIdentity, InstallInput) (Instance, Operation, error)
	CompleteInstallReservation(context.Context, int64, int64, int64, string) error
	FailReservation(context.Context, int64, int64, error) error
	ReserveOperation(context.Context, int64, SiteIdentity, OperationInput) (Instance, Operation, error)
	AttachBackupAndEnqueue(context.Context, int64, int64) error
	Detach(context.Context, int64, SiteIdentity) error
	ReserveUninstall(context.Context, auth.SessionUser, SiteIdentity, UninstallInput) (Instance, Operation, error)
	FailUninstallReservation(context.Context, int64, int64, error) error
}
