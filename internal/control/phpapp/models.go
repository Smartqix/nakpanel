package phpapp

import (
	"context"
	"errors"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ErrNotFound           = errors.New("PHP application not found")
	ErrInactive           = errors.New("PHP application subscription is inactive")
	ErrRuntimeUnavailable = errors.New("PHP runtime is unavailable")
	ErrRevisionConflict   = errors.New("PHP application revision conflict")
	ErrManagedToClassic   = errors.New("managed-to-classic conversion is not supported")
)

type SiteIdentity struct {
	ID             int64
	ApplicationID  int64
	SubscriptionID int64
	CustomerID     int64
	Domain         string
	PHPVersion     string
}

type Workspace struct {
	Application          types.PHPApplicationSpec
	Deployments          []types.PHPDeployment
	Environment          []types.PHPEnvironmentVariable
	Workers              []types.PHPWorker
	Policy               types.HostingPolicy
	Runtime              types.PHPRuntimeCapability
	ObservedState        string
	ConvergenceStatus    string
	ObservedMessage      string
	LastError            string
	AppliedRevision      int64
	ActiveDeploymentID   int64
	PreviousDeploymentID int64
	LoadedAt             time.Time
}

type ConfigureApplicationInput struct {
	HostingMode      types.PHPHostingMode
	PHPVersion       string
	RepositoryID     int64
	RepositoryRef    string
	FrameworkProfile types.PHPFrameworkProfile
	PublicPath       string
	HealthPath       string
	SharedPaths      []string
	ReleaseRetention int
	Composer         types.PHPComposerSpec
}

type DeploymentInput struct {
	RequestedRevision string
}

type EnvironmentInput struct {
	Name   string
	Value  string
	Secret bool
}

type WorkerInput struct {
	ID           int64
	Name         string
	Script       string
	Arguments    []string
	Processes    int
	DesiredState string
}

type AccessPolicy interface {
	CanManagePHP(context.Context, auth.SessionUser, string) (bool, error)
}

type CapabilityReader interface {
	RuntimeCapabilities(context.Context) (types.RuntimeCapabilities, error)
}

type ManagerStore interface {
	SiteIdentity(context.Context, int64) (SiteIdentity, error)
	Workspace(context.Context, int64) (Workspace, error)
	ConfigureApplication(context.Context, int64, int64, ConfigureApplicationInput, types.PHPRuntimeCapability) (types.PHPApplicationSpec, error)
	QueueDeployment(context.Context, int64, int64, DeploymentInput, types.PHPRuntimeCapability) (types.PHPDeployment, error)
	QueueRollback(context.Context, int64, int64, int64, types.PHPRuntimeCapability) (types.PHPDeployment, error)
	UpsertEnvironment(context.Context, int64, int64, EnvironmentInput) (types.PHPEnvironmentVariable, error)
	DeleteEnvironment(context.Context, int64, int64, string) error
	UpsertWorker(context.Context, int64, int64, WorkerInput) (types.PHPWorker, error)
	DeleteWorker(context.Context, int64, int64, int64) error
	SetWorkerState(context.Context, int64, int64, int64, string) error
	RequestReconcile(context.Context, int64, int64) error
}
