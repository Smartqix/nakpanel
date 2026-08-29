package types

import "time"

const (
	ApplicationKindContainer = "container"
	ApplicationKindManaged   = "managed"

	ApplicationRouteDomain = "domain"
	ApplicationRoutePrefix = "prefix"

	ApplicationHealthHTTP = "http"
	ApplicationHealthTCP  = "tcp"
)

type ApplicationEndpointSpec struct {
	RouteMode     string `json:"route_mode"`
	RoutePrefix   string `json:"route_prefix"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
}

type ApplicationVolumeSpec struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	SizeMB   int    `json:"size_mb"`
	ReadOnly bool   `json:"read_only"`
}

type ApplicationHealthSpec struct {
	Kind           string `json:"kind"`
	Path           string `json:"path,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type ApplicationManifestRevision struct {
	PresetID     int64                   `json:"preset_id"`
	Revision     int64                   `json:"revision"`
	Runtime      string                  `json:"runtime"`
	ImageRef     string                  `json:"image_ref"`
	ReadOnlyRoot bool                    `json:"read_only_root"`
	Endpoint     ApplicationEndpointSpec `json:"endpoint"`
	Volumes      []ApplicationVolumeSpec `json:"volumes,omitempty"`
	Health       ApplicationHealthSpec   `json:"health"`
	Environment  []string                `json:"environment,omitempty"`
	SecretNames  []string                `json:"secret_names,omitempty"`
}

type ApplicationSecretBinding struct {
	Name      string    `json:"name"`
	SecretID  string    `json:"secret_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ApplicationGeneration struct {
	ID              int64     `json:"id"`
	ApplicationID   int64     `json:"application_id"`
	DesiredRevision int64     `json:"desired_revision"`
	ImageRef        string    `json:"image_ref"`
	EndpointPort    int       `json:"endpoint_port"`
	UnitName        string    `json:"unit_name"`
	ContainerName   string    `json:"container_name"`
	Status          string    `json:"status"`
	HealthMessage   string    `json:"health_message,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	HealthyAt       time.Time `json:"healthy_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type ApplicationObservedState struct {
	ApplicationID  int64     `json:"application_id"`
	DesiredState   string    `json:"desired_state"`
	ObservedState  string    `json:"observed_state"`
	Message        string    `json:"message,omitempty"`
	ActiveRevision int64     `json:"active_revision"`
	EndpointPort   int       `json:"endpoint_port,omitempty"`
	UnitName       string    `json:"unit_name,omitempty"`
	ContainerName  string    `json:"container_name,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
}

type DeployApplicationGenerationResult struct {
	ApplicationObservedState
	Changed bool `json:"changed"`
}

type ApplicationControlReq struct {
	ApplicationID  int64                   `json:"application_id"`
	SubscriptionID int64                   `json:"subscription_id"`
	Username       string                  `json:"username"`
	ActiveRevision int64                   `json:"active_revision,omitempty"`
	Action         string                  `json:"action"`
	Endpoint       ApplicationEndpointSpec `json:"endpoint,omitempty"`
	Health         ApplicationHealthSpec   `json:"health,omitempty"`
}

type ApplicationLogReq struct {
	ApplicationID  int64  `json:"application_id"`
	SubscriptionID int64  `json:"subscription_id"`
	Username       string `json:"username"`
	Lines          int    `json:"lines"`
	Bytes          int    `json:"bytes"`
}

type ApplicationLogResult struct {
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
}
