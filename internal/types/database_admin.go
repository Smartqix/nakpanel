package types

import "time"

const (
	OpInspectDatabaseAdmin = "inspect_database_admin"
	OpManageDatabaseAdmin  = "manage_database_admin"
)

type DatabaseAdminTarget struct {
	DatabaseID int64  `json:"database_id"`
	Name       string `json:"name"`
	Principal  string `json:"principal"`
}

type InspectDatabaseAdminReq struct {
	Targets []DatabaseAdminTarget `json:"targets,omitempty"`
}

type DatabaseServerHealth struct {
	Engine      string    `json:"engine"`
	Version     string    `json:"version,omitempty"`
	Available   bool      `json:"available"`
	Connections int       `json:"connections"`
	Threads     int       `json:"threads"`
	Uptime      int64     `json:"uptime_seconds"`
	CheckedAt   time.Time `json:"checked_at"`
	LastError   string    `json:"last_error,omitempty"`
}

type TrackedDatabaseState struct {
	DatabaseID       int64  `json:"database_id"`
	Name             string `json:"name"`
	Principal        string `json:"principal"`
	DatabaseExists   bool   `json:"database_exists"`
	PrincipalExists  bool   `json:"principal_exists"`
	IntegrityChecked bool   `json:"integrity_checked,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

type DatabaseAdminSnapshot struct {
	Server    DatabaseServerHealth   `json:"server"`
	Databases []TrackedDatabaseState `json:"databases"`
	CheckedAt time.Time              `json:"checked_at"`
}

type DatabaseAdminAction string

const (
	DatabaseAdminRotatePassword DatabaseAdminAction = "rotate_password"
	DatabaseAdminSetRole        DatabaseAdminAction = "set_role"
	DatabaseAdminCheck          DatabaseAdminAction = "check"
)

type DatabaseAdminRole string

const (
	DatabaseAdminRoleReadOnly      DatabaseAdminRole = "read-only"
	DatabaseAdminRoleReadWrite     DatabaseAdminRole = "read-write"
	DatabaseAdminRoleSchemaManager DatabaseAdminRole = "schema-manager"
)

type ManageDatabaseAdminReq struct {
	OperationID string              `json:"operation_id"`
	Action      DatabaseAdminAction `json:"action"`
	Target      DatabaseAdminTarget `json:"target"`
	Role        DatabaseAdminRole   `json:"role,omitempty"`
	Password    string              `json:"password,omitempty"`
}

type DatabaseIntegrityItem struct {
	Table   string `json:"table"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type ManageDatabaseAdminResult struct {
	OperationID string                  `json:"operation_id,omitempty"`
	DatabaseID  int64                   `json:"database_id"`
	Action      DatabaseAdminAction     `json:"action"`
	Status      string                  `json:"status,omitempty"`
	Changed     bool                    `json:"changed"`
	Role        DatabaseAdminRole       `json:"role,omitempty"`
	Checks      []DatabaseIntegrityItem `json:"checks,omitempty"`
	CheckedAt   time.Time               `json:"checked_at"`
}
