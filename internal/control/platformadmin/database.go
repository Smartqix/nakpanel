package platformadmin

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

type DatabaseEngine string

const (
	DatabaseEngineMariaDB    DatabaseEngine = "mariadb"
	DatabaseEnginePostgreSQL DatabaseEngine = "postgresql"
)

type DatabaseTLSMode string

const (
	DatabaseTLSRequired   DatabaseTLSMode = "required"
	DatabaseTLSVerifyCA   DatabaseTLSMode = "verify-ca"
	DatabaseTLSVerifyFull DatabaseTLSMode = "verify-full"
	DatabaseTLSDisabled   DatabaseTLSMode = "disabled"
)

// DatabaseServerSpec is a registry entry, not an agent request. Agent calls
// carry only ID, so hostnames and credentials cannot be substituted at the
// privileged boundary.
type DatabaseServerSpec struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	Engine             DatabaseEngine  `json:"engine"`
	Host               string          `json:"host"`
	Port               int             `json:"port"`
	TLSMode            DatabaseTLSMode `json:"tls_mode"`
	CredentialSecretID int64           `json:"credential_secret_id"`
	CASecretID         int64           `json:"ca_secret_id,omitempty"`
}

func (s DatabaseServerSpec) Validate() error {
	if err := validateSafeRef("database server id", s.ID); err != nil {
		return err
	}
	if err := validateDisplayName("database server name", s.Name, 80); err != nil {
		return err
	}
	switch s.Engine {
	case DatabaseEngineMariaDB, DatabaseEnginePostgreSQL:
	default:
		return fmt.Errorf("unsupported database engine %q", s.Engine)
	}
	if err := validateEndpointHost("database server host", s.Host); err != nil {
		return err
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("database server port must be between 1 and 65535")
	}
	switch s.TLSMode {
	case DatabaseTLSRequired, DatabaseTLSVerifyCA, DatabaseTLSVerifyFull, DatabaseTLSDisabled:
	default:
		return fmt.Errorf("unsupported database TLS mode %q", s.TLSMode)
	}
	if !isLoopbackHost(s.Host) && s.TLSMode == DatabaseTLSDisabled {
		return errors.New("remote database servers require TLS")
	}
	if (s.TLSMode == DatabaseTLSVerifyCA || s.TLSMode == DatabaseTLSVerifyFull) && s.CASecretID <= 0 {
		return errors.New("verified database TLS requires a CA secret")
	}
	if s.TLSMode != DatabaseTLSVerifyCA && s.TLSMode != DatabaseTLSVerifyFull && s.CASecretID != 0 {
		return errors.New("CA secret is only valid for a verified TLS mode")
	}
	if s.CredentialSecretID <= 0 {
		return errors.New("database server credentials must reference an encrypted secret")
	}
	return nil
}

type DatabaseRole string

const (
	DatabaseRoleReadOnly      DatabaseRole = "read-only"
	DatabaseRoleReadWrite     DatabaseRole = "read-write"
	DatabaseRoleSchemaManager DatabaseRole = "schema-manager"
)

// DatabaseRoleRequest selects a server-owned role template. It contains no
// SQL, database identifier, username, or password.
type DatabaseRoleRequest struct {
	ServerID    string       `json:"server_id"`
	DatabaseID  int64        `json:"database_id"`
	PrincipalID int64        `json:"principal_id"`
	Role        DatabaseRole `json:"role"`
}

func (r DatabaseRoleRequest) Validate() error {
	if err := validateSafeRef("database server id", r.ServerID); err != nil {
		return err
	}
	if r.DatabaseID <= 0 || r.PrincipalID <= 0 {
		return errors.New("database and principal IDs are required")
	}
	switch r.Role {
	case DatabaseRoleReadOnly, DatabaseRoleReadWrite, DatabaseRoleSchemaManager:
		return nil
	default:
		return fmt.Errorf("unsupported database role %q", r.Role)
	}
}

// DatabaseAccessRequest applies canonical network prefixes to a stored
// database principal. A world-open prefix requires a separate acknowledgement.
type DatabaseAccessRequest struct {
	ServerID    string   `json:"server_id"`
	DatabaseID  int64    `json:"database_id"`
	PrincipalID int64    `json:"principal_id"`
	CIDRs       []string `json:"cidrs"`
	AllowPublic bool     `json:"allow_public,omitempty"`
}

func (r DatabaseAccessRequest) Validate() error {
	if err := validateSafeRef("database server id", r.ServerID); err != nil {
		return err
	}
	if r.DatabaseID <= 0 || r.PrincipalID <= 0 {
		return errors.New("database and principal IDs are required")
	}
	_, err := CanonicalDatabaseCIDRs(r.CIDRs, r.AllowPublic)
	return err
}

func CanonicalDatabaseCIDRs(values []string, allowPublic bool) ([]string, error) {
	if len(values) > 64 {
		return nil, errors.New("database access is limited to 64 CIDR rules")
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() {
			return nil, fmt.Errorf("database access CIDR %q is invalid", raw)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 && !allowPublic {
			return nil, errors.New("world-open database access requires explicit acknowledgement")
		}
		canonical := prefix.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	sort.Strings(result)
	return result, nil
}

type DatabaseDumpFormat string
type DatabaseDumpCompression string
type DatabaseDumpDestination string

const (
	DatabaseDumpFormatSQL    DatabaseDumpFormat = "sql"
	DatabaseDumpFormatCustom DatabaseDumpFormat = "custom"

	DatabaseDumpCompressionNone DatabaseDumpCompression = "none"
	DatabaseDumpCompressionGzip DatabaseDumpCompression = "gzip"

	DatabaseDumpDestinationDownload DatabaseDumpDestination = "download"
	DatabaseDumpDestinationBackup   DatabaseDumpDestination = "backup"
)

// DatabaseDumpRequest references a tracked database and a managed artifact
// destination. It cannot select a filesystem path or pass dump flags.
type DatabaseDumpRequest struct {
	ServerID       string                  `json:"server_id"`
	DatabaseID     int64                   `json:"database_id"`
	Format         DatabaseDumpFormat      `json:"format"`
	Compression    DatabaseDumpCompression `json:"compression"`
	Destination    DatabaseDumpDestination `json:"destination"`
	IncludeSchema  bool                    `json:"include_schema"`
	IncludeData    bool                    `json:"include_data"`
	RetentionHours int                     `json:"retention_hours,omitempty"`
}

// Validate checks the request against the engine loaded from ServerID's
// registry entry. The engine is intentionally not supplied by the caller.
func (r DatabaseDumpRequest) Validate(engine DatabaseEngine) error {
	if err := validateSafeRef("database server id", r.ServerID); err != nil {
		return err
	}
	if r.DatabaseID <= 0 {
		return errors.New("database ID is required")
	}
	switch engine {
	case DatabaseEngineMariaDB:
		if r.Format != DatabaseDumpFormatSQL {
			return errors.New("MariaDB dumps support only SQL format")
		}
	case DatabaseEnginePostgreSQL:
		if r.Format != DatabaseDumpFormatSQL && r.Format != DatabaseDumpFormatCustom {
			return errors.New("PostgreSQL dump format must be sql or custom")
		}
	default:
		return fmt.Errorf("unsupported database engine %q", engine)
	}
	if r.Compression != DatabaseDumpCompressionNone && r.Compression != DatabaseDumpCompressionGzip {
		return fmt.Errorf("unsupported database dump compression %q", r.Compression)
	}
	if r.Destination != DatabaseDumpDestinationDownload && r.Destination != DatabaseDumpDestinationBackup {
		return fmt.Errorf("unsupported database dump destination %q", r.Destination)
	}
	if !r.IncludeSchema && !r.IncludeData {
		return errors.New("database dump must include schema, data, or both")
	}
	if r.RetentionHours < 0 || r.RetentionHours > 24*30 {
		return errors.New("database dump retention must be between 0 and 720 hours")
	}
	return nil
}
