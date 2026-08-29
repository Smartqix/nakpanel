package platformadmin

import (
	"reflect"
	"testing"
)

func validDatabaseServer() DatabaseServerSpec {
	return DatabaseServerSpec{
		ID: "primary-db", Name: "Primary database", Engine: DatabaseEngineMariaDB,
		Host: "db.internal.example", Port: 3306, TLSMode: DatabaseTLSVerifyFull,
		CredentialSecretID: 41, CASecretID: 42,
	}
}

func TestDatabaseServerSpec(t *testing.T) {
	if err := validDatabaseServer().Validate(); err != nil {
		t.Fatalf("valid server: %v", err)
	}

	local := validDatabaseServer()
	local.Host = "127.0.0.1"
	local.TLSMode = DatabaseTLSDisabled
	local.CASecretID = 0
	if err := local.Validate(); err != nil {
		t.Fatalf("loopback server may explicitly disable TLS: %v", err)
	}
}

func TestDatabaseServerRejectsUnsafeOrUnencryptedRemoteConfiguration(t *testing.T) {
	tests := []func(*DatabaseServerSpec){
		func(spec *DatabaseServerSpec) { spec.ID = "primary;drop" },
		func(spec *DatabaseServerSpec) { spec.Name = "Primary\nInjected" },
		func(spec *DatabaseServerSpec) { spec.Engine = "mysql; flags" },
		func(spec *DatabaseServerSpec) { spec.Host = "https://db.example" },
		func(spec *DatabaseServerSpec) { spec.Host = "db.example; command" },
		func(spec *DatabaseServerSpec) { spec.Port = 0 },
		func(spec *DatabaseServerSpec) { spec.TLSMode = DatabaseTLSDisabled; spec.CASecretID = 0 },
		func(spec *DatabaseServerSpec) { spec.TLSMode = DatabaseTLSVerifyCA; spec.CASecretID = 0 },
		func(spec *DatabaseServerSpec) { spec.CredentialSecretID = 0 },
	}
	for _, mutate := range tests {
		spec := validDatabaseServer()
		mutate(&spec)
		if err := spec.Validate(); err == nil {
			t.Fatalf("expected server rejection for %#v", spec)
		}
	}
}

func TestDatabaseRoleUsesOnlySafeTemplatesAndIDs(t *testing.T) {
	for _, role := range []DatabaseRole{
		DatabaseRoleReadOnly, DatabaseRoleReadWrite, DatabaseRoleSchemaManager,
	} {
		request := DatabaseRoleRequest{
			ServerID: "primary-db", DatabaseID: 1, PrincipalID: 2, Role: role,
		}
		if err := request.Validate(); err != nil {
			t.Fatalf("%s should be valid: %v", role, err)
		}
	}
	if err := (DatabaseRoleRequest{
		ServerID: "primary-db", DatabaseID: 1, PrincipalID: 2, Role: "SUPERUSER",
	}).Validate(); err == nil {
		t.Fatal("expected arbitrary role to be rejected")
	}
}

func TestCanonicalDatabaseCIDRs(t *testing.T) {
	got, err := CanonicalDatabaseCIDRs([]string{
		"192.0.2.4/24", "2001:db8::1/64", "192.0.2.0/24",
	}, false)
	if err != nil {
		t.Fatalf("canonicalize CIDRs: %v", err)
	}
	want := []string{"192.0.2.0/24", "2001:db8::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical CIDRs = %#v, want %#v", got, want)
	}
}

func TestDatabaseAccessRequiresPublicAcknowledgement(t *testing.T) {
	if _, err := CanonicalDatabaseCIDRs([]string{"0.0.0.0/0"}, false); err == nil {
		t.Fatal("expected world-open IPv4 rule to require acknowledgement")
	}
	if _, err := CanonicalDatabaseCIDRs([]string{"::/0"}, false); err == nil {
		t.Fatal("expected world-open IPv6 rule to require acknowledgement")
	}
	if got, err := CanonicalDatabaseCIDRs([]string{"0.0.0.0/0", "::/0"}, true); err != nil || len(got) != 2 {
		t.Fatalf("acknowledged public networks = %#v, %v", got, err)
	}
	if _, err := CanonicalDatabaseCIDRs([]string{"127.0.0.1;DROP/32"}, false); err == nil {
		t.Fatal("expected malformed CIDR to be rejected")
	}
}

func TestDatabaseDumpRequest(t *testing.T) {
	valid := DatabaseDumpRequest{
		ServerID: "primary-db", DatabaseID: 7,
		Format: DatabaseDumpFormatSQL, Compression: DatabaseDumpCompressionGzip,
		Destination: DatabaseDumpDestinationBackup, IncludeSchema: true, IncludeData: true,
	}
	if err := valid.Validate(DatabaseEngineMariaDB); err != nil {
		t.Fatalf("valid dump: %v", err)
	}

	pg := valid
	pg.Format = DatabaseDumpFormatCustom
	if err := pg.Validate(DatabaseEnginePostgreSQL); err != nil {
		t.Fatalf("valid PostgreSQL custom dump: %v", err)
	}
}

func TestDatabaseDumpRejectsFlagsPathsAndInvalidCombinations(t *testing.T) {
	base := DatabaseDumpRequest{
		ServerID: "primary-db", DatabaseID: 7,
		Format: DatabaseDumpFormatSQL, Compression: DatabaseDumpCompressionGzip,
		Destination: DatabaseDumpDestinationDownload, IncludeSchema: true,
	}
	tests := []struct {
		mutate func(*DatabaseDumpRequest)
		engine DatabaseEngine
	}{
		{func(request *DatabaseDumpRequest) { request.ServerID = "../socket" }, DatabaseEngineMariaDB},
		{func(request *DatabaseDumpRequest) { request.DatabaseID = 0 }, DatabaseEngineMariaDB},
		{func(request *DatabaseDumpRequest) {}, "mariadb --all-databases"},
		{func(request *DatabaseDumpRequest) { request.Format = DatabaseDumpFormatCustom }, DatabaseEngineMariaDB},
		{func(request *DatabaseDumpRequest) { request.Compression = "gzip; rm" }, DatabaseEngineMariaDB},
		{func(request *DatabaseDumpRequest) { request.Destination = "/tmp/dump.sql" }, DatabaseEngineMariaDB},
		{func(request *DatabaseDumpRequest) { request.IncludeSchema = false; request.IncludeData = false }, DatabaseEngineMariaDB},
		{func(request *DatabaseDumpRequest) { request.RetentionHours = 721 }, DatabaseEngineMariaDB},
	}
	for _, test := range tests {
		request := base
		test.mutate(&request)
		if err := request.Validate(test.engine); err == nil {
			t.Fatalf("expected dump rejection for %#v", request)
		}
	}
}
