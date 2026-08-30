package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPhase30PHPHostingTypesPreserveLegacyRuntimeJSON(t *testing.T) {
	legacyRuntime := []byte(`{"php_versions":["8.4"],"disk_quota":true}`)
	var capabilities RuntimeCapabilities
	if err := json.Unmarshal(legacyRuntime, &capabilities); err != nil {
		t.Fatal(err)
	}
	if len(capabilities.PHPVersions) != 1 || capabilities.PHPVersions[0] != "8.4" || !capabilities.DiskQuota {
		t.Fatalf("legacy runtime JSON changed: %#v", capabilities)
	}

	legacySite := []byte(`{"site_id":7,"username":"acct","domain":"example.test","php_version":"8.4","state":"active","policy":{},"limits":{}}`)
	var runtime SiteRuntimeSpec
	if err := json.Unmarshal(legacySite, &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.SiteID != 7 || runtime.PHPVersion != "8.4" || runtime.HostingMode != "" {
		t.Fatalf("legacy site runtime JSON changed: %#v", runtime)
	}
}

func TestPhase30PublicEnvironmentBindingsDoNotCarrySecretPlaintext(t *testing.T) {
	variable := PHPEnvironmentVariable{Name: "APP_KEY", SecretID: 42}
	if err := json.Unmarshal([]byte(`{"name":"APP_KEY","secret_id":42,"secret":"must-not-leak"}`), &variable); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(variable)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-leak") || !strings.Contains(string(encoded), `"secret_id":42`) {
		t.Fatalf("environment variable JSON = %s", encoded)
	}

	args := DeployPHPApplicationArgs{ApplicationID: 9, DeploymentID: 10, DesiredRevision: 3}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	if string(argsJSON) != `{"application_id":9,"deployment_id":10,"desired_revision":3}` {
		t.Fatalf("deploy args JSON = %s", argsJSON)
	}
}

func TestPhase30ProtectedRPCEnvironmentRoundTripsDecryptedSecret(t *testing.T) {
	request := DeployPHPApplicationReq{
		Application: PHPApplicationSpec{ApplicationID: 9},
		Deployment:  PHPDeployment{ID: 10},
		Environment: []PHPEnvironmentPayload{
			{Name: "APP_ENV", Value: "production"},
			{Name: "APP_KEY", Secret: "rpc-only-secret"},
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"secret":"rpc-only-secret"`) {
		t.Fatalf("protected RPC request lost decrypted secret: %s", encoded)
	}
	var decoded DeployPHPApplicationReq
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Environment[1].Secret != "rpc-only-secret" {
		t.Fatalf("protected RPC secret = %q", decoded.Environment[1].Secret)
	}
}

func TestPhase30PHPHostingPublicContractsRoundTrip(t *testing.T) {
	spec := PHPApplicationSpec{
		ApplicationID: 12, SubscriptionID: 4, SiteID: 7,
		HostingMode: PHPHostingModeManaged, PHPVersion: "8.4",
		RepositoryID: 15, RepositoryRef: "main", FrameworkProfile: PHPFrameworkLaravel,
		PublicPath: "public", HealthPath: "/up", SharedPaths: []string{"storage", "bootstrap/cache"},
		Composer: PHPComposerSpec{Install: true, AllowScripts: false},
		Workers:  []PHPWorkerSpec{{WorkerID: 18, Name: "queue", Script: "artisan", Arguments: []string{"queue:work"}, Processes: 2}},
	}
	request := DeployPHPApplicationReq{
		Application: spec,
		Deployment:  PHPDeployment{ID: 22, ApplicationID: 12, RequestedRevision: "main"},
		Environment: []PHPEnvironmentPayload{{Name: "APP_ENV", Value: "production"}, {Name: "APP_KEY", Secret: "runtime-only"}},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"secret":"runtime-only"`) {
		t.Fatalf("protected deploy RPC lost secret: %s", encoded)
	}
	var decoded DeployPHPApplicationReq
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Application.HostingMode != PHPHostingModeManaged || decoded.Application.FrameworkProfile != PHPFrameworkLaravel ||
		decoded.Application.HealthPath != "/up" || len(decoded.Application.SharedPaths) != 2 ||
		decoded.Application.Workers[0].Processes != 2 || decoded.Environment[0].Value != "production" {
		t.Fatalf("decoded deploy request = %#v", decoded)
	}

	var _ DeployPHPReleaseReq = request
	var _ DeployPHPReleaseResult = DeployPHPApplicationResult{}
	var _ RollbackPHPReleaseReq = RollbackPHPApplicationReq{}
	var _ RollbackPHPReleaseResult = RollbackPHPApplicationResult{}

	capabilities := RuntimeCapabilities{
		PHPVersions:       []string{"8.4"},
		PHPRuntimes:       []PHPRuntimeCapability{{Version: "8.4", Ready: true, SupportStatus: PHPSupportActive, CLIPath: "/usr/bin/php8.4", FPMPath: "/usr/sbin/php-fpm8.4"}},
		ComposerAvailable: true, ComposerVersion: "2.8.10",
		WPCLIAvailable: true, WPCLIVersion: "2.12.0",
	}
	capJSON, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(capJSON), `"php_versions":["8.4"]`) ||
		!strings.Contains(string(capJSON), `"php_runtimes"`) ||
		!strings.Contains(string(capJSON), `"cli_path":"/usr/bin/php8.4"`) ||
		!strings.Contains(string(capJSON), `"fpm_path":"/usr/sbin/php-fpm8.4"`) ||
		!strings.Contains(string(capJSON), `"composer_available":true`) ||
		!strings.Contains(string(capJSON), `"wp_cli_available":true`) {
		t.Fatalf("runtime capabilities JSON = %s", capJSON)
	}
}
