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

func TestPhase30PHPHostingTypesDoNotSerializeSecretPlaintext(t *testing.T) {
	variable := PHPEnvironmentVariable{Name: "APP_KEY", SecretID: 42, Secret: "must-not-leak"}
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

func TestPhase30PHPHostingPublicContractsRoundTrip(t *testing.T) {
	spec := PHPApplicationSpec{
		ApplicationID: 12, SubscriptionID: 4, SiteID: 7,
		HostingMode: HostingModeManaged, PHPVersion: "8.4",
		RepositoryID: 15, RepositoryRef: "main", PublicPath: "public",
		Composer: PHPComposerSpec{Install: true, AllowScripts: false},
		Workers:  []PHPWorkerSpec{{WorkerID: 18, Name: "queue", Script: "artisan", Arguments: []string{"queue:work"}, Processes: 2}},
	}
	request := DeployPHPApplicationReq{
		Application: spec,
		Deployment:  PHPDeployment{ID: 22, ApplicationID: 12, RequestedRevision: "main"},
		Environment: []PHPEnvironmentVariable{{Name: "APP_ENV", Value: "production"}, {Name: "APP_KEY", SecretID: 41, Secret: "runtime-only"}},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "runtime-only") {
		t.Fatalf("deploy request leaked secret: %s", encoded)
	}
	var decoded DeployPHPApplicationReq
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Application.HostingMode != HostingModeManaged || decoded.Application.Workers[0].Processes != 2 || decoded.Environment[0].Value != "production" {
		t.Fatalf("decoded deploy request = %#v", decoded)
	}

	capabilities := RuntimeCapabilities{
		PHPVersions:       []string{"8.4"},
		PHPRuntimes:       []PHPRuntimeCapability{{Version: "8.4", Ready: true, SupportStatus: PHPSupportActive}},
		ComposerAvailable: true, ComposerVersion: "2.8.10",
		WPCLIAvailable: true, WPCLIVersion: "2.12.0",
	}
	capJSON, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(capJSON), `"php_versions":["8.4"]`) ||
		!strings.Contains(string(capJSON), `"php_runtimes"`) ||
		!strings.Contains(string(capJSON), `"composer_available":true`) ||
		!strings.Contains(string(capJSON), `"wp_cli_available":true`) {
		t.Fatalf("runtime capabilities JSON = %s", capJSON)
	}
}
