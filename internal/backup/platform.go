package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// PlatformProvenance records observed versions, never credentials or dump data.
// Unknown optional observations remain empty; they cannot qualify a migration.
type PlatformProvenance struct {
	OSID                   string            `json:"os_id"`
	VersionID              string            `json:"version_id"`
	Codename               string            `json:"codename,omitempty"`
	Architecture           string            `json:"architecture"`
	Profile                string            `json:"profile,omitempty"`
	InternalPHPVersion     string            `json:"internal_php_version,omitempty"`
	HostingPHPVersions     []string          `json:"hosting_php_versions,omitempty"`
	RequiredPHPVersions    []string          `json:"required_php_versions,omitempty"`
	PHPInventoryComplete   bool              `json:"php_inventory_complete"`
	PostgresServerVersion  string            `json:"postgres_server_version,omitempty"`
	PostgresDumpVersion    string            `json:"postgres_dump_version,omitempty"`
	PostgresRestoreVersion string            `json:"postgres_restore_version,omitempty"`
	MariaDBServerVersion   string            `json:"mariadb_server_version,omitempty"`
	MariaDBDumpVersion     string            `json:"mariadb_dump_version,omitempty"`
	MariaDBClientVersion   string            `json:"mariadb_client_version,omitempty"`
	StalwartVersion        string            `json:"stalwart_version,omitempty"`
	ImageDigests           map[string]string `json:"image_digests,omitempty"`
}

type RestoreMode string

const (
	RestoreSamePlatform     RestoreMode = "same-platform"
	RestoreForwardMigration RestoreMode = "forward-migration"
)

// CheckRestoreCompatibility is a read-only gate; run it before stopping services
// or creating any restore state. Passing is necessary, not migration qualification.
func CheckRestoreCompatibility(source Manifest, target PlatformProvenance, mode RestoreMode) error {
	if mode == "" {
		mode = RestoreSamePlatform
	}
	if mode != RestoreSamePlatform && mode != RestoreForwardMigration {
		return fmt.Errorf("unknown restore mode %q", mode)
	}
	s := source.Platform
	if s == nil {
		if mode == RestoreSamePlatform && target.OSID == "ubuntu" && target.VersionID == "24.04" {
			return nil
		}
		return fmt.Errorf("legacy archive has no platform provenance; same-platform recovery is limited to Ubuntu 24.04; cross-release recovery requires reviewed provenance reconstruction")
	}
	if s.OSID != "ubuntu" || target.OSID != s.OSID {
		return fmt.Errorf("restore OS mismatch: %q -> %q", s.OSID, target.OSID)
	}
	if s.Architecture == "" || s.Architecture != target.Architecture {
		return fmt.Errorf("restore architecture mismatch: %q -> %q", s.Architecture, target.Architecture)
	}
	if mode == RestoreSamePlatform {
		if s.VersionID == "" || s.VersionID != target.VersionID {
			return fmt.Errorf("same-platform restore requires the same OS release; use the separately qualified forward-migration path")
		}
		if s.Profile != "" && target.Profile != "" && s.Profile != target.Profile {
			return fmt.Errorf("same-platform restore requires the same installed profile (%s -> %s)", s.Profile, target.Profile)
		}
		if s.VersionID == "26.04" && (s.Profile == "" || target.Profile == "") {
			return fmt.Errorf("same-platform 26.04 restore requires recorded installed profiles")
		}
	} else {
		if s.VersionID != "24.04" || target.VersionID != "26.04" {
			return fmt.Errorf("unsupported forward-migration direction %s -> %s", s.VersionID, target.VersionID)
		}
		if s.Profile != "ubuntu-24.04" || (target.Profile != "ubuntu-26.04-native" && target.Profile != "ubuntu-26.04-sury") || s.Codename != "noble" || target.Codename != "resolute" || s.InternalPHPVersion != "8.3" || target.InternalPHPVersion != "8.5" {
			return fmt.Errorf("forward-migration requires reviewed ubuntu-24.04 to a known ubuntu-26.04 profile")
		}
		for _, p := range []PlatformProvenance{*s, target} {
			if p.Codename == "" || p.Profile == "" || p.InternalPHPVersion == "" || len(p.HostingPHPVersions) == 0 || p.PostgresServerVersion == "" || p.PostgresDumpVersion == "" || p.PostgresRestoreVersion == "" || p.MariaDBServerVersion == "" || p.MariaDBDumpVersion == "" || p.MariaDBClientVersion == "" {
				return fmt.Errorf("forward-migration requires complete observed platform and database provenance")
			}
		}
		if !s.PHPInventoryComplete {
			return fmt.Errorf("forward-migration requires a complete source PHP intent inventory")
		}
	}
	for _, required := range s.RequiredPHPVersions {
		found := false
		for _, installed := range target.HostingPHPVersions {
			if installed == required {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("target lacks required hosted PHP %s; tenant intent cannot be rewritten", required)
		}
	}
	// pg_dump can emit a newer custom archive format than the server. pg_restore
	// and the target server must therefore both cover the actual dump tool version.
	for _, v := range []string{s.PostgresServerVersion, s.PostgresDumpVersion} {
		if err := requireNotOlder("PostgreSQL server", target.PostgresServerVersion, v, 1); err != nil {
			return err
		}
	}
	if err := requireNotOlder("pg_restore", target.PostgresRestoreVersion, s.PostgresDumpVersion, 1); err != nil {
		return err
	}
	for _, v := range []string{s.MariaDBServerVersion, s.MariaDBDumpVersion} {
		if err := requireNotOlder("MariaDB server", target.MariaDBServerVersion, v, 2); err != nil {
			return err
		}
	}
	if err := requireNotOlder("MariaDB import client", target.MariaDBClientVersion, s.MariaDBDumpVersion, 2); err != nil {
		return err
	}
	if source.IncludeMailData && (mode == RestoreForwardMigration || s.StalwartVersion != "") && (s.StalwartVersion == "" || s.StalwartVersion != target.StalwartVersion) {
		return fmt.Errorf("Stalwart mail store requires the identical observed version; source %q target %q", s.StalwartVersion, target.StalwartVersion)
	}
	return nil
}

func requireNotOlder(label, target, source string, parts int) error {
	if source == "" {
		return nil
	} // Optional in same-platform archives; forward requires all fields above.
	if target == "" {
		return fmt.Errorf("%s target version is unknown", label)
	}
	s, t := versionNumbers(source), versionNumbers(target)
	if len(s) < parts || len(t) < parts {
		return fmt.Errorf("invalid %s version provenance", label)
	}
	for i := 0; i < parts; i++ {
		if t[i] > s[i] {
			return nil
		}
		if t[i] < s[i] {
			return fmt.Errorf("%s %s cannot import source %s", label, target, source)
		}
	}
	return nil
}

var observedVersionRE = regexp.MustCompile(`(?:^|[^0-9])([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

func observedVersion(value string) string {
	m := observedVersionRE.FindStringSubmatch(value)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}
func versionNumbers(value string) []int {
	v := observedVersion(value)
	if v == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

type platformProbe struct {
	readFile func(string) ([]byte, error)
	command  func(context.Context, string, ...string) ([]byte, error)
}

// CollectPlatformProvenance observes the local installed system. It never copies
// environment variables, tool errors, SQL credentials, or tool output verbatim.
// Missing tools leave unknown fields rather than inventing package versions.
type ReadyPHPCollector func(context.Context) ([]string, error)

func CollectPlatformProvenance(ctx context.Context, postgresDSN string, ready ...ReadyPHPCollector) (PlatformProvenance, error) {
	p, err := collectPlatform(ctx, postgresDSN, platformProbe{os.ReadFile, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}})
	if err != nil {
		return p, err
	}
	if len(ready) > 0 && ready[0] != nil {
		p.HostingPHPVersions, err = ready[0](ctx)
		sort.Strings(p.HostingPHPVersions)
	}
	return p, err
}
func collectPlatform(ctx context.Context, dsn string, probe platformProbe) (PlatformProvenance, error) {
	p := PlatformProvenance{Architecture: runtime.GOARCH}
	data, err := probe.readFile("/etc/os-release")
	if err != nil {
		return p, fmt.Errorf("read target OS identity: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "\"'")
		switch k {
		case "ID":
			p.OSID = v
		case "VERSION_ID":
			p.VersionID = v
		case "VERSION_CODENAME":
			p.Codename = v
		}
	}
	if data, err = probe.readFile("/etc/nakpanel/platform.json"); err == nil {
		var installed PlatformProvenance
		if json.Unmarshal(data, &installed) != nil {
			return p, fmt.Errorf("invalid installed platform state")
		}
		if installed.OSID != p.OSID || installed.VersionID != p.VersionID || installed.Architecture != p.Architecture {
			return p, fmt.Errorf("installed platform state does not match actual OS/architecture")
		}
		p.Profile = installed.Profile
		if installed.InternalPHPVersion != "" {
			out, e := probe.command(ctx, "php"+installed.InternalPHPVersion, "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
			if e == nil {
				p.InternalPHPVersion = strings.TrimSpace(string(out))
			}
		}
	}
	// Existing Noble installations predate platform.json and use the legacy
	// internal 8.3 interpreter; still observe the actual binary before recording.
	if p.InternalPHPVersion == "" && p.OSID == "ubuntu" && p.VersionID == "24.04" {
		if out, e := probe.command(ctx, "php8.3", "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;"); e == nil && strings.TrimSpace(string(out)) == "8.3" {
			p.InternalPHPVersion = "8.3"
		}
	}
	observe := func(name string, args ...string) string {
		out, e := probe.command(ctx, name, args...)
		if e != nil {
			return ""
		}
		return observedVersion(string(out))
	}
	p.PostgresDumpVersion = observe("pg_dump", "--version")
	p.PostgresRestoreVersion = observe("pg_restore", "--version")
	if dsn == "" {
		dsn = "postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable"
	}
	p.PostgresServerVersion = observe("runuser", "-u", "nakpanel", "--", "psql", "-Atq", dsn, "-c", "SHOW server_version")
	p.MariaDBServerVersion = observe("mariadb", "-NBe", "SELECT VERSION()")
	// MariaDB tools print an unrelated distribution number before 'Distrib'.
	mariaTool := func(name string) string {
		out, e := probe.command(ctx, name, "--version")
		if e != nil {
			return ""
		}
		value := string(out)
		if _, tail, ok := strings.Cut(value, "Distrib "); ok {
			value = tail
		}
		if _, tail, ok := strings.Cut(value, "from "); ok {
			value = tail
		}
		return observedVersion(value)
	}
	p.MariaDBDumpVersion = mariaTool("mariadb-dump")
	p.MariaDBClientVersion = mariaTool("mariadb")
	p.StalwartVersion = observe("/usr/local/bin/stalwart-mail", "--version")
	if p.StalwartVersion == "" {
		p.StalwartVersion = observe("stalwart-mail", "--version")
	}
	// Hosted readiness is supplied by the trusted descriptor/extension/isolated
	// FPM collector at the caller boundary; stray versioned binaries prove nothing.
	// Include active and desired versions: a suspended site or pending runtime is
	// still tenant intent. Query failure makes migration provenance incomplete.
	query := `SELECT DISTINCT version FROM (SELECT php_version AS version FROM sites UNION SELECT desired_php_version FROM sites UNION SELECT php_version FROM php_applications) p WHERE version <> '' ORDER BY version`
	out, e := probe.command(ctx, "runuser", "-u", "nakpanel", "--", "psql", "-Atq", dsn, "-c", query)
	if e == nil {
		p.PHPInventoryComplete = true
		for _, v := range strings.Fields(string(out)) {
			if matched, _ := regexp.MatchString(`^[0-9]+\.[0-9]+$`, v); !matched {
				p.PHPInventoryComplete = false
				break
			}
			p.RequiredPHPVersions = append(p.RequiredPHPVersions, v)
		}
	}
	p.ImageDigests = collectImageDigests(ctx, dsn, probe)
	return p, nil
}

// Only store a digest actually observed in the managed rootless image store.
// Missing/purged image caches are expected on fresh targets and stay unknown.
func collectImageDigests(ctx context.Context, dsn string, probe platformProbe) map[string]string {
	const query = `SELECT COALESCE(json_agg(json_build_object('username',account.username,'subscription_id',app.subscription_id,'image_ref',app.image_ref)),'[]'::json) FROM application_instances app JOIN subscription_system_accounts account ON account.subscription_id=app.subscription_id WHERE app.runtime='oci' AND NOT app.delete_requested AND app.image_ref<>''`
	out, err := probe.command(ctx, "runuser", "-u", "nakpanel", "--", "psql", "-Atq", dsn, "-c", query)
	if err != nil || len(out) > 4<<20 {
		return nil
	}
	var images []struct {
		Username       string `json:"username"`
		SubscriptionID int64  `json:"subscription_id"`
		ImageRef       string `json:"image_ref"`
	}
	if json.Unmarshal(out, &images) != nil || len(images) > 10000 {
		return nil
	}
	digests := map[string]string{}
	imageRefRE := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{1,447}@sha256:[a-f0-9]{64}$`)
	usernameRE := regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)
	digestRE := regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	for _, image := range images {
		if !usernameRE.MatchString(image.Username) || image.SubscriptionID <= 0 || !imageRefRE.MatchString(image.ImageRef) {
			continue
		}
		base := fmt.Sprintf("/var/lib/nakpanel/containers/sub-%d", image.SubscriptionID)
		observed, err := probe.command(ctx, "runuser", "-u", image.Username, "--", "env", "HOME="+base+"/home", "XDG_DATA_HOME="+base+"/data", "XDG_CONFIG_HOME="+base+"/config", fmt.Sprintf("XDG_RUNTIME_DIR=/run/nakpanel-containers/sub-%d", image.SubscriptionID), "podman", "image", "inspect", "--format", "{{.Digest}}", image.ImageRef)
		if err != nil {
			continue
		}
		digest := strings.TrimSpace(string(observed))
		if digestRE.MatchString(digest) {
			digests[image.ImageRef] = digest
		}
	}
	if len(digests) == 0 {
		return nil
	}
	return digests
}
