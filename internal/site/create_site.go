package site

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	usernameRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	labelRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// reservedUsernames are system/service accounts that happen to match
// usernameRE but must never be adopted as tenant accounts: doing so would run
// tenant PHP as a privileged service user or re-own that account's files. The
// regex alone accepts "root", "mysql", "nakpanel", etc., so this denylist is
// the boundary that rejects them.
var reservedUsernames = map[string]struct{}{}

func init() {
	for _, name := range []string{
		"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
		"news", "uucp", "proxy", "backup", "list", "irc", "gnats", "nobody",
		"systemd", "messagebus", "syslog", "sshd", "ntp", "dnsmasq", "tss",
		"postgres", "mysql", "mariadb", "redis", "memcache", "mongodb",
		"bind", "named", "nginx", "apache", "httpd", "www", "wwwdata",
		"stalwart", "roundcube", "adminer", "nakpanel", "admin", "adm",
		"operator", "ftp", "ubuntu", "sudo", "staff", "users", "shadow",
		"disk", "tty", "dialout", "landscape", "lxd", "netdev", "render",
		"scheduler", "postfix", "dovecot", "opendkim", "clamav", "spamd",
	} {
		reservedUsernames[name] = struct{}{}
	}
}

// ValidateUsername enforces the tenant-username regex and rejects reserved
// system/service accounts. Every agent op that materializes a system user
// should gate on this, not on the bare regex.
func ValidateUsername(username string) error {
	if !usernameRE.MatchString(username) {
		return fmt.Errorf("username must match %s", usernameRE.String())
	}
	if _, reserved := reservedUsernames[username]; reserved {
		return fmt.Errorf("username %q is reserved and cannot be used for a tenant account", username)
	}
	return nil
}

// PathWithinDir reports whether cleaned path p is dir itself or a descendant
// of dir. Both are cleaned; it is a lexical containment check for use after a
// caller has already resolved symlinks or is operating on derived paths.
func PathWithinDir(dir, p string) bool {
	dir = strings.TrimRight(filepath.Clean(dir), string(filepath.Separator))
	p = filepath.Clean(p)
	if p == dir {
		return true
	}
	return strings.HasPrefix(p, dir+string(filepath.Separator))
}

// ValidateSFTPRelativeRoot restricts an identity to the subscription root or
// to a server-derived domain start directory. It intentionally rejects
// quoting and option syntax because the value is embedded in authorized_keys.
func ValidateSFTPRelativeRoot(value string) error {
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(value)))
	if clean == "" || clean == "." {
		return nil
	}
	parts := strings.Split(clean, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "domains" || ValidateDomain(parts[1]) != nil {
		return errors.New("SFTP root must select a hosted domain")
	}
	if len(parts) == 3 && parts[2] != "public_html" {
		return errors.New("SFTP root must select the domain root or public_html")
	}
	return nil
}

func NormalizeCreateSiteRequest(req types.CreateSiteReq) types.CreateSiteReq {
	return types.CreateSiteReq{
		SiteID:         req.SiteID,
		SubscriptionID: req.SubscriptionID,
		Username:       strings.ToLower(strings.TrimSpace(req.Username)),
		Domain:         NormalizeDomain(req.Domain),
		PHPVersion:     strings.TrimSpace(req.PHPVersion),
		Docroot:        strings.TrimSpace(req.Docroot),
		SharedAccount:  req.SharedAccount,
		Limits:         req.Limits,
	}
}

func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func ValidateCreateSiteRequest(req types.CreateSiteReq) error {
	if err := ValidateUsername(req.Username); err != nil {
		return err
	}
	if err := ValidateDomain(req.Domain); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(req.PHPVersion) {
		return fmt.Errorf("php version %q is not supported", req.PHPVersion)
	}
	if req.Docroot != "" {
		return errors.New("docroot must be empty because it is derived by the agent")
	}
	if err := validateRuntimeLimits(req.Limits); err != nil {
		return err
	}
	return nil
}

func validateRuntimeLimits(limits types.SiteResourceLimits) error {
	switch limits.PreferredDomain {
	case "", "none", "www", "root", "non-www":
	default:
		return errors.New("preferred domain must be none, www, or root")
	}
	switch limits.SecurityHeaderPreset {
	case "", "off", "balanced", "strict":
	default:
		return errors.New("invalid security header preset")
	}
	if limits.IndexFiles != "" && !regexp.MustCompile(`^[A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)*$`).MatchString(limits.IndexFiles) {
		return errors.New("invalid nginx index file list")
	}
	for _, cidr := range strings.Split(limits.AllowedCIDRs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid access CIDR %q", cidr)
		}
	}
	for _, value := range []string{limits.ErrorDocument404, limits.ErrorDocument50X} {
		if value != "" && (!strings.HasPrefix(value, "/") || strings.Contains(value, "..") ||
			!regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`).MatchString(value)) {
			return fmt.Errorf("invalid nginx error document %q", value)
		}
	}
	return nil
}

func ValidateDomain(domain string) error {
	if len(domain) < 4 || len(domain) > 253 {
		return errors.New("domain length is invalid")
	}
	if strings.Contains(domain, "..") || !strings.Contains(domain, ".") {
		return errors.New("domain must be a fully qualified name")
	}
	for _, label := range strings.Split(domain, ".") {
		if !labelRE.MatchString(label) {
			return fmt.Errorf("domain label %q is invalid", label)
		}
	}
	return nil
}
