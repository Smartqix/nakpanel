// Package gitremote validates the narrow set of Git remotes supported by the panel.
package gitremote

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var sshUser = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// Normalize accepts HTTPS and SSH URLs, including conventional SCP-style remotes.
// Passwords, URL options, local transports and ambiguous host syntax are rejected.
func Normalize(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n\t ") {
		return "", errors.New("invalid Git remote")
	}
	if !strings.Contains(raw, "://") {
		at := strings.IndexByte(raw, '@')
		colon := strings.IndexByte(raw, ':')
		if at < 1 || colon <= at+1 {
			return "", errors.New("Git remote must use SSH or HTTPS")
		}
		raw = "ssh://" + raw[:colon] + "/" + raw[colon+1:]
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "ssh" && u.Scheme != "https") || u.Opaque != "" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return "", errors.New("Git remote must be an SSH or HTTPS repository URL")
	}
	if u.User != nil {
		_, password := u.User.Password()
		if password || u.Scheme != "ssh" || !sshUser.MatchString(u.User.Username()) {
			return "", errors.New("Git remote passwords are not allowed")
		}
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasPrefix(host, "-") || strings.ContainsAny(host, "%\\") {
		return "", errors.New("invalid Git remote hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !PublicIP(ip) {
			return "", errors.New("Git remote must use a public address")
		}
	} else {
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(label) {
				return "", errors.New("invalid Git remote hostname")
			}
		}
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid Git remote port")
		}
	}
	if strings.ContainsAny(u.Path, "\x00\r\n\\") {
		return "", errors.New("invalid Git repository path")
	}
	return u.String(), nil
}

// PublicIP excludes local, private, documentation and transition networks.
func PublicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/32", "2002::/16", "64:ff9b::/96"} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return false
		}
	}
	return true
}
