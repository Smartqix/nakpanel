package ops

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var acmeChallengeTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type http01ChallengeProbe struct {
	allowPrivate bool
	resolve      func(context.Context, string) ([]net.IPAddr, error)
	dial         func(context.Context, string, string) (net.Conn, error)
}

func IsLocalACMEDirectory(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func (p http01ChallengeProbe) Check(ctx context.Context, domain, path, expected string) error {
	if !usageDomainRE.MatchString(domain) || !strings.HasPrefix(path, http01ChallengePrefix) || !acmeChallengeTokenRE.MatchString(strings.TrimPrefix(path, http01ChallengePrefix)) {
		return errors.New("invalid challenge target")
	}
	resolve := p.resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupIPAddr
	}
	addresses, err := resolve(ctx, domain)
	if err != nil || len(addresses) == 0 || len(addresses) > 8 {
		return errors.New("public DNS is not ready")
	}
	for _, address := range addresses {
		if !allowedChallengeIP(address.IP, p.allowPrivate) {
			return errors.New("DNS points to an unavailable challenge address")
		}
	}
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	for _, address := range addresses {
		pinned := net.JoinHostPort(address.IP.String(), "80")
		transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) { return dial(ctx, network, pinned) }, DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+path, nil)
		if err != nil {
			return errors.New("invalid challenge request")
		}
		response, err := client.Do(request)
		if err != nil {
			transport.CloseIdleConnections()
			return errors.New("HTTP challenge is not reachable on port 80")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 2049))
		response.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil || response.StatusCode != http.StatusOK || len(body) > 2048 || string(body) != expected {
			return errors.New("HTTP challenge does not return the expected proof")
		}
	}
	return nil
}

func allowedChallengeIP(ip net.IP, allowPrivate bool) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return allowPrivate
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, block := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, network, _ := net.ParseCIDR(block)
		if network.Contains(ip) {
			return false
		}
	}
	return true
}
