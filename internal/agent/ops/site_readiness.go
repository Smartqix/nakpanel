package ops

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// InspectSiteReadiness only reads this identity's managed runtime files and
// connects to its isolated FPM socket. It never reloads services or writes data.
func (p *SiteProvisioner) InspectSiteReadiness(ctx context.Context, req types.InspectSiteReadinessReq) (types.SiteReadinessResult, error) {
	result := types.SiteReadinessResult{Ready: true, CheckedAt: time.Now().UTC()}
	if req.SiteID <= 0 || req.SubscriptionID <= 0 || req.Domain != site.NormalizeDomain(req.Domain) {
		return result, errors.New("invalid site readiness identity")
	}
	plan, err := NewSitePlan(types.CreateSiteReq{SiteID: req.SiteID, SubscriptionID: req.SubscriptionID, Username: req.Username, Domain: req.Domain, PHPVersion: req.PHPVersion, SharedAccount: true}, p.paths)
	if err != nil {
		return result, errors.New("site runtime identity could not be validated")
	}
	read := func(path string) (string, bool) {
		f, err := openSiteIdentityRead(path)
		if err != nil {
			return "", false
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || !siteIdentityOwnedByAgent(info) || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
			return "", false
		}
		data, err := io.ReadAll(io.LimitReader(f, 1<<20))
		return string(data), err == nil
	}
	add := func(code string, passed bool) {
		result.Checks = append(result.Checks, types.ReadinessCheck{Code: code, Passed: passed})
		result.Ready = result.Ready && passed
	}
	nginx, nginxOK := read(plan.NginxConfig)
	link, err := os.Readlink(plan.NginxEnabled)
	if err == nil && !filepath.IsAbs(link) {
		link = filepath.Join(filepath.Dir(plan.NginxEnabled), link)
	}
	serverName := regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`).FindAllStringSubmatch(nginx, -1)
	ownName := false
	for _, match := range serverName {
		for _, name := range strings.Fields(match[1]) {
			ownName = ownName || name == req.Domain
		}
	}
	add("managed_vhost", nginxOK && err == nil && filepath.Clean(link) == plan.NginxConfig && ownName && strings.Contains(nginx, "fastcgi_pass unix:"+plan.PHPFPMSocket+";"))
	pool, poolOK := read(plan.PHPFPMConfig)
	value := func(key, want string) bool {
		m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*([^\r\n;]+)\s*$`).FindStringSubmatch(pool)
		return len(m) == 2 && strings.TrimSpace(m[1]) == want
	}
	add("isolated_runtime", poolOK && value("user", req.Username) && value("group", req.Username) && value("listen", plan.PHPFPMSocket))
	var d net.Dialer
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	connection, err := d.DialContext(probeCtx, "unix", plan.PHPFPMSocket)
	if err == nil {
		connection.Close()
	}
	add("runtime_socket", err == nil)
	result.CheckedAt = time.Now().UTC()
	return result, nil
}
