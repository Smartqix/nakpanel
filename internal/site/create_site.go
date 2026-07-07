package site

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	usernameRE = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	labelRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func NormalizeCreateSiteRequest(req types.CreateSiteReq) types.CreateSiteReq {
	return types.CreateSiteReq{
		Username:   strings.ToLower(strings.TrimSpace(req.Username)),
		Domain:     NormalizeDomain(req.Domain),
		PHPVersion: strings.TrimSpace(req.PHPVersion),
		Docroot:    strings.TrimSpace(req.Docroot),
		Limits:     req.Limits,
	}
}

func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func ValidateCreateSiteRequest(req types.CreateSiteReq) error {
	if !usernameRE.MatchString(req.Username) {
		return fmt.Errorf("username must match %s", usernameRE.String())
	}
	if err := ValidateDomain(req.Domain); err != nil {
		return err
	}
	switch req.PHPVersion {
	case "8.3", "8.2":
	default:
		return fmt.Errorf("php version %q is not supported", req.PHPVersion)
	}
	if req.Docroot != "" {
		return errors.New("docroot must be empty because it is derived by the agent")
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
