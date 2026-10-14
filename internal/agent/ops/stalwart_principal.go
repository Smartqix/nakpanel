package ops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var removalMailboxLocalRE = regexp.MustCompile("^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
var removalStalwartVersionRE = regexp.MustCompile(`(?:^|[[:space:]])v?0\.11\.8(?:$|[[:space:]])`)

func (p *MailProvisioner) removeMailboxPrincipal(ctx context.Context, name string) error {
	local, domain, ok := strings.Cut(name, "@")
	if !ok || !removalMailboxLocalRE.MatchString(local) || !validMailQueueDomain(domain) {
		return errors.New("invalid approved mailbox identity")
	}
	version, err := p.runner.Run(ctx, "stalwart-mail", "--version")
	if err != nil || !removalStalwartVersionRE.Match(version) {
		return errors.New("mailbox cleanup requires the verified Stalwart 0.11.8 API")
	}
	status, body, err := p.removalPrincipalRequest(ctx, http.MethodGet, name)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status != http.StatusOK {
		return errors.New("mailbox principal cannot be inspected")
	}
	var principal struct {
		Data struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &principal) != nil || principal.Data.Name != name || principal.Data.Type != "individual" {
		return errors.New("mailbox principal identity cannot be verified")
	}
	status, _, err = p.removalPrincipalRequest(ctx, http.MethodDelete, name)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return errors.New("approved mailbox principal could not be removed")
	}
	status, _, err = p.removalPrincipalRequest(ctx, http.MethodGet, name)
	if err != nil {
		return err
	}
	if status != http.StatusNotFound {
		return errors.New("mailbox principal removal has not converged")
	}
	return nil
}

func (p *MailProvisioner) removalPrincipalRequest(ctx context.Context, method, name string) (int, []byte, error) {
	endpoint, err := url.Parse(p.managementURL)
	if err != nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" {
		return 0, nil, errors.New("private mail management endpoint is invalid")
	}
	ip := net.ParseIP(endpoint.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return 0, nil, errors.New("mail principal cleanup is restricted to loopback")
	}
	secret, err := os.ReadFile(p.adminSecretPath)
	if err != nil || len(secret) > 4096 {
		return 0, nil, errors.New("private mail management credential is unavailable")
	}
	defer clear(secret)
	req, err := http.NewRequestWithContext(ctx, method, p.managementURL+"/api/principal/"+url.PathEscape(name), nil)
	if err != nil {
		return 0, nil, errors.New("mail principal request could not be prepared")
	}
	req.SetBasicAuth("admin", strings.TrimSpace(string(secret)))
	client := *p.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, errors.New("private mail management request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return 0, nil, errors.New("mail principal response exceeded its safe limit")
	}
	return response.StatusCode, body, nil
}
