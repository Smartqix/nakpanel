package ops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// An HTTP-only snapshot can predate concurrent certificate installation. TLS
// removal is not a runtime operation; keep the installed route until explicit
// certificate replacement, including while serving a suspension response.
func retainInstalledTLS(plan SitePlan, cert, key string, redirect bool) (string, string, bool, error) {
	if cert != "" || key != "" {
		return cert, key, redirect, nil
	}
	config, err := os.ReadFile(plan.NginxConfig)
	if errors.Is(err, os.ErrNotExist) {
		return cert, key, redirect, nil
	}
	if err != nil {
		return cert, key, redirect, err
	}
	if !regexp.MustCompile(`(?m)^\s*ssl_certificate(?:_key)?\s`).Match(config) {
		return cert, key, redirect, nil
	}
	_, cert, key, redirect, _, err = existingCertificateRuntime(plan)
	if err == nil && (cert == "" || key == "") {
		err = errors.New("existing TLS directives could not be safely retained")
	}
	return cert, key, redirect, err
}

// Certificate replacement must not switch an active managed release back to public_html.
func existingCertificateRuntime(plan SitePlan) (SitePlan, string, string, bool, bool, error) {
	config, err := os.ReadFile(plan.NginxConfig)
	if errors.Is(err, os.ErrNotExist) {
		return plan, "", "", false, false, nil
	}
	if err != nil {
		return plan, "", "", false, false, err
	}
	if info, err := os.Stat(plan.NginxConfig); err == nil {
		plan.FileMode = info.Mode().Perm()
	}
	roots := regexp.MustCompile(`(?m)^    root ([/A-Za-z0-9._-]+);$`).FindAllSubmatch(config, -1)
	if len(roots) > 0 {
		current := string(roots[0][1])
		for _, root := range roots {
			if string(root[1]) != current {
				return plan, "", "", false, false, errors.New("nginx hosting roots disagree")
			}
		}
		managedRoot := filepath.Join(filepath.Dir(plan.Docroot), ".nakpanel", "releases")
		relative, relErr := filepath.Rel(managedRoot, current)
		managed := relErr == nil && relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
		if !filepath.IsAbs(current) || filepath.Clean(current) != current || (current != plan.Docroot && !managed) {
			return plan, "", "", false, false, errors.New("nginx hosting root is outside this site's managed content")
		}
		plan.Docroot = current
	}
	getPath := func(directive string) (string, error) {
		matches := regexp.MustCompile(`(?m)^    `+directive+` ([/A-Za-z0-9._-]+);$`).FindAllSubmatch(config, -1)
		if len(matches) == 0 {
			return "", nil
		}
		path := string(matches[0][1])
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return "", fmt.Errorf("invalid existing %s path", directive)
		}
		for _, match := range matches {
			if string(match[1]) != path {
				return "", fmt.Errorf("existing %s paths disagree", directive)
			}
		}
		return path, nil
	}
	cert, certErr := getPath("ssl_certificate")
	key, keyErr := getPath("ssl_certificate_key")
	if certErr != nil || keyErr != nil || (cert == "") != (key == "") {
		return plan, "", "", false, false, errors.Join(certErr, keyErr, errors.New("existing nginx TLS paths are invalid"))
	}
	expectedSuspended := renderSuspendedNginxRuntimeVHost(plan, cert, key)
	legacySuspended := strings.Replace(expectedSuspended, renderNginxACMEChallenge(plan)+"\n", "", 1)
	suspended := string(config) == expectedSuspended || string(config) == legacySuspended
	if len(roots) == 0 && !suspended {
		return plan, "", "", false, false, errors.New("existing nginx hosting state is not recognized")
	}
	redirect := cert != "" && strings.Contains(string(config), "return 301 https://$host$request_uri;")
	return plan, cert, key, redirect, suspended, nil
}

func renderCertificateRuntime(plan SitePlan, cert, key string, redirect, suspended bool) string {
	if suspended {
		return renderSuspendedNginxRuntimeVHost(plan, cert, key)
	}
	return RenderNginxRuntimeVHost(plan, cert, key, redirect)
}
