package platformadmin

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var (
	safeRefRE        = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)
	safeSlugRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	queueIDRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	cursorRE         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
	envNameRE        = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	dnsLabelRE       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	repositoryPartRE = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)
	digestRE         = regexp.MustCompile(`^[a-f0-9]{64}$`)
	healthPathRE     = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
)

func validateSafeRef(field, value string) error {
	if !safeRefRE.MatchString(value) {
		return fmt.Errorf("%s must be a stable registry identifier", field)
	}
	return nil
}

func validateSlug(field, value string) error {
	if !safeSlugRE.MatchString(value) {
		return fmt.Errorf("%s must contain only lowercase letters, digits, and hyphens", field)
	}
	return nil
}

func validateDisplayName(field, value string, max int) error {
	if value != strings.TrimSpace(value) || value == "" || len(value) > max || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s must be between 1 and %d characters on one line", field, max)
	}
	return nil
}

func validateDomain(field, value string) error {
	if value != strings.ToLower(strings.TrimSpace(value)) || len(value) > 253 || strings.HasSuffix(value, ".") {
		return fmt.Errorf("%s must be a canonical lowercase domain", field)
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%s must be a fully qualified domain", field)
	}
	for _, label := range labels {
		if !dnsLabelRE.MatchString(label) {
			return fmt.Errorf("%s contains an invalid DNS label", field)
		}
	}
	return nil
}

func validateEndpointHost(field, value string) error {
	if value != strings.ToLower(strings.TrimSpace(value)) || value == "" || len(value) > 253 ||
		strings.ContainsAny(value, "/\\@?#[]\x00\r\n\t ") {
		return fmt.Errorf("%s must be a canonical hostname or IP address without a scheme", field)
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is4In6() || addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("%s is not an eligible endpoint address", field)
		}
		return nil
	}
	if value == "localhost" {
		return nil
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !dnsLabelRE.MatchString(label) {
			return fmt.Errorf("%s contains an invalid DNS label", field)
		}
	}
	return nil
}

func isLoopbackHost(value string) bool {
	if value == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.IsLoopback()
}

func validateRegistry(value string) error {
	if value == "localhost" {
		return nil
	}
	host := value
	if index := strings.LastIndexByte(value, ':'); index >= 0 {
		if strings.Count(value, ":") != 1 {
			return errors.New("registry must use a hostname and optional port")
		}
		port, err := strconv.Atoi(value[index+1:])
		if err != nil || port < 1 || port > 65535 {
			return errors.New("registry port is invalid")
		}
		host = value[:index]
	}
	if err := validateEndpointHost("registry", host); err != nil {
		return err
	}
	return nil
}

func validatePinnedImage(value string) (string, error) {
	if value != strings.ToLower(strings.TrimSpace(value)) || len(value) > 512 {
		return "", errors.New("image must be a canonical lowercase reference")
	}
	beforeDigest, digest, ok := strings.Cut(value, "@sha256:")
	if !ok || !digestRE.MatchString(digest) || strings.Contains(beforeDigest, "@") {
		return "", errors.New("image must be pinned by a sha256 digest")
	}
	registry, repository, ok := strings.Cut(beforeDigest, "/")
	if !ok || repository == "" {
		return "", errors.New("image must include an explicit registry")
	}
	if err := validateRegistry(registry); err != nil {
		return "", err
	}
	for _, part := range strings.Split(repository, "/") {
		if !repositoryPartRE.MatchString(part) {
			return "", errors.New("image repository is invalid")
		}
	}
	return registry, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
