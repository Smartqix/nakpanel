package quota

import (
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

// ReadyPHPVersions treats detailed inventory as authoritative when available.
func ReadyPHPVersions(capabilities types.RuntimeCapabilities) []string {
	if len(capabilities.PHPRuntimes) == 0 {
		return append([]string(nil), capabilities.PHPVersions...)
	}
	var ready []string
	for _, runtime := range capabilities.PHPRuntimes {
		if runtime.Ready {
			ready = append(ready, strings.TrimSpace(runtime.Version))
		}
	}
	return ready
}

// ResolveReadyPHPVersion selects only a permitted, ready runtime. Explicit
// requests are never substituted with another version.
func ResolveReadyPHPVersion(limits Limits, requested string, ready []string) (string, error) {
	available := make(map[string]bool, len(ready))
	for _, version := range ready {
		if version = strings.TrimSpace(version); version != "" {
			available[version] = true
		}
	}
	permitted := make(map[string]bool)
	var ordered []string
	for _, version := range strings.Split(limits.PHPAllowlist, ",") {
		if version = strings.TrimSpace(version); version != "" {
			permitted[version] = true
			ordered = append(ordered, version)
		}
	}
	requested = strings.TrimSpace(requested)
	if requested != "" {
		if !permitted[requested] {
			return "", fmt.Errorf("PHP %s is not allowed by the subscription", requested)
		}
		if !available[requested] {
			return "", fmt.Errorf("PHP %s is not ready on the server", requested)
		}
		return requested, nil
	}
	for _, version := range append([]string{"8.4", strings.TrimSpace(limits.DefaultPHPVersion)}, ordered...) {
		if permitted[version] && available[version] {
			return version, nil
		}
	}
	return "", fmt.Errorf("the subscription has no ready permitted PHP runtime")
}
