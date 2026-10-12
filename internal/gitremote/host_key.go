package gitremote

import "net/url"

// Pinned from https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
// Host-key rotation requires a reviewed update, never trust-on-first-use.
func TrustedHostKey(remote string) string {
	normalized, err := Normalize(remote)
	if err != nil {
		return ""
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Scheme != "ssh" || u.Hostname() != "github.com" || (u.Port() != "" && u.Port() != "22") {
		return ""
	}
	return "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
}
