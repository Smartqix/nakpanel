// Package version carries the product version stamped into the binaries at
// build time. The authoritative value lives in the repository-root VERSION
// file and is injected with -ldflags; "dev" means an unstamped build.
package version

// Version is the bare product version (for example "29.0.0"). Only this value
// participates in upgrade/downgrade comparisons.
var Version = "dev"

// Commit is the short git commit the binaries were built from. Informational
// only; never compared.
var Commit = "unknown"

// Number returns the bare comparable version.
func Number() string {
	return Version
}

// String returns the human-readable version including the commit,
// for example "29.0.0+abc1234".
func String() string {
	if Commit == "" || Commit == "unknown" {
		return Version
	}
	return Version + "+" + Commit
}
