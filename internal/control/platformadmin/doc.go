// Package platformadmin defines the unprivileged, typed control-plane
// contracts used by the Phase 26 mail, database, and application workspaces.
//
// The package deliberately contains no shell commands, SQL fragments, or host
// filesystem paths. Privileged adapters consume validated identifiers and
// resolve them through server-owned registries.
package platformadmin
