package operator

import (
	"context"
	"fmt"
	"regexp"
)

var providerPHPVersionRE = regexp.MustCompile(`^8\.[345]$`)

// RuntimeProviderInUse conservatively checks the version-only schema. Until a
// qualified migration adds provider identity, ANY reference to this version
// protects its sole registered provider, including desired and retained state.
// An error never authorizes dpkg removal. Call while tenant mutations are paused.
func (s *Service) RuntimeProviderInUse(ctx context.Context, provider, version, internalVersion string) (bool, error) {
	if provider != "nakpanel" || !providerPHPVersionRE.MatchString(version) || !providerPHPVersionRE.MatchString(internalVersion) {
		return false, fmt.Errorf("unknown provider/version or internal runtime state")
	}
	if version == internalVersion {
		return true, nil
	}
	if s.db == nil {
		return false, fmt.Errorf("runtime usage database unavailable")
	}
	var used bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM sites WHERE php_version=$1 OR desired_php_version=$1
 UNION ALL SELECT 1 FROM php_applications WHERE php_version=$1
 UNION ALL SELECT 1 FROM site_removal_operations WHERE state<>'completed' AND
   (jsonb_path_exists(snapshot,'$.**.php_version ? (@ == $version)',jsonb_build_object('version',$1::text))
    OR jsonb_path_exists(snapshot,'$.**.desired_php_version ? (@ == $version)',jsonb_build_object('version',$1::text)))
 UNION ALL SELECT 1 FROM server_backups WHERE status IN ('active','delete_failed') AND
   (manifest#>'{platform,required_php_versions}' @> jsonb_build_array($1::text)
    OR COALESCE((manifest#>>'{platform,php_inventory_complete}')::boolean,false)=false)
 )`, version).Scan(&used)
	if err != nil {
		return false, fmt.Errorf("check runtime provider references: %w", err)
	}
	return used, nil
}
