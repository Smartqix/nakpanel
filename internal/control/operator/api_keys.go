package operator

import (
	"context"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/provisioningapi"
)

func (s *Service) CreateAPIKey(ctx context.Context, name string, cidrs []string, rateLimit int, expiresAt time.Time) (provisioningapi.APIKey, string, error) {
	key, raw, err := provisioningapi.NewKeyStore(s.db).Create(ctx, provisioningapi.APIKeyCreate{
		Name: name, Scope: provisioningapi.ScopeProvisioning, IPAllowlist: cidrs,
		RateLimitPerMinute: rateLimit, ExpiresAt: expiresAt,
	})
	if err == nil {
		err = s.audit(ctx, "api_key.created", "api_key", key.ID, map[string]any{"name": key.Name, "prefix": key.Prefix, "scope": key.Scope, "cidrs": key.IPAllowlist, "rate_limit": key.RateLimitPerMinute})
	}
	return key, raw, err
}

func (s *Service) ListAPIKeys(ctx context.Context) ([]provisioningapi.APIKey, error) {
	return provisioningapi.NewKeyStore(s.db).List(ctx)
}

func (s *Service) RevokeAPIKey(ctx context.Context, prefix string) error {
	if err := provisioningapi.NewKeyStore(s.db).Revoke(ctx, prefix); err != nil {
		return err
	}
	return s.audit(ctx, "api_key.revoked", "api_key", 0, map[string]any{"prefix": prefix})
}
