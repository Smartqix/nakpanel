package dnstemplate

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

func withProviderDefaults(current types.DNSTemplateRevision, input types.DNSProviderDefaults) (types.DNSTemplateRevision, error) {
	primary := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input.PrimaryNameserver), "."))
	secondary := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input.SecondaryNameserver), "."))
	if site.ValidateDomain(primary) != nil || site.ValidateDomain(secondary) != nil || primary == secondary {
		return current, errors.New("enter two different fully qualified nameserver hostnames")
	}
	records := make([]types.DNSTemplateRecord, 0, len(current.Records)+2)
	for _, record := range current.Records {
		if record.Type == "NS" && record.HostTemplate == "@" && record.Scope != "subdomain" {
			continue
		}
		if record.StableKey == "ns1-a" && record.HostTemplate == "ns1" && record.ValueTemplate == "<ip.dns>" {
			continue
		}
		records = append(records, record)
	}
	current.Records = append(records,
		types.DNSTemplateRecord{StableKey: "primary-ns", Scope: "root", HostTemplate: "@", Type: "NS", ValueTemplate: primary, TTL: 3600},
		types.DNSTemplateRecord{StableKey: "secondary-ns", Scope: "root", HostTemplate: "@", Type: "NS", ValueTemplate: secondary, TTL: 3600})
	current.SOA.PrimaryNameserver = primary
	return current, validateTemplateRevision(current)
}

func (m *Manager) PreviewProviderDefaults(ctx context.Context, input types.DNSProviderDefaults) (types.DNSTemplateRevision, error) {
	current, err := m.activeTemplate(ctx, m.db)
	if err != nil {
		return current, err
	}
	return withProviderDefaults(current, input)
}

func (m *Manager) SaveProviderDefaults(ctx context.Context, actorID, expectedRevision int64, input types.DNSProviderDefaults) (int64, error) {
	return m.createRevision(ctx, actorID, expectedRevision, func(current *types.DNSTemplateRevision) error {
		next, err := withProviderDefaults(*current, input)
		if err == nil {
			*current = next
		}
		return err
	})
}

func providerDefaults(current types.DNSTemplateRevision) types.DNSProviderDefaults {
	result := types.DNSProviderDefaults{PrimaryNameserver: current.SOA.PrimaryNameserver}
	for _, record := range current.Records {
		if record.Type == "NS" && record.Scope != "subdomain" && record.HostTemplate == "@" && record.ValueTemplate != result.PrimaryNameserver {
			result.SecondaryNameserver = record.ValueTemplate
			break
		}
	}
	return result
}

func providerWarnings(ctx context.Context, input types.DNSProviderDefaults) []string {
	if strings.Contains(input.PrimaryNameserver, "<") || input.SecondaryNameserver == "" {
		return []string{"Provider nameservers are not configured. Domain-relative defaults are still in use."}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	primary, err1 := net.DefaultResolver.LookupIP(ctx, "ip", input.PrimaryNameserver)
	secondary, err2 := net.DefaultResolver.LookupIP(ctx, "ip", input.SecondaryNameserver)
	if err1 != nil || err2 != nil {
		return []string{"Nameserver addresses could not be verified. Check delegation and glue records at the registrar before applying."}
	}
	if nameserversShareAddress(primary, secondary) {
		return []string{"Both nameservers share an IP address. This is a single-server setup, not redundant DNS."}
	}
	return nil
}

func nameserversShareAddress(primary, secondary []net.IP) bool {
	for _, a := range primary {
		for _, b := range secondary {
			if a.Equal(b) {
				return true
			}
		}
	}
	return false
}
