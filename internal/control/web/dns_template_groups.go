package web

import (
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

type dnsTemplateGroup struct {
	Name        string
	Description string
	Rows        []dnsTemplateRow
}

type dnsTemplateRow struct {
	Record    types.DNSTemplateRecord
	Condition string
	Detail    string
	Automatic bool
}

func dnsTemplateGroups(template types.DNSTemplateRevision) []dnsTemplateGroup {
	groups := []dnsTemplateGroup{
		{Name: "Website", Description: "Base website addresses; IPv6 is included only when configured."},
		{Name: "Nameservers", Description: "Authority records and addresses for nameservers inside the zone."},
		{Name: "Local mail", Description: "Service-managed records. External mail routing and local overrides take precedence."},
		{Name: "FTPS", Description: "The address is generated after an enabled FTPS account converges."},
		{Name: "Webmail", Description: "The address follows the configured, active webmail hostname."},
		{Name: "Additional records", Description: "Provider-defined template records."},
	}
	for _, record := range template.Records {
		index := 5
		if record.Type == "NS" {
			index = 1
		} else if record.HostTemplate == "@" && (record.Type == "A" || record.Type == "AAAA") || record.HostTemplate == "www" {
			index = 0
		} else if record.Type == "MX" || strings.Contains(record.HostTemplate, "_domainkey") || record.HostTemplate == "_dmarc" || record.Type == "TXT" && strings.HasPrefix(record.ValueTemplate, "v=spf1") {
			index = 2
		}
		condition, detail := "Always", "All authoritative zones"
		if record.Scope == "root" {
			detail = "Root zones only"
		}
		if record.Scope == "subdomain" {
			detail = "Subdomain zones only"
		}
		if strings.Contains(record.ValueTemplate, "<ipv6.") {
			condition, detail = "When configured", "IPv6 address required; "+strings.ToLower(detail)
		}
		groups[index].Rows = append(groups[index].Rows, dnsTemplateRow{Record: record, Condition: condition, Detail: detail})
		if record.Type == "NS" && record.HostTemplate == "@" && record.Scope != "subdomain" {
			groups[1].Rows = append(groups[1].Rows, dnsTemplateRow{Record: types.DNSTemplateRecord{HostTemplate: record.ValueTemplate, Type: "A", ValueTemplate: "<ip.web>", TTL: 3600}, Condition: "When applicable", Detail: "Root zones only, when this nameserver belongs to the zone", Automatic: true})
		}
	}
	service := func(index int, host, kind, value, condition, detail string) {
		groups[index].Rows = append(groups[index].Rows, dnsTemplateRow{Record: types.DNSTemplateRecord{HostTemplate: host, Type: kind, ValueTemplate: value, TTL: 3600}, Condition: condition, Detail: detail, Automatic: true})
	}
	service(2, "mail", "A", "<mail address>", "When enabled", "Local mail is enabled")
	service(2, "@", "MX", "10 mail.<domain>", "When enabled", "Local delivery only; external MX is preserved")
	service(2, "@", "TXT", "v=spf1 mx ~all", "When enabled", "Existing SPF policy is preserved")
	service(2, "_dmarc", "TXT", "<domain DMARC policy>", "When enabled", "Existing DMARC policy is preserved")
	service(2, "nak1._domainkey", "TXT", "<domain public key>", "Generated per domain", "DKIM public key; never shared across domains")
	service(3, "ftp", "A", "<ip.web>", "When enabled", "Enabled FTPS account is in sync")
	service(4, "<webmail hostname>", "A", "<ip.web>", "When enabled", "Configured webmail host is active")
	result := []dnsTemplateGroup{}
	for _, group := range groups {
		if len(group.Rows) > 0 {
			result = append(result, group)
		}
	}
	return result
}

func dnsTemplateRowCount(template types.DNSTemplateRevision) int {
	count := 0
	for _, group := range dnsTemplateGroups(template) {
		count += len(group.Rows)
	}
	return count
}
