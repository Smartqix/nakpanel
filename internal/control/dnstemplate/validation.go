package dnstemplate

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	templatePlaceholderRE = regexp.MustCompile(`<(?:domain|subdomain|hostname|ip\.[a-z0-9_-]+|ipv6\.[a-z0-9_-]+)>`)
	dnsOwnerRE            = regexp.MustCompile(`^(@|[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_-])?)$`)
	templateRecordKeyRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)
	caaValueRE            = regexp.MustCompile(`^([0-9]{1,3})\s+(issue|issuewild|iodef)\s+"([^"\r\n]+)"$`)
	dsValueRE             = regexp.MustCompile(`^([0-9]{1,5})\s+([0-9]{1,3})\s+([0-9]{1,3})\s+([A-Fa-f0-9]+)$`)
)

type expansionContext struct {
	domain    string
	subdomain string
	hostname  string
	ipv4      string
	ipv6      string
}

func validateTemplateRecord(record types.DNSTemplateRecord) (types.DNSTemplateRecord, error) {
	record.StableKey = strings.TrimSpace(record.StableKey)
	record.Scope = strings.ToLower(strings.TrimSpace(record.Scope))
	record.HostTemplate = strings.ToLower(strings.TrimSpace(record.HostTemplate))
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.ValueTemplate = strings.TrimSpace(record.ValueTemplate)
	if record.Scope == "" {
		record.Scope = "all"
	}
	if record.TTL == 0 {
		record.TTL = 3600
	}
	if !templateRecordKeyRE.MatchString(record.StableKey) {
		return record, errors.New("template record key must contain 1 to 96 letters, numbers, dots, underscores, or hyphens")
	}
	if record.Scope != "all" && record.Scope != "root" && record.Scope != "subdomain" {
		return record, errors.New("template record scope must be all, root, or subdomain")
	}
	for _, value := range []string{record.HostTemplate, record.ValueTemplate} {
		if value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return record, errors.New("DNS template fields cannot be blank or contain control characters")
		}
	}
	if err := validatePlaceholders(record.HostTemplate); err != nil {
		return record, fmt.Errorf("host template: %w", err)
	}
	if err := validatePlaceholders(record.ValueTemplate); err != nil {
		return record, fmt.Errorf("value template: %w", err)
	}
	contexts := []expansionContext{{
		domain: "example.test", hostname: "panel.example.test",
		ipv4: "192.0.2.10", ipv6: "2001:db8::10",
	}}
	if record.Scope == "subdomain" {
		contexts = contexts[:0]
	}
	if record.Scope == "all" || record.Scope == "subdomain" {
		contexts = append(contexts, expansionContext{
			domain: "example.test", subdomain: "shop", hostname: "panel.example.test",
			ipv4: "192.0.2.10", ipv6: "2001:db8::10",
		})
	}
	for _, sample := range contexts {
		expanded, omit, err := expandTemplateRecord(record, sample)
		if err != nil {
			return record, err
		}
		if omit {
			return record, errors.New("template record is not valid for its selected scope")
		}
		if _, err := normalizeRecord(sample.domain, expanded); err != nil {
			return record, err
		}
	}
	return record, nil
}

func validateTemplateRevision(template types.DNSTemplateRevision) error {
	normalized := make([]types.DNSTemplateRecord, len(template.Records))
	seenKeys := make(map[string]struct{}, len(template.Records))
	for i, record := range template.Records {
		value, err := validateTemplateRecord(record)
		if err != nil {
			return fmt.Errorf("template record %q: %w", record.StableKey, err)
		}
		if _, exists := seenKeys[value.StableKey]; exists {
			return fmt.Errorf("template record key %q is duplicated", value.StableKey)
		}
		seenKeys[value.StableKey] = struct{}{}
		normalized[i] = value
	}

	contexts := []expansionContext{
		{
			domain: "example.test", hostname: "panel.example.test",
			ipv4: "192.0.2.10", ipv6: "2001:db8::10",
		},
		{
			domain: "example.test", subdomain: "shop", hostname: "panel.example.test",
			ipv4: "192.0.2.10", ipv6: "2001:db8::10",
		},
	}
	var parentZoneRecords []types.DNSRecord
	for _, sample := range contexts {
		var records []types.DNSRecord
		for _, record := range normalized {
			expanded, omit, err := expandTemplateRecord(record, sample)
			if err != nil {
				return fmt.Errorf("expand template record %q: %w", record.StableKey, err)
			}
			if omit {
				continue
			}
			records = append(records, expanded)
		}
		if sample.subdomain == "" {
			records = appendMissingSystemSampleRecords(records, sample)
		}
		if err := validateDNSRecordSet(records); err != nil {
			return fmt.Errorf("template record set is invalid: %w", err)
		}
		parentZoneRecords = append(parentZoneRecords, records...)
	}
	if err := validateDNSRecordSet(parentZoneRecords); err != nil {
		return fmt.Errorf("template conflicts when a subdomain uses its parent zone: %w", err)
	}
	return nil
}

func appendMissingSystemSampleRecords(records []types.DNSRecord, sample expansionContext) []types.DNSRecord {
	system := []types.DNSRecord{
		{Host: "@", Type: "NS", Value: "ns1." + sample.domain, TTL: 3600},
		{Host: "ns1", Type: "A", Value: sample.ipv4, TTL: 3600},
		{Host: "webmail", Type: "A", Value: sample.ipv4, TTL: 3600},
	}
	for _, wanted := range system {
		satisfied := false
		for _, existing := range records {
			if recordsSameRData(existing, wanted) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			records = append(records, wanted)
		}
	}
	return records
}

func validatePlaceholders(value string) error {
	stripped := templatePlaceholderRE.ReplaceAllString(value, "")
	if strings.ContainsAny(stripped, "<>") {
		return errors.New("contains an unsupported placeholder")
	}
	return nil
}

func expandTemplateRecord(record types.DNSTemplateRecord, values expansionContext) (types.DNSRecord, bool, error) {
	if record.Scope == "root" && values.subdomain != "" {
		return types.DNSRecord{}, true, nil
	}
	if record.Scope == "subdomain" && values.subdomain == "" {
		return types.DNSRecord{}, true, nil
	}
	host := expandPlaceholders(record.HostTemplate, values)
	value := expandPlaceholders(record.ValueTemplate, values)
	if values.subdomain != "" {
		switch {
		case host == "@":
			host = values.subdomain
		case host != values.subdomain && !strings.HasSuffix(host, "."+values.subdomain):
			host += "." + values.subdomain
		}
	}
	if strings.Contains(record.ValueTemplate, "<ipv6.") && values.ipv6 == "" {
		return types.DNSRecord{}, true, nil
	}
	expanded := types.DNSRecord{
		Host: host, Type: record.Type, Value: value, Priority: record.Priority,
		Weight: record.Weight, Port: record.Port, TTL: record.TTL,
		Origin: "template", TemplateRecordKey: record.StableKey,
	}
	normalized, err := normalizeRecord(values.domain, expanded)
	return normalized, false, err
}

func expandPlaceholders(value string, values expansionContext) string {
	replacements := map[string]string{
		"<domain>": values.domain, "<subdomain>": values.subdomain, "<hostname>": values.hostname,
	}
	for old, replacement := range replacements {
		value = strings.ReplaceAll(value, old, replacement)
	}
	value = regexp.MustCompile(`<ip\.[a-z0-9_-]+>`).ReplaceAllString(value, values.ipv4)
	value = regexp.MustCompile(`<ipv6\.[a-z0-9_-]+>`).ReplaceAllString(value, values.ipv6)
	return value
}

func normalizeRecord(domain string, record types.DNSRecord) (types.DNSRecord, error) {
	record.Host = strings.ToLower(strings.TrimSpace(record.Host))
	if record.Host == "" {
		record.Host = "@"
	}
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Value = strings.TrimSpace(record.Value)
	if record.TTL == 0 {
		record.TTL = 3600
	}
	if record.TTL < 60 || record.TTL > 86400 {
		return record, errors.New("DNS TTL must be between 60 and 86400 seconds")
	}
	if len(record.Host) > 253 || !dnsOwnerRE.MatchString(record.Host) ||
		!validDNSOwnerLabels(record.Host) || strings.ContainsAny(record.Host, "\r\n\x00 \t") {
		return record, errors.New("DNS host is invalid")
	}
	if strings.ContainsAny(record.Value, "\r\n\x00") {
		return record, errors.New("DNS value contains control characters")
	}
	if record.Host != "@" && !strings.Contains(record.Host, "_") {
		if err := site.ValidateDomain(record.Host + "." + domain); err != nil {
			return record, fmt.Errorf("invalid DNS host: %w", err)
		}
	}
	switch record.Type {
	case "A":
		if ip := net.ParseIP(record.Value); ip == nil || ip.To4() == nil {
			return record, errors.New("A record requires an IPv4 address")
		}
		clearRecordFields(&record)
	case "AAAA":
		if ip := net.ParseIP(record.Value); ip == nil || ip.To4() != nil {
			return record, errors.New("AAAA record requires an IPv6 address")
		}
		clearRecordFields(&record)
	case "CNAME":
		if record.Host == "@" {
			return record, errors.New("a CNAME record cannot be created at the zone apex")
		}
		if err := validateTarget(record.Value); err != nil {
			return record, fmt.Errorf("CNAME: %w", err)
		}
		record.Value = canonicalTarget(record.Value)
		clearRecordFields(&record)
	case "MX", "NS":
		if err := validateTarget(record.Value); err != nil {
			return record, fmt.Errorf("%s: %w", record.Type, err)
		}
		record.Value = canonicalTarget(record.Value)
		if record.Type == "MX" {
			if record.Priority < 0 || record.Priority > 65535 {
				return record, errors.New("MX priority is invalid")
			}
			record.Weight, record.Port = 0, 0
		} else {
			clearRecordFields(&record)
		}
	case "TXT":
		if record.Value == "" || len(record.Value) > 4096 {
			return record, errors.New("TXT value must contain 1 to 4096 characters")
		}
		clearRecordFields(&record)
	case "SRV":
		if !validSRVOwner(record.Host) {
			return record, errors.New("SRV host must use the _service._protocol form")
		}
		if record.Priority < 0 || record.Priority > 65535 || record.Weight < 0 || record.Weight > 65535 || record.Port < 1 || record.Port > 65535 {
			return record, errors.New("SRV priority, weight, or port is invalid")
		}
		if err := validateTarget(record.Value); err != nil {
			return record, fmt.Errorf("SRV: %w", err)
		}
		record.Value = canonicalTarget(record.Value)
	case "CAA":
		match := caaValueRE.FindStringSubmatch(record.Value)
		if len(match) != 4 {
			return record, errors.New(`CAA value must be: flags tag "value"`)
		}
		flags, _ := strconv.Atoi(match[1])
		if flags > 255 {
			return record, errors.New("CAA flags must be between 0 and 255")
		}
		clearRecordFields(&record)
	case "DS":
		match := dsValueRE.FindStringSubmatch(record.Value)
		if len(match) != 5 {
			return record, errors.New("DS value must contain key-tag algorithm digest-type digest")
		}
		keyTag, _ := strconv.Atoi(match[1])
		algorithm, _ := strconv.Atoi(match[2])
		if keyTag > 65535 || algorithm < 1 || algorithm > 255 {
			return record, errors.New("DS key tag or algorithm is invalid")
		}
		digestType, _ := strconv.Atoi(match[3])
		wantLength := map[int]int{1: 40, 2: 64, 4: 96}[digestType]
		if wantLength == 0 || len(match[4]) != wantLength {
			return record, errors.New("DS digest length does not match its digest type")
		}
		clearRecordFields(&record)
	default:
		return record, fmt.Errorf("unsupported DNS record type %q", record.Type)
	}
	return record, nil
}

func clearRecordFields(record *types.DNSRecord) {
	record.Priority, record.Weight, record.Port = 0, 0, 0
}

func validateTarget(value string) error {
	target := canonicalTarget(value)
	if target == "" {
		return errors.New("target cannot be blank")
	}
	return site.ValidateDomain(target)
}

func canonicalTarget(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func validSRVOwner(host string) bool {
	labels := strings.Split(strings.ToLower(strings.TrimSpace(host)), ".")
	return len(labels) >= 2 && len(labels[0]) > 1 && len(labels[1]) > 1 &&
		strings.HasPrefix(labels[0], "_") && strings.HasPrefix(labels[1], "_")
}

func validDNSOwnerLabels(host string) bool {
	if host == "@" {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		first, last := label[0], label[len(label)-1]
		if first == '-' || last == '-' {
			return false
		}
	}
	return true
}

func validateDNSRecordSet(records []types.DNSRecord) error {
	type ownerState struct {
		total  int
		cnames int
	}
	owners := make(map[string]ownerState)
	identities := make(map[string]struct{}, len(records))
	for _, record := range records {
		host := strings.ToLower(strings.TrimSpace(record.Host))
		recordType := strings.ToUpper(strings.TrimSpace(record.Type))
		state := owners[host]
		state.total++
		if recordType == "CNAME" {
			state.cnames++
		}
		owners[host] = state

		value := strings.TrimSpace(record.Value)
		switch recordType {
		case "CNAME", "MX", "NS", "SRV":
			value = canonicalTarget(value)
		}
		identity := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d\x00%d",
			host, recordType, value, record.Priority, record.Weight, record.Port)
		if _, exists := identities[identity]; exists {
			return fmt.Errorf("duplicate %s record at %q", recordType, host)
		}
		identities[identity] = struct{}{}
	}
	for host, state := range owners {
		if state.cnames > 0 && state.total != 1 {
			return fmt.Errorf("CNAME record at %q cannot coexist with another record", host)
		}
	}
	return nil
}

func validateSOA(settings types.DNSSOASettings) error {
	if err := validateTemplateDomain(settings.PrimaryNameserver); err != nil {
		return fmt.Errorf("primary nameserver: %w", err)
	}
	if err := validateTemplateDomain(settings.ResponsibleMailbox); err != nil {
		return fmt.Errorf("responsible mailbox: %w", err)
	}
	if settings.SerialFormat != "unix" && settings.SerialFormat != "date-counter" {
		return errors.New("SOA serial format is invalid")
	}
	checks := []struct {
		name       string
		value, min int
		max        int
	}{
		{"default TTL", settings.DefaultTTL, 60, 86400},
		{"refresh", settings.RefreshSeconds, 300, 86400},
		{"retry", settings.RetrySeconds, 60, 86400},
		{"expire", settings.ExpireSeconds, 86400, 2419200},
		{"minimum TTL", settings.MinimumTTL, 60, 86400},
	}
	for _, check := range checks {
		if check.value < check.min || check.value > check.max {
			return fmt.Errorf("%s must be between %d and %d", check.name, check.min, check.max)
		}
	}
	return nil
}

func validateTemplateDomain(value string) error {
	if err := validatePlaceholders(value); err != nil {
		return err
	}
	sample := expandPlaceholders(strings.TrimSpace(value), expansionContext{
		domain: "example.test", subdomain: "shop", hostname: "panel.example.test",
		ipv4: "192.0.2.10", ipv6: "2001:db8::10",
	})
	return site.ValidateDomain(strings.TrimSuffix(sample, "."))
}

func validateCIDRs(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid transfer CIDR %q", raw)
		}
		value := network.String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}
