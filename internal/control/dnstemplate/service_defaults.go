package dnstemplate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

func withServiceDefaults(zone zoneSnapshot, plan zonePlan) zonePlan {
	if zone.Services == nil {
		return plan
	}
	removed := map[int64]bool{}
	for _, id := range plan.remove {
		removed[id] = true
	}
	var candidate []types.DNSRecord
	for _, record := range zone.Records {
		if removed[record.ID] {
			continue
		}
		if updated, ok := plan.update[record.ID]; ok {
			record = updated
		}
		candidate = append(candidate, record)
	}
	candidate = append(candidate, plan.add...)
	prefix := zone.expansionForSite(zone.SiteID).subdomain
	desired := provision.DNSServiceDefaults(zone.Domain, zone.Address, prefix, candidate, zone.Services.FTPS, zone.Services.Webmail)
	var wanted []types.DNSRecord
	for _, record := range desired {
		baseHost := strings.TrimSuffix(record.Host, "."+prefix)
		if zone.SuppressedKeys[zone.SiteID][baseHost+"-a"] {
			plan.item.OverrideCount++
			continue
		}
		record.OwnerSiteID = zone.SiteID
		wanted = append(wanted, record)
	}
	if zone.AdoptMatching {
		for i, record := range candidate {
			if record.Origin != "custom" || (record.OwnerSiteID != 0 && record.OwnerSiteID != zone.SiteID) {
				continue
			}
			for _, value := range wanted {
				if recordsEqual(record, value) && canAdoptDNSRecord(candidate, record, value) {
					value.ID = record.ID
					if _, alreadyCounted := plan.adopt[record.ID]; !alreadyCounted {
						plan.item.AdoptedCount++
					}
					plan.adopt[record.ID] = value
					candidate[i] = value
					break
				}
			}
		}
	}
	add, remove, preserved := provision.PlanServiceDNSRecords(candidate, wanted, func(record types.DNSRecord) bool {
		return (record.OwnerSiteID == zone.SiteID || record.OwnerSiteID == 0) && provision.IsEndpointDNSRecord(record)
	})
	plan.add = append(plan.add, add...)
	plan.remove = append(plan.remove, remove...)
	plan.item.AddedCount += len(add)
	plan.item.RemovedCount += len(remove)
	plan.item.OverrideCount += preserved
	return plan
}

func canAdoptDNSRecord(records []types.DNSRecord, match, wanted types.DNSRecord) bool {
	if match.Origin != "custom" {
		return false
	}
	for _, record := range records {
		if record.ID == match.ID || !strings.EqualFold(record.Host, wanted.Host) {
			continue
		}
		if record.Type == "CNAME" || (record.Type == wanted.Type && record.Type != "TXT" && !recordsEqual(record, wanted)) {
			return false
		}
	}
	return true
}

func zonePlanFingerprint(plan zonePlan, zone zoneSnapshot) string {
	services := map[int64]*provision.DNSServiceState{zone.SiteID: zone.Services}
	for id, child := range zone.SubdomainSite {
		services[id] = child.Services
	}
	data, _ := json.Marshal(struct {
		Add             []types.DNSRecord
		Update          map[int64]types.DNSRecord
		Remove          []int64
		Adopt           map[int64]types.DNSRecord
		Settings, Retry bool
		Services        map[int64]*provision.DNSServiceState
	}{plan.add, plan.update, plan.remove, plan.adopt, plan.settingsChanged, plan.retryConvergence, services})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
