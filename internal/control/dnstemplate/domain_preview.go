package dnstemplate

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

func (m *Manager) PreviewDomains(ctx context.Context) ([]types.DNSPreviewDomain, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id,domain FROM sites ORDER BY domain,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	domains := []types.DNSPreviewDomain{}
	for rows.Next() {
		var domain types.DNSPreviewDomain
		if err := rows.Scan(&domain.SiteID, &domain.Domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

// This preview shares the synchronization planner but never persists a run or enqueues a job.
func (m *Manager) DomainPreview(ctx context.Context, siteID int64) (types.DNSDomainPreview, error) {
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return types.DNSDomainPreview{}, err
	}
	defer tx.Rollback()
	var domain string
	if err = tx.QueryRowContext(ctx, `SELECT domain FROM sites WHERE id=$1`, siteID).Scan(&domain); err != nil {
		return types.DNSDomainPreview{}, err
	}
	template, err := m.activeTemplate(ctx, tx)
	if err != nil {
		return types.DNSDomainPreview{}, err
	}
	zone, err := m.zoneForSiteTx(ctx, tx, siteID, false)
	if errors.Is(err, sql.ErrNoRows) {
		return types.DNSDomainPreview{SiteID: siteID, Domain: domain, TemplateRevision: template.Revision, Records: []types.DNSPreviewRecord{}, Warnings: []string{"No local DNS zone is configured. External DNS is not changed by this template."}}, nil
	}
	if err != nil {
		return types.DNSDomainPreview{}, err
	}
	return buildDomainPreview(template, zone, siteID, domain), nil
}

func buildDomainPreview(template types.DNSTemplateRevision, zone zoneSnapshot, siteID int64, domain string) types.DNSDomainPreview {
	preview := types.DNSDomainPreview{SiteID: siteID, Domain: domain, ZoneDomain: zone.Domain, Mode: zone.Mode, TemplateRevision: template.Revision, Records: []types.DNSPreviewRecord{}}
	plan := zonePlan{}
	if zone.Mode == "primary" {
		if siteID == zone.AuthoritativeSiteID {
			plan = compareWholeZone(template, zone)
		} else {
			zone.SiteID = siteID
			zone.Services = zone.SubdomainSite[siteID].Services
			zone.AdoptionCompleted = zone.SubdomainSite[siteID].AdoptionCompleted
			plan = compareZone(template, zone)
		}
	} else {
		preview.Warnings = append(preview.Warnings, "This zone is not primary. Only current records are shown; the template will not change it.")
	}
	if plan.item.ConflictCount > 0 {
		preview.Warnings = append(preview.Warnings, "Some template records conflict with this zone. Review synchronization impact before applying.")
	}
	removed := map[int64]bool{}
	for _, id := range plan.remove {
		removed[id] = true
	}
	visible := func(record types.DNSRecord) bool {
		if siteID == zone.AuthoritativeSiteID {
			return true
		}
		prefix := strings.TrimSuffix(domain, "."+zone.Domain)
		return record.Host == prefix || strings.HasSuffix(record.Host, "."+prefix)
	}
	for _, record := range zone.Records {
		if !visible(record) {
			continue
		}
		action := "Unchanged"
		if record.Origin == "custom" || record.LocallyModified {
			action = "Preserved"
		}
		if updated, ok := plan.update[record.ID]; ok {
			record, action = updated, "Update"
		}
		if removed[record.ID] {
			action = "Remove"
		}
		preview.Records = append(preview.Records, types.DNSPreviewRecord{Record: record, Action: action})
	}
	for _, record := range plan.add {
		if visible(record) {
			preview.Records = append(preview.Records, types.DNSPreviewRecord{Record: record, Action: "Add"})
		}
	}
	sort.SliceStable(preview.Records, func(i, j int) bool {
		a, b := preview.Records[i].Record, preview.Records[j].Record
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Value < b.Value
	})
	return preview
}
