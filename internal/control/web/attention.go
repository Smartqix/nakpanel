package web

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

// Severity ranks how urgently an operator must look at something. The panel
// renders one vocabulary everywhere: a raw machine state never reaches the UI.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityInfo
	SeverityWarning
	SeverityCritical
)

func (s Severity) Label() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return ""
	}
}

// Class maps a severity onto the shipped status tokens so pills, dots and
// borders never invent their own colours.
func (s Severity) Class() string {
	switch s {
	case SeverityCritical:
		return "fail"
	case SeverityWarning:
		return "pend"
	case SeverityInfo:
		return "run"
	default:
		return "ok"
	}
}

// certificateExpiryWindow is how far ahead an expiring certificate starts
// asking for attention. Two weeks leaves room for a failed renewal to be
// noticed and retried before the site starts serving a broken chain.
const certificateExpiryWindow = 14 * 24 * time.Hour

// SiteIssue is one concrete problem with a hosted domain, phrased for an
// operator and carrying the action that resolves it.
type SiteIssue struct {
	Severity Severity
	Title    string
	Detail   string
	Action   string
	ActionTo string
}

// SiteHealth summarises every problem the panel already knows about a site.
// The fields it reads are loaded for the dashboard anyway, so building this
// costs no extra queries.
type SiteHealth struct {
	Severity Severity
	Summary  string
	Issues   []SiteIssue
}

// NeedsAttention reports whether the site should be flagged in lists and in
// the navigation badge.
func (h SiteHealth) NeedsAttention() bool { return h.Severity >= SeverityWarning }

// siteHealth correlates the error fields that are otherwise scattered across
// six different tabs (convergence, TLS, provisioning) into one verdict.
func siteHealth(site dashboard.Site, now time.Time) SiteHealth {
	health := SiteHealth{}
	add := func(issue SiteIssue) {
		health.Issues = append(health.Issues, issue)
		if issue.Severity > health.Severity {
			health.Severity = issue.Severity
			health.Summary = issue.Title
		}
	}

	sitePath := fmt.Sprintf("/sites/%d", site.ID)

	if strings.TrimSpace(site.LastError) != "" {
		add(SiteIssue{
			Severity: SeverityCritical,
			Title:    "Provisioning failed",
			Detail:   strings.TrimSpace(site.LastError),
			Action:   "Open website",
			ActionTo: sitePath,
		})
	}
	if strings.TrimSpace(site.SettingsError) != "" || site.SettingsStatus == "failed" {
		detail := strings.TrimSpace(site.SettingsError)
		if detail == "" {
			detail = "The applied configuration does not match the desired state."
		}
		add(SiteIssue{
			Severity: SeverityCritical,
			Title:    "Configuration has not converged",
			Detail:   detail,
			Action:   "Reconcile",
			ActionTo: sitePath + "?tab=hosting",
		})
	}
	if strings.TrimSpace(site.TLSLastError) != "" {
		add(SiteIssue{
			Severity: SeverityCritical,
			Title:    "Certificate could not be issued",
			Detail:   strings.TrimSpace(site.TLSLastError),
			Action:   "Open SSL/TLS",
			ActionTo: sitePath + "?tab=ssl",
		})
	}

	switch {
	case site.TLSExpiresAt.Valid && site.TLSExpiresAt.Time.Before(now):
		add(SiteIssue{
			Severity: SeverityCritical,
			Title:    "Certificate has expired",
			Detail:   "Visitors see a browser warning until a new certificate is issued.",
			Action:   "Issue certificate",
			ActionTo: sitePath + "?tab=ssl",
		})
	case site.TLSExpiresAt.Valid && site.TLSExpiresAt.Time.Sub(now) <= certificateExpiryWindow:
		days := int(site.TLSExpiresAt.Time.Sub(now).Hours() / 24)
		detail := fmt.Sprintf("Expires in %d days.", days)
		if days <= 1 {
			detail = "Expires within a day."
		}
		if !site.TLSAutoRenew {
			detail += " Automatic renewal is off."
		}
		add(SiteIssue{
			Severity: SeverityWarning,
			Title:    "Certificate expiring",
			Detail:   detail,
			Action:   "Review certificate",
			ActionTo: sitePath + "?tab=ssl",
		})
	}

	sort.SliceStable(health.Issues, func(i, j int) bool {
		return health.Issues[i].Severity > health.Issues[j].Severity
	})
	return health
}

// SiteHealthMap indexes health by site id so a list can render a health column
// without recomputing per row.
type SiteHealthMap map[int64]SiteHealth

func buildSiteHealth(sites []dashboard.Site, now time.Time) SiteHealthMap {
	out := make(SiteHealthMap, len(sites))
	for _, site := range sites {
		out[site.ID] = siteHealth(site, now)
	}
	return out
}

func (m SiteHealthMap) attentionCount() int {
	count := 0
	for _, health := range m {
		if health.NeedsAttention() {
			count++
		}
	}
	return count
}

// AttentionItem is one row of the "needs attention" surface. Duplicates are
// collapsed into a single item carrying its occurrence count, so fourteen
// identical warnings can never bury one critical failure.
type AttentionItem struct {
	Severity    Severity
	Title       string
	Detail      string
	Count       int
	Action      string
	ActionTo    string
	Secondary   string
	SecondaryTo string
}

// Occurrences renders the grouped-count suffix, empty when there is only one.
func (i AttentionItem) Occurrences() string {
	if i.Count <= 1 {
		return ""
	}
	return fmt.Sprintf("%d occurrences", i.Count)
}

// Attention is the panel-wide answer to "what needs me right now".
type Attention struct {
	Items    []AttentionItem
	Critical int
	Warning  int
}

func (a Attention) Total() int { return a.Critical + a.Warning }

// NavBadge is the severity badge for the Activity nav item: an action count,
// never an inventory count.
func (a Attention) NavBadge() string { return formatBadgeCount(a.Total()) }

func (a Attention) BadgeSeverity() Severity {
	if a.Critical > 0 {
		return SeverityCritical
	}
	if a.Warning > 0 {
		return SeverityWarning
	}
	return SeverityNone
}

func alertSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "error", "fatal":
		return SeverityCritical
	case "warning", "warn":
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// buildAttention groups unresolved alerts by kind, folds in failed jobs and
// expiring certificates, and orders the result by severity so the most urgent
// row is always first.
func buildAttention(data dashboard.Data, health SiteHealthMap, now time.Time) Attention {
	var attention Attention

	type group struct {
		item  AttentionItem
		first time.Time
		last  time.Time
	}
	groups := map[string]*group{}
	order := []string{}

	for _, alert := range data.UsageAlerts {
		if !alert.ResolvedAt.IsZero() {
			continue
		}
		severity := alertSeverity(alert.Severity)
		if severity < SeverityWarning {
			continue
		}
		key := alert.Kind + "|" + alert.Title
		existing, ok := groups[key]
		if !ok {
			groups[key] = &group{
				item: AttentionItem{
					Severity: severity,
					Title:    strings.TrimSpace(alert.Title),
					Detail:   strings.TrimSpace(alert.Body),
					Count:    1,
					Action:   "Open activity",
					ActionTo: "/activity",
				},
				first: alert.CreatedAt,
				last:  alert.CreatedAt,
			}
			order = append(order, key)
			continue
		}
		existing.item.Count++
		if existing.item.Severity < severity {
			existing.item.Severity = severity
		}
		if alert.CreatedAt.Before(existing.first) {
			existing.first = alert.CreatedAt
		}
		if alert.CreatedAt.After(existing.last) {
			existing.last = alert.CreatedAt
		}
	}

	for _, key := range order {
		grouped := groups[key]
		if grouped.item.Count > 1 && !grouped.first.IsZero() && !grouped.last.IsZero() {
			window := grouped.first.Format("15:04")
			if grouped.last.Format("15:04") != window {
				window = window + "–" + grouped.last.Format("15:04")
			}
			if grouped.item.Detail != "" {
				grouped.item.Detail += " · "
			}
			grouped.item.Detail += "grouped " + window
		}
		attention.Items = append(attention.Items, grouped.item)
	}

	// Failed provisioning work is the most actionable signal the panel has.
	failedJobs := map[string]int{}
	jobOrder := []string{}
	for _, job := range data.Jobs {
		if job.State != "discarded" && job.State != "failed" {
			continue
		}
		if _, ok := failedJobs[job.Kind]; !ok {
			jobOrder = append(jobOrder, job.Kind)
		}
		failedJobs[job.Kind]++
	}
	for _, kind := range jobOrder {
		attention.Items = append(attention.Items, AttentionItem{
			Severity: SeverityCritical,
			Title:    humanJobKind(kind) + " failed",
			Detail:   "Provisioning work did not complete.",
			Count:    failedJobs[kind],
			Action:   "Open activity",
			ActionTo: "/activity",
		})
	}

	// Expiring certificates roll up into a single row naming the domains.
	var expiring []string
	for _, site := range data.Sites {
		state := health[site.ID]
		for _, issue := range state.Issues {
			if issue.Title == "Certificate expiring" || issue.Title == "Certificate has expired" {
				expiring = append(expiring, site.Domain)
				break
			}
		}
	}
	if len(expiring) > 0 {
		detail := strings.Join(expiring, " · ")
		if len(expiring) > 3 {
			detail = strings.Join(expiring[:3], " · ") + fmt.Sprintf(" and %d more", len(expiring)-3)
		}
		title := "1 certificate expires soon"
		if len(expiring) > 1 {
			title = fmt.Sprintf("%d certificates expire soon", len(expiring))
		}
		attention.Items = append(attention.Items, AttentionItem{
			Severity: SeverityWarning,
			Title:    title,
			Detail:   detail,
			Count:    1,
			Action:   "Review",
			ActionTo: "/certificates",
		})
	}

	sort.SliceStable(attention.Items, func(i, j int) bool {
		return attention.Items[i].Severity > attention.Items[j].Severity
	})
	for _, item := range attention.Items {
		switch item.Severity {
		case SeverityCritical:
			attention.Critical++
		case SeverityWarning:
			attention.Warning++
		}
	}
	return attention
}

// humanJobKind turns a queue identifier into something an operator reads,
// so `create_site` never reaches the interface unchanged.
func humanJobKind(kind string) string {
	cleaned := strings.ReplaceAll(strings.TrimSpace(kind), "_", " ")
	if cleaned == "" {
		return "Background job"
	}
	return strings.ToUpper(cleaned[:1]) + cleaned[1:]
}

// --- template-facing helpers -------------------------------------------------
// These recompute from slices the dashboard has already loaded; the panel does
// a full data load per navigation anyway, so the cost is noise.

// siteHealthOf is the per-row entry point: the caller already holds the site,
// so a list renders its health column without a lookup.
func siteHealthOf(site dashboard.Site) SiteHealth { return siteHealth(site, time.Now()) }

// workspaceAttention answers "what needs me right now" for the whole panel.
func workspaceAttention(data dashboard.Data) Attention {
	now := time.Now()
	return buildAttention(data, buildSiteHealth(data.Sites, now), now)
}

// sitesNeedingAttention is the Domains nav badge: a count of sites with an
// open problem, never the size of the estate.
func sitesNeedingAttention(sites []dashboard.Site) int {
	return buildSiteHealth(sites, time.Now()).attentionCount()
}

// attentionBadge renders a nav badge only when there is something to act on.
func attentionBadge(count int) string { return formatBadgeCount(count) }

// badgeClass selects the severity token for a nav badge.
func badgeClass(severity Severity) string {
	if severity == SeverityNone {
		return ""
	}
	return " np-nav-badge-" + severity.Class()
}
