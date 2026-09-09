package web

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
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
		// An alert and its failed job describe the same incident; keep the
		// alert, which carries the operator-facing detail.
		if attentionMentions(attention.Items, humanJobKind(kind)+" failed") {
			continue
		}
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

// navBadgeClass returns the whole class name so the CSS build keeps the rule.
func navBadgeClass(severity Severity) string {
	switch severity {
	case SeverityCritical:
		return "np-nav-badge-fail"
	case SeverityWarning:
		return "np-nav-badge-pend"
	default:
		return "np-nav-badge-run"
	}
}

func attentionBadgeTitle(count int) string {
	if count == 1 {
		return "1 item needs attention"
	}
	return fmt.Sprintf("%d items need attention", count)
}

// attentionHealthClass drives the server dot in the rail header. It must not
// claim health while a critical item is open.
func attentionHealthClass(a Attention) string {
	switch {
	case a.Critical > 0:
		return "np-side-health-fail"
	case a.Warning > 0:
		return "np-side-health-pend"
	default:
		return "np-side-health-ok"
	}
}

func attentionHealthLabel(a Attention) string {
	switch {
	case a.Critical > 0:
		return fmt.Sprintf("%d critical", a.Critical)
	case a.Warning > 0:
		return fmt.Sprintf("%d warning", a.Warning)
	default:
		return "All services healthy"
	}
}

// --- capacity ---------------------------------------------------------------

// CapacityItem is one subscription at or approaching a plan limit.
type CapacityItem struct {
	SubscriptionID int64
	Name           string
	PlanName       string
	Label          string
	Used           int
	Limit          int
	ratio          float64
	Severity       Severity
}

// CapacityPressure separates the subscriptions an operator must act on from
// the ones that are merely present. The old panel listed every subscription,
// so rows reading "0/1 sites" outnumbered and hid the ones at their limit.
type CapacityPressure struct {
	Items     []CapacityItem
	Total     int
	Remaining int
	Hidden    int
}

// FooterNote summarises everything the panel is not showing.
func (p CapacityPressure) FooterNote() string {
	switch {
	case p.Hidden > 0 && p.Remaining > 0:
		return fmt.Sprintf("%d more under pressure · %d inside their limits", p.Hidden, p.Remaining)
	case p.Hidden > 0:
		return fmt.Sprintf("%d more subscriptions are under pressure", p.Hidden)
	case p.Remaining > 0:
		return fmt.Sprintf("%d further subscriptions are inside their limits", p.Remaining)
	default:
		return ""
	}
}

// capacityWarnRatio is where a limit starts being worth showing: at 80% an
// operator still has room to act before provisioning starts failing.
const capacityWarnRatio = 0.8

func capacityPressure(subscriptions []types.SubscriptionSummary) CapacityPressure {
	pressure := CapacityPressure{Total: len(subscriptions)}
	for _, subscription := range subscriptions {
		worst := CapacityItem{
			SubscriptionID: subscription.ID,
			Name:           subscription.SubscriptionName,
			PlanName:       subscription.PlanName,
		}
		consider := func(used, limit int, unit string) {
			// A limit of zero means unlimited here, so it can never be strained.
			if limit <= 0 {
				return
			}
			ratio := float64(used) / float64(limit)
			if ratio < capacityWarnRatio || ratio < worst.ratio {
				return
			}
			severity := SeverityWarning
			if used >= limit {
				severity = SeverityCritical
			}
			worst.ratio = ratio
			worst.Used = used
			worst.Limit = limit
			worst.Severity = severity
			worst.Label = fmt.Sprintf("%d/%d %s", used, limit, unit)
		}
		consider(subscription.SitesUsed, subscription.MaxSites, "sites")
		consider(subscription.DatabasesUsed, subscription.MaxDatabases, "databases")
		consider(subscription.BackupsUsed, subscription.MaxBackups, "backups")

		if worst.Severity == SeverityNone {
			continue
		}
		pressure.Items = append(pressure.Items, worst)
	}
	sort.SliceStable(pressure.Items, func(i, j int) bool {
		if pressure.Items[i].Severity != pressure.Items[j].Severity {
			return pressure.Items[i].Severity > pressure.Items[j].Severity
		}
		return pressure.Items[i].ratio > pressure.Items[j].ratio
	})
	pressure.Remaining = pressure.Total - len(pressure.Items)
	if len(pressure.Items) > capacityDisplayLimit {
		pressure.Hidden = len(pressure.Items) - capacityDisplayLimit
		pressure.Items = pressure.Items[:capacityDisplayLimit]
	}
	return pressure
}

// recentSites caps the home list so it stops being a second copy of /sites.
func recentSites(sites []dashboard.Site) []dashboard.Site {
	const homeSiteLimit = 6
	if len(sites) <= homeSiteLimit {
		return sites
	}
	return sites[:homeSiteLimit]
}

func attentionPanelClass(a Attention) string {
	if a.Critical > 0 {
		return "np-attention-fail"
	}
	return "np-attention-pend"
}

func attentionCountLabel(count int, word string) string {
	return fmt.Sprintf("%d %s", count, word)
}

func severityDotClass(s Severity) string {
	switch s {
	case SeverityCritical:
		return "np-attention-dot-fail"
	case SeverityWarning:
		return "np-attention-dot-pend"
	default:
		return "np-attention-dot-run"
	}
}

func severityTextClass(s Severity) string {
	switch s {
	case SeverityCritical:
		return "np-usage-value-fail"
	case SeverityWarning:
		return "np-usage-value-pend"
	default:
		return "np-usage-value-ok"
	}
}

// attentionMentions reports whether an equivalent item is already listed, so
// the same failure is not counted from two sources.
func attentionMentions(items []AttentionItem, title string) bool {
	needle := normaliseIncident(title)
	for _, item := range items {
		if normaliseIncident(item.Title) == needle {
			return true
		}
	}
	return false
}

// normaliseIncident reduces a title to its distinctive words so
// "System reconciliation failed" and "Reconcile system failed" match.
func normaliseIncident(title string) string {
	replacer := strings.NewReplacer("reconciliation", "reconcile", "_", " ")
	words := strings.Fields(strings.ToLower(replacer.Replace(title)))
	sort.Strings(words)
	return strings.Join(words, " ")
}

// capacityDisplayLimit keeps the Home panel scannable; the rest are counted.
const capacityDisplayLimit = 5

// --- list-report helpers -----------------------------------------------------

// healthFilterValue is the row attribute the client-side filter matches on.
func healthFilterValue(h SiteHealth) string {
	if h.NeedsAttention() {
		return "attention"
	}
	return "healthy"
}

func severityPillClass(s Severity) string {
	switch s {
	case SeverityCritical:
		return "np-pill-fail"
	case SeverityWarning:
		return "np-pill-pend"
	case SeverityInfo:
		return "np-pill-run"
	default:
		return "np-pill-susp"
	}
}

// siteStatusOptions lists the statuses actually present, so the filter never
// offers a value that matches nothing.
func siteStatusOptions(sites []dashboard.Site) []string {
	seen := map[string]bool{}
	var out []string
	for _, site := range sites {
		status := strings.TrimSpace(site.Status)
		if status == "" || seen[status] {
			continue
		}
		seen[status] = true
		out = append(out, status)
	}
	sort.Strings(out)
	return out
}

func siteSubscriptionName(subscriptions []types.SubscriptionSummary, site dashboard.Site) string {
	for _, subscription := range subscriptions {
		if subscription.ID == site.SubscriptionID {
			return subscription.SubscriptionName
		}
	}
	return "—"
}

func siteSubscriptionPlan(subscriptions []types.SubscriptionSummary, site dashboard.Site) string {
	for _, subscription := range subscriptions {
		if subscription.ID == site.SubscriptionID {
			return subscription.PlanName
		}
	}
	return ""
}

// TLSSummary describes certificate condition for a list cell.
type TLSSummary struct {
	Label  string
	Detail string
	Class  string
}

func tlsSummary(site dashboard.Site) TLSSummary {
	now := time.Now()
	if strings.TrimSpace(site.TLSLastError) != "" {
		return TLSSummary{Label: "Failed", Detail: "Issuance error", Class: "np-pill-fail"}
	}
	if !site.TLSExpiresAt.Valid {
		return TLSSummary{Label: "None", Detail: "Not issued", Class: "np-pill-pend"}
	}
	remaining := site.TLSExpiresAt.Time.Sub(now)
	switch {
	case remaining <= 0:
		return TLSSummary{Label: "Expired", Class: "np-pill-fail"}
	case remaining <= certificateExpiryWindow:
		summary := TLSSummary{Label: fmt.Sprintf("%d days", int(remaining.Hours()/24)), Class: "np-pill-pend"}
		if !site.TLSAutoRenew {
			summary.Detail = "auto-renew off"
		}
		return summary
	default:
		return TLSSummary{Label: fmt.Sprintf("Valid %dd", int(remaining.Hours()/24)), Class: "np-pill-ok"}
	}
}

func healthPanelClass(h SiteHealth) string {
	if h.Severity == SeverityCritical {
		return "np-attention-fail"
	}
	return "np-attention-pend"
}

// groupedAlerts collapses identical alerts into one row carrying an occurrence
// count and orders them by severity. Before this, fourteen copies of the same
// warning pushed the single critical row below the fold.
func groupedAlerts(alerts []types.UsageAlert) []AttentionItem {
	type bucket struct {
		item  AttentionItem
		first time.Time
		last  time.Time
	}
	buckets := map[string]*bucket{}
	var order []string

	for _, alert := range alerts {
		if !alert.ResolvedAt.IsZero() {
			continue
		}
		key := alert.Kind + "|" + alert.Title
		existing, ok := buckets[key]
		if !ok {
			buckets[key] = &bucket{
				item: AttentionItem{
					Severity: alertSeverity(alert.Severity),
					Title:    strings.TrimSpace(alert.Title),
					Detail:   strings.TrimSpace(alert.Body),
					Count:    1,
				},
				first: alert.CreatedAt,
				last:  alert.CreatedAt,
			}
			order = append(order, key)
			continue
		}
		existing.item.Count++
		if severity := alertSeverity(alert.Severity); severity > existing.item.Severity {
			existing.item.Severity = severity
		}
		if alert.CreatedAt.Before(existing.first) {
			existing.first = alert.CreatedAt
		}
		if alert.CreatedAt.After(existing.last) {
			existing.last = alert.CreatedAt
		}
	}

	items := make([]AttentionItem, 0, len(order))
	for _, key := range order {
		grouped := buckets[key]
		when := grouped.last.Format("15:04")
		if grouped.item.Count > 1 && grouped.first.Format("15:04") != when {
			when = grouped.first.Format("15:04") + "–" + when
		}
		if grouped.item.Detail != "" {
			grouped.item.Detail += " · "
		}
		grouped.item.Detail += when
		items = append(items, grouped.item)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Severity > items[j].Severity })
	return items
}

// capacityAllClearCopy phrases the no-pressure case for both an estate with
// subscriptions and one without, rather than reporting "All 0 subscriptions".
func capacityAllClearCopy(p CapacityPressure) string {
	switch p.Total {
	case 0:
		return "No subscriptions yet."
	case 1:
		return "The only subscription is inside its limits."
	default:
		return fmt.Sprintf("All %d subscriptions are inside their limits.", p.Total)
	}
}
