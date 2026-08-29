package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dnstemplate"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Server) registerDNSTemplateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /tools-settings/dns/template/settings", s.handleDNSTemplateSettings)
	mux.HandleFunc("POST /tools-settings/dns/template/records", s.handleDNSTemplateRecord)
	mux.HandleFunc("POST /tools-settings/dns/template/records/{recordID}/delete", s.handleDeleteDNSTemplateRecord)
	mux.HandleFunc("POST /tools-settings/dns/template/reset", s.handleResetDNSTemplate)
	mux.HandleFunc("POST /tools-settings/dns/sync/preview", s.handlePreviewDNSSynchronization)
	mux.HandleFunc("POST /tools-settings/dns/sync/{runID}/apply", s.handleApplyDNSSynchronization)
	mux.HandleFunc("POST /tools-settings/dns/sync/{runID}/retry", s.handleRetryDNSSynchronization)
	mux.HandleFunc("POST /sites/{id}/dns-template/preview", s.handlePreviewSiteDNSTemplate)
	mux.HandleFunc("POST /sites/{id}/dns-template/{runID}/apply", s.handleApplySiteDNSTemplate)
	mux.HandleFunc("POST /sites/{id}/dns-template/reset", s.handleResetSiteDNS)
	mux.HandleFunc("POST /sites/{id}/dns-records/{recordID}/restore", s.handleRestoreDNSRecord)
	mux.HandleFunc("POST /sites/{id}/dns-zone/mode", s.handleDNSZoneMode)
	mux.HandleFunc("POST /sites/{id}/dns-zone/soa", s.handleDNSZoneSOA)
	mux.HandleFunc("POST /sites/{id}/dns-zone/subdomain-mode", s.handleDNSSubdomainMode)
}

func (s *Server) handleRetryDNSSynchronization(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDNSAdmin(w, r, false)
	if !ok {
		return
	}
	runID, err := dnsPathInt64(r, "runID")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	run, err := s.dnsTemplates.RetryPreview(r.Context(), user.ID, runID)
	if err != nil {
		writeDNSError(w, r, "Could not re-preview DNS synchronization", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.synchronization_retried", "dns_sync_run", run.ID, map[string]any{"previous_run_id": runID})
	http.Redirect(w, r, "/tools-settings/dns?run="+strconv.FormatInt(run.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleDNSTemplateSettings(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDNSAdmin(w, r, true)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS template settings", http.StatusBadRequest)
		return
	}
	input := types.DNSTemplateSettingsInput{
		ExpectedRevision: parseFormInt64Default(r, "expected_revision", 0),
		ZoneStatus:       strings.TrimSpace(r.Form.Get("zone_status")),
		SubdomainPolicy:  strings.TrimSpace(r.Form.Get("subdomain_policy")),
		TransferCIDRs:    splitDNSList(r.Form.Get("transfer_cidrs")),
		SOA:              parseSOAForm(r),
	}
	revision, err := s.dnsTemplates.SaveSettings(r.Context(), user.ID, input)
	if err != nil {
		writeDNSError(w, r, "Could not save DNS template settings", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.template_settings_changed", "dns_template_revision", revision, nil)
	http.Redirect(w, r, "/tools-settings/dns?notice=dns-template-saved", http.StatusSeeOther)
}

func (s *Server) handleDNSTemplateRecord(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDNSAdmin(w, r, false)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS template record", http.StatusBadRequest)
		return
	}
	recordID := parseFormInt64Default(r, "record_id", 0)
	record := types.DNSTemplateRecord{
		StableKey: strings.TrimSpace(r.Form.Get("stable_key")), Scope: strings.TrimSpace(r.Form.Get("scope")),
		HostTemplate: strings.TrimSpace(r.Form.Get("host_template")), Type: strings.TrimSpace(r.Form.Get("record_type")),
		ValueTemplate: strings.TrimSpace(r.Form.Get("value_template")), Priority: parseFormIntDefault(r, "priority", 0),
		Weight: parseFormIntDefault(r, "weight", 0), Port: parseFormIntDefault(r, "port", 0),
		TTL: parseFormIntDefault(r, "ttl", 3600),
	}
	revision, err := s.dnsTemplates.UpsertTemplateRecord(
		r.Context(), user.ID, recordID, parseFormInt64Default(r, "expected_revision", 0), record)
	if err != nil {
		writeDNSError(w, r, "Could not save DNS template record", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.template_record_saved", "dns_template_revision", revision, map[string]any{"type": record.Type})
	http.Redirect(w, r, "/tools-settings/dns?notice=dns-template-record-saved", http.StatusSeeOther)
}

func (s *Server) handleDeleteDNSTemplateRecord(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDNSAdmin(w, r, false)
	if !ok {
		return
	}
	recordID, err := dnsPathInt64(r, "recordID")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS template request", http.StatusBadRequest)
		return
	}
	revision, err := s.dnsTemplates.DeleteTemplateRecord(
		r.Context(), user.ID, recordID, parseFormInt64Default(r, "expected_revision", 0))
	if err != nil {
		writeDNSError(w, r, "Could not delete DNS template record", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.template_record_deleted", "dns_template_revision", revision, map[string]any{"record_id": recordID})
	http.Redirect(w, r, "/tools-settings/dns?notice=dns-template-record-deleted", http.StatusSeeOther)
}

func (s *Server) handleResetDNSTemplate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDNSAdmin(w, r, true)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil || r.Form.Get("confirmation") != "RESET DNS TEMPLATE" {
		http.Error(w, `Type "RESET DNS TEMPLATE" to confirm`, http.StatusBadRequest)
		return
	}
	revision, err := s.dnsTemplates.ResetTemplate(
		r.Context(), user.ID, parseFormInt64Default(r, "expected_revision", 0))
	if err != nil {
		writeDNSError(w, r, "Could not reset DNS template", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.template_reset", "dns_template_revision", revision, nil)
	http.Redirect(w, r, "/tools-settings/dns?notice=dns-template-reset", http.StatusSeeOther)
}

func (s *Server) handlePreviewDNSSynchronization(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDNSAdmin(w, r, false)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS synchronization request", http.StatusBadRequest)
		return
	}
	run, err := s.dnsTemplates.Preview(r.Context(), user.ID, strings.TrimSpace(r.Form.Get("scope")), 0)
	if err != nil {
		writeDNSError(w, r, "Could not preview DNS synchronization", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.synchronization_previewed", "dns_sync_run", run.ID, map[string]any{"scope": run.Scope})
	http.Redirect(w, r, "/tools-settings/dns?run="+strconv.FormatInt(run.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleApplyDNSSynchronization(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDNSAdmin(w, r, true)
	if !ok {
		return
	}
	runID, err := dnsPathInt64(r, "runID")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS synchronization request", http.StatusBadRequest)
		return
	}
	if err := s.dnsTemplates.ApplyPreview(r.Context(), user.ID, runID, r.Form.Get("preview_token"), r.Form.Get("confirmation")); err != nil {
		writeDNSError(w, r, "Could not apply DNS synchronization", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.synchronization_started", "dns_sync_run", runID, nil)
	http.Redirect(w, r, "/tools-settings/dns?run="+strconv.FormatInt(runID, 10)+"&notice=dns-sync-started", http.StatusSeeOther)
}

func (s *Server) handlePreviewSiteDNSTemplate(w http.ResponseWriter, r *http.Request) {
	user, siteID, ok := s.requireSiteDNS(w, r)
	if !ok {
		return
	}
	run, err := s.dnsTemplates.ApplyZone(r.Context(), user.ID, siteID)
	if err != nil {
		writeDNSError(w, r, "Could not preview the zone template", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.zone_template_previewed", "site", siteID, map[string]any{"run_id": run.ID})
	http.Redirect(w, r, siteDNSPath(siteID)+"&dns_run="+strconv.FormatInt(run.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleApplySiteDNSTemplate(w http.ResponseWriter, r *http.Request) {
	user, siteID, ok := s.requireSiteDNS(w, r)
	if !ok {
		return
	}
	runID, err := dnsPathInt64(r, "runID")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS synchronization request", http.StatusBadRequest)
		return
	}
	manager, ok := s.dnsTemplates.(interface {
		ApplySitePreview(context.Context, int64, int64, int64, string, string) error
	})
	if !ok {
		http.Error(w, "Site DNS synchronization is unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := manager.ApplySitePreview(r.Context(), user.ID, siteID, runID, r.Form.Get("preview_token"), r.Form.Get("confirmation")); err != nil {
		writeDNSError(w, r, "Could not apply the zone template", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.zone_template_started", "site", siteID, map[string]any{"run_id": runID})
	http.Redirect(w, r, siteDNSPath(siteID)+"&notice=dns-template-started", http.StatusSeeOther)
}

func (s *Server) handleResetSiteDNS(w http.ResponseWriter, r *http.Request) {
	user, siteID, ok := s.requireSiteDNS(w, r)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		http.Error(w, "Recent authentication is required", http.StatusPreconditionRequired)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS reset request", http.StatusBadRequest)
		return
	}
	if err := s.dnsTemplates.ResetZone(r.Context(), user.ID, siteID, r.Form.Get("confirmation")); err != nil {
		writeDNSError(w, r, "Could not reset this DNS zone", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.zone_reset", "site", siteID, nil)
	http.Redirect(w, r, siteDNSPath(siteID)+"&notice=dns-zone-reset", http.StatusSeeOther)
}

func (s *Server) handleRestoreDNSRecord(w http.ResponseWriter, r *http.Request) {
	user, siteID, ok := s.requireSiteDNS(w, r)
	if !ok {
		return
	}
	recordID, err := dnsPathInt64(r, "recordID")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.dnsTemplates.RestoreRecord(r.Context(), siteID, recordID); err != nil {
		writeDNSError(w, r, "Could not restore the inherited DNS record", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.record_restored", "site", siteID, map[string]any{"record_id": recordID})
	http.Redirect(w, r, siteDNSPath(siteID)+"&notice=dns-record-restored", http.StatusSeeOther)
}

func (s *Server) handleDNSZoneMode(w http.ResponseWriter, r *http.Request) {
	user, siteID, ok := s.requireSiteDNS(w, r)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		http.Error(w, "Recent authentication is required", http.StatusPreconditionRequired)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid DNS zone mode", http.StatusBadRequest)
		return
	}
	input := types.DNSZoneModeInput{
		Mode: strings.TrimSpace(r.Form.Get("mode")), UpstreamPrimaries: splitDNSList(r.Form.Get("upstream_primaries")),
		ExpectedRevision: parseFormInt64Default(r, "expected_revision", 0),
	}
	if err := s.dnsTemplates.SetZoneMode(r.Context(), siteID, input); err != nil {
		writeDNSError(w, r, "Could not change DNS zone mode", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.zone_mode_changed", "site", siteID, map[string]any{"mode": input.Mode})
	http.Redirect(w, r, siteDNSPath(siteID)+"&notice=dns-zone-mode-saved", http.StatusSeeOther)
}

func (s *Server) handleDNSZoneSOA(w http.ResponseWriter, r *http.Request) {
	user, siteID, ok := s.requireSiteDNS(w, r)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		http.Error(w, "Recent authentication is required", http.StatusPreconditionRequired)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid SOA settings", http.StatusBadRequest)
		return
	}
	var settings *types.DNSSOASettings
	var transferCIDRs *[]string
	if !parseFormBool(r, "inherit_soa") {
		value := parseSOAForm(r)
		settings = &value
		values := splitDNSList(r.Form.Get("transfer_cidrs"))
		transferCIDRs = &values
	}
	if err := s.dnsTemplates.SetZoneSOA(
		r.Context(), siteID, parseFormInt64Default(r, "expected_revision", 0),
		settings, transferCIDRs); err != nil {
		writeDNSError(w, r, "Could not save SOA settings", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.zone_soa_changed", "site", siteID, map[string]any{"inherited": settings == nil})
	http.Redirect(w, r, siteDNSPath(siteID)+"&notice=dns-soa-saved", http.StatusSeeOther)
}

func (s *Server) handleDNSSubdomainMode(w http.ResponseWriter, r *http.Request) {
	user, siteID, ok := s.requireSiteDNS(w, r)
	if !ok {
		return
	}
	if user.Role != auth.RoleAdmin {
		http.Error(w, "Only administrators can create or remove authoritative subdomain zones", http.StatusForbidden)
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		http.Error(w, "Recent authentication is required", http.StatusPreconditionRequired)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid subdomain zone mode", http.StatusBadRequest)
		return
	}
	mode := strings.TrimSpace(r.Form.Get("subdomain_mode"))
	if err := s.dnsTemplates.SetSubdomainZoneMode(
		r.Context(), siteID, parseFormInt64Default(r, "expected_revision", 0), mode); err != nil {
		writeDNSError(w, r, "Could not change subdomain DNS behavior", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "dns.subdomain_mode_changed", "site", siteID, map[string]any{"mode": mode})
	http.Redirect(w, r, siteDNSPath(siteID)+"&notice=dns-subdomain-mode-saved", http.StatusSeeOther)
}

func (s *Server) requireDNSAdmin(w http.ResponseWriter, r *http.Request, recent bool) (auth.SessionUser, bool) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return auth.SessionUser{}, false
	}
	if s.dnsTemplates == nil {
		http.Error(w, "DNS template management is not configured", http.StatusServiceUnavailable)
		return auth.SessionUser{}, false
	}
	if recent && !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		http.Error(w, "Recent authentication is required", http.StatusPreconditionRequired)
		return auth.SessionUser{}, false
	}
	return user, true
}

func (s *Server) requireSiteDNS(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, bool) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return auth.SessionUser{}, 0, false
	}
	if s.dnsTemplates == nil {
		http.Error(w, "DNS template management is not configured", http.StatusServiceUnavailable)
		return auth.SessionUser{}, 0, false
	}
	siteID, err := dnsPathInt64(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return auth.SessionUser{}, 0, false
	}
	data, err := s.loadDashboard(r.Context(), user)
	if err != nil {
		http.Error(w, "Could not authorize DNS zone", http.StatusInternalServerError)
		return auth.SessionUser{}, 0, false
	}
	for _, site := range data.Sites {
		if site.ID != siteID {
			continue
		}
		for _, subscription := range data.Subscriptions {
			if subscription.ID == site.SubscriptionID && subscription.AllowDNS {
				return user, siteID, true
			}
		}
		http.Error(w, "DNS is not enabled for this subscription", http.StatusForbidden)
		return auth.SessionUser{}, 0, false
	}
	http.NotFound(w, r)
	return auth.SessionUser{}, 0, false
}

func parseSOAForm(r *http.Request) types.DNSSOASettings {
	return types.DNSSOASettings{
		PrimaryNameserver:  strings.TrimSpace(r.Form.Get("primary_nameserver")),
		ResponsibleMailbox: strings.TrimSpace(r.Form.Get("responsible_mailbox")),
		SerialFormat:       strings.TrimSpace(r.Form.Get("serial_format")),
		DefaultTTL:         parseFormIntDefault(r, "default_ttl", 3600),
		RefreshSeconds:     parseFormIntDefault(r, "refresh_seconds", 3600),
		RetrySeconds:       parseFormIntDefault(r, "retry_seconds", 900),
		ExpireSeconds:      parseFormIntDefault(r, "expire_seconds", 604800),
		MinimumTTL:         parseFormIntDefault(r, "minimum_ttl", 300),
	}
}

func splitDNSList(raw string) []string {
	return normalizeFormList(strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}))
}

func dnsPathInt64(r *http.Request, name string) (int64, error) {
	value, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("invalid identifier")
	}
	return value, nil
}

func writeDNSError(w http.ResponseWriter, r *http.Request, prefix string, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, dnstemplate.ErrStalePreview) {
		status = http.StatusConflict
	}
	http.Error(w, prefix+": "+err.Error(), status)
}

func siteDNSPath(siteID int64) string {
	return "/sites/" + strconv.FormatInt(siteID, 10) + "?tab=dns"
}
