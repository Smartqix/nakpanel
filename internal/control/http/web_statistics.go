package panelhttp

import (
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/control/webstatistics"
	"net/http"
	"strconv"
)

func (s *Server) loadWebStatistics(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, id int64, view *web.WorkspaceView) bool {
	if s.webStatistics == nil {
		http.Error(w, "Web statistics unavailable", http.StatusServiceUnavailable)
		return false
	}
	v, err := s.webStatistics.Workspace(r.Context(), actor, id)
	if err != nil {
		s.statisticsError(w, r, err)
		return false
	}
	switch r.URL.Query().Get("statistics_error") {
	case "429":
		v.LastError = "Refresh already pending or requested within the last 15 minutes."
	case "409":
		v.LastError = "The subscription does not permit this operation."
	case "503":
		v.LastError = "Web statistics are temporarily unavailable."
	}
	view.WebStatistics = &v
	return true
}
func (s *Server) statisticsRequest(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, bool) {
	actor, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return actor, 0, false
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return actor, 0, false
	}
	if actor.Role == auth.RoleAdmin && !s.phpSupportMutationVisible(w, r, actor, id) {
		return actor, 0, false
	}
	if s.webStatistics == nil {
		http.Error(w, "Web statistics unavailable", http.StatusServiceUnavailable)
		return actor, 0, false
	}
	return actor, id, true
}
func (s *Server) handleRefreshWebStatistics(w http.ResponseWriter, r *http.Request) {
	actor, id, ok := s.statisticsRequest(w, r)
	if !ok {
		return
	}
	if err := s.webStatistics.Queue(r.Context(), &actor, id, true); err != nil {
		s.statisticsError(w, r, err)
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "web_statistics.refresh_queued", "site", id, nil)
	if wantsSPAJSON(r) {
		writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "status": "pending"})
		return
	}
	http.Redirect(w, r, supportRedirectPath(r, actor, "/sites/"+strconv.FormatInt(id, 10)+"/statistics"), http.StatusSeeOther)
}
func (s *Server) handleConfigureWebStatistics(w http.ResponseWriter, r *http.Request) {
	actor, id, ok := s.statisticsRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid statistics settings", 400)
		return
	}
	engine, err := boundedFormString(r, "engine", 16)
	if err != nil {
		http.Error(w, "Invalid statistics engine", 400)
		return
	}
	if err = s.webStatistics.Configure(r.Context(), actor, id, engine); err != nil {
		s.statisticsError(w, r, err)
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "web_statistics.site_configured", "site", id, map[string]any{"engine": engine})
	http.Redirect(w, r, supportRedirectPath(r, actor, "/sites/"+strconv.FormatInt(id, 10)+"/statistics"), http.StatusSeeOther)
}
func (s *Server) handleWebStatisticsReport(w http.ResponseWriter, r *http.Request) {
	actor, id, ok := s.statisticsRequest(w, r)
	if !ok {
		return
	}
	report, err := s.webStatistics.Report(r.Context(), actor, id)
	if err != nil {
		s.statisticsError(w, r, err)
		return
	}
	setStatisticsReportHeaders(w.Header())
	_, _ = w.Write(report.HTML)
}

func setStatisticsReportHeaders(header http.Header) {
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store, private")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Del("X-Frame-Options")
}
func (s *Server) statisticsError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, webstatistics.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	status := http.StatusServiceUnavailable
	message := "Web statistics unavailable"
	if errors.Is(err, webstatistics.ErrDisabled) {
		status = http.StatusConflict
		message = "Web statistics are disabled for this site"
	}
	if errors.Is(err, webstatistics.ErrCooldown) {
		status = http.StatusTooManyRequests
		message = "Refresh already pending or requested within the last 15 minutes"
		w.Header().Set("Retry-After", "900")
	}
	if wantsSPAJSON(r) {
		writeSPAError(w, status, message)
		return
	}
	if r.Method == http.MethodPost && r.PathValue("id") != "" {
		actor, _ := s.currentUser(w, r)
		http.Redirect(w, r, supportRedirectPath(r, actor, "/sites/"+r.PathValue("id")+"/statistics?statistics_error="+strconv.Itoa(status)), http.StatusSeeOther)
		return
	}
	http.Error(w, message, status)
}
func (s *Server) handleStatisticsSettings(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if actor.Role != auth.RoleAdmin || r.FormValue("support_customer_id") != "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.webStatistics == nil {
		http.Error(w, "Web statistics unavailable", http.StatusServiceUnavailable)
		return
	}
	settings, err := s.webStatistics.Settings(r.Context(), actor)
	if err != nil {
		s.statisticsError(w, r, err)
		return
	}
	data, err := s.loadDashboard(r.Context(), actor)
	if err != nil {
		http.Error(w, "Could not load settings", 500)
		return
	}
	view := web.WorkspaceView{Route: "tools-settings", SettingsFocus: "web-statistics", CSRFToken: csrfToken(r), StatisticsSettings: &settings}
	renderPage(w, r, web.RoutedDashboardPage("Web Statistics", actor, data, s.dashboardActions(actor), view))
}
func (s *Server) handleSaveStatisticsSettings(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if actor.Role != auth.RoleAdmin || r.FormValue("support_customer_id") != "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.webStatistics == nil {
		http.Error(w, "Web statistics unavailable", 503)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid settings", 400)
		return
	}
	days, err := boundedFormInt(r, "retention_days", 30, 1, 90)
	if err != nil {
		http.Error(w, "Invalid retention", 400)
		return
	}
	hour, err := boundedFormInt(r, "schedule_hour", 3, 0, 23)
	if err != nil {
		http.Error(w, "Invalid schedule", 400)
		return
	}
	enabled, err := boundedFormBool(r, "enabled")
	if err != nil {
		http.Error(w, "Invalid setting", 400)
		return
	}
	anonymize, err := boundedFormBool(r, "anonymize_ip")
	if err != nil {
		http.Error(w, "Invalid privacy setting", 400)
		return
	}
	if err = s.webStatistics.SaveSettings(r.Context(), actor, webstatistics.Settings{Enabled: enabled, RetentionDays: days, ScheduleHour: hour, AnonymizeIP: anonymize}); err != nil {
		s.statisticsError(w, r, err)
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "web_statistics.settings_updated", "server", 0, map[string]any{"retention_days": days, "schedule_hour": hour, "anonymize_ip": anonymize, "enabled": enabled})
	http.Redirect(w, r, "/tools-settings/web-statistics", http.StatusSeeOther)
}
