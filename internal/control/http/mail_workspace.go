package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Server) handleEmailRedirect(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	target := "/mail"
	if user.Role == auth.RoleAdmin || user.Role == auth.RoleReseller {
		target = s.providerMailTarget(r.Context(), user, parseQueryInt64(r, "domain_id"))
	} else if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleMailWorkspace(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if user.Role == auth.RoleAdmin || user.Role == auth.RoleReseller {
		http.Redirect(w, r, s.providerMailTarget(r.Context(), user, parseQueryInt64(r, "domain_id")), http.StatusSeeOther)
		return
	}
	s.handleWorkspace("mail").ServeHTTP(w, r)
}

func (s *Server) providerMailTarget(ctx context.Context, user auth.SessionUser, mailDomainID int64) string {
	if mailDomainID <= 0 {
		return "/sites"
	}
	data, err := s.loadDashboard(ctx, user)
	if err != nil {
		return "/sites"
	}
	for _, domain := range data.SubscriptionServices.MailDomains {
		if domain.ID != mailDomainID {
			continue
		}
		for _, site := range data.Sites {
			if site.SubscriptionID == domain.SubscriptionID && ((domain.SiteID > 0 && site.ID == domain.SiteID) || (domain.SiteID == 0 && strings.EqualFold(site.Domain, domain.Domain))) {
				return "/sites/" + strconv.FormatInt(site.ID, 10) + "?tab=mail"
			}
		}
	}
	return "/sites"
}

func (s *Server) redirectSiteMail(w http.ResponseWriter, r *http.Request, user auth.SessionUser, siteID, subscriptionID int64, domain, notice string) {
	target, ok := s.siteMailTarget(r.Context(), user, siteID, subscriptionID, domain, parseFormInt64Default(r, "support_customer_id", 0))
	if !ok {
		http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(subscriptionID, 10)+"?tab=mail&notice="+notice, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target+"&notice="+notice, http.StatusSeeOther)
}

func (s *Server) siteMailTarget(ctx context.Context, user auth.SessionUser, siteID, subscriptionID int64, domain string, supportCustomerID int64) (string, bool) {
	if siteID <= 0 || subscriptionID <= 0 {
		return "", false
	}
	data, err := s.loadDashboard(ctx, user)
	if err != nil {
		return "", false
	}
	for _, site := range data.Sites {
		if site.ID != siteID || site.SubscriptionID != subscriptionID || (domain != "" && !strings.EqualFold(site.Domain, domain)) {
			continue
		}
		if supportCustomerID > 0 && user.Role == auth.RoleAdmin && site.CustomerID == supportCustomerID {
			return "/support/customers/" + strconv.FormatInt(supportCustomerID, 10) + "/sites/" + strconv.FormatInt(site.ID, 10) + "?tab=mail", true
		}
		return "/sites/" + strconv.FormatInt(site.ID, 10) + "?tab=mail", true
	}
	return "", false
}

func (s *Server) handleMailStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.mail == nil {
		writeSPAError(w, http.StatusServiceUnavailable, "Mail management is not configured")
		return
	}
	status, err := s.mail.MailServerStatus(r.Context(), user)
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Mail status unavailable")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
}

func (s *Server) handleUpdateMailSettings(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.mail == nil {
		http.Error(w, "Mail management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid mail settings form", http.StatusBadRequest)
		return
	}
	update := types.MailSettingsUpdate{
		MailHostname: strings.TrimSpace(r.Form.Get("mail_hostname")), SmarthostHost: strings.TrimSpace(r.Form.Get("smarthost_host")),
		SmarthostPort: int(parseFormInt64Default(r, "smarthost_port", 587)), SmarthostUsername: strings.TrimSpace(r.Form.Get("smarthost_username")),
		SmarthostPassword: r.Form.Get("smarthost_password"), ClearSmarthost: parseFormBool(r, "clear_smarthost"),
		OutboundRateLimit: strings.TrimSpace(r.Form.Get("outbound_rate_limit")), QueueAlertThreshold: int(parseFormInt64Default(r, "queue_alert_threshold", 50)),
	}
	view, err := s.mail.UpdateMailSettings(r.Context(), user, update)
	if err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		http.Error(w, "Could not save mail settings: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "mail_settings.updated", "mail_settings", 1, map[string]any{
		"hostname": view.MailHostname, "smarthost": view.SmarthostHost, "rate_limit": view.OutboundRateLimit, "alert_threshold": view.QueueAlertThreshold,
	})
	http.Redirect(w, r, "/tools-settings?notice=mail-settings-saved", http.StatusSeeOther)
}

func (s *Server) handleReconfigureMail(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.mail == nil {
		http.Error(w, "Mail management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.mail.ReconfigureMail(r.Context(), user); err != nil {
		http.Error(w, "Could not queue mail reconfiguration: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "mail.reconfigure_queued", "mail_server", 1, nil)
	http.Redirect(w, r, "/tools-settings?notice=mail-reconfigure-queued", http.StatusSeeOther)
}

func (s *Server) handleRestartMail(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.mail == nil {
		http.Error(w, "Mail management is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.mail.RestartMail(r.Context(), user); err != nil {
		http.Error(w, "Could not restart mail service: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "mail.restarted", "mail_server", 1, nil)
	http.Redirect(w, r, "/tools-settings?notice=mail-restarted", http.StatusSeeOther)
}
