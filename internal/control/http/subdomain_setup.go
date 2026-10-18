package panelhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

type siteSetupReader interface {
	SiteSetupStatus(context.Context, auth.SessionUser, int64) (types.SiteSetupStatus, error)
}

func (s *Server) siteSetupTarget(w http.ResponseWriter, r *http.Request) (auth.SessionUser, types.SiteSetupStatus, int64, bool) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := s.currentUser(w, r, func() {
		writeSPAError(w, http.StatusUnauthorized, "Sign in to check setup.")
	})
	if !ok {
		return user, types.SiteSetupStatus{}, 0, false
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return user, types.SiteSetupStatus{}, 0, false
	}
	reader, ok := s.sites.(siteSetupReader)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Setup status is unavailable.")
		return user, types.SiteSetupStatus{}, 0, false
	}
	setup, err := reader.SiteSetupStatus(r.Context(), user, id)
	if errors.Is(err, provision.ErrForbidden) {
		http.NotFound(w, r)
		return user, setup, 0, false
	}
	if err != nil {
		writeSPAError(w, http.StatusServiceUnavailable, "Setup status is temporarily unavailable.")
		return user, setup, 0, false
	}
	if setup.SiteID != id {
		http.NotFound(w, r)
		return user, setup, 0, false
	}
	if setup.Kind == "" {
		setup.Kind = "website"
		if setup.ParentID > 0 {
			setup.Kind = "subdomain"
		}
	}
	var supportID int64
	if raw := r.PathValue("customerID"); raw != "" {
		supportID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || supportID <= 0 || user.Role != auth.RoleAdmin || setup.CustomerID != supportID {
			http.NotFound(w, r)
			return user, setup, 0, false
		}
	}
	return user, setup, supportID, true
}

func setupPath(supportID, siteID int64, suffix string) string {
	path := "/sites/" + strconv.FormatInt(siteID, 10) + suffix
	if supportID > 0 {
		path = "/support/customers/" + strconv.FormatInt(supportID, 10) + path
	}
	return path
}

func (s *Server) handleSiteSetupStatus(w http.ResponseWriter, r *http.Request) {
	_, setup, supportID, ok := s.siteSetupTarget(w, r)
	if !ok {
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "site_id": setup.SiteID, "kind": setup.Kind, "ssl_requested": setup.SSLRequested, "can_retry_ssl": setup.CanRetrySSL, "domain": setup.Domain, "state": setup.State, "message": setup.Message, "steps": setup.Steps, "redirect": setupPath(supportID, setup.SiteID, "?tab=overview&notice="+setupNotice(setup))})
}

func setupNotice(setup types.SiteSetupStatus) string {
	if setup.SSLRequested {
		return "website-secured"
	}
	if setup.ParentID > 0 {
		return "subdomain-created"
	}
	return "website-created"
}

func (s *Server) handleRetrySetupSSL(w http.ResponseWriter, r *http.Request) {
	user, setup, supportID, ok := s.siteSetupTarget(w, r)
	if !ok {
		return
	}
	retry, ok := s.sites.(interface {
		RetryCreationSSLFor(context.Context, auth.SessionUser, int64) (int64, error)
	})
	if !ok {
		if wantsSPAJSON(r) {
			writeSPAError(w, http.StatusServiceUnavailable, "SSL retry is unavailable.")
		} else {
			redirectFormError(w, r, setupPath(supportID, setup.SiteID, "/setup"), "SSL retry is unavailable.")
		}
		return
	}
	_, err := retry.RetryCreationSSLFor(r.Context(), user, setup.SiteID)
	if errors.Is(err, provision.ErrForbidden) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if wantsSPAJSON(r) {
			writeSPAError(w, http.StatusBadRequest, "Could not retry SSL: "+err.Error())
		} else {
			redirectFormError(w, r, setupPath(supportID, setup.SiteID, "/setup"), "Could not retry SSL: "+err.Error())
		}
		return
	}
	s.recordAudit(r.Context(), user, setup.CustomerID, setup.SubscriptionID, "certificate.setup_retry", "site", setup.SiteID, map[string]any{"domain": setup.Domain})
	progress := setupPath(supportID, setup.SiteID, "/setup")
	if wantsSPAJSON(r) {
		writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "site_id": setup.SiteID, "kind": setup.Kind, "ssl_requested": true, "status_url": progress + "/status", "setup_url": progress})
		return
	}
	http.Redirect(w, r, progress, http.StatusSeeOther)
}

func (s *Server) handleSiteSetupPage(w http.ResponseWriter, r *http.Request) {
	user, setup, supportID, ok := s.siteSetupTarget(w, r)
	if !ok {
		return
	}
	if setup.State == "ready" {
		http.Redirect(w, r, setupPath(supportID, setup.SiteID, "?tab=overview&notice="+setupNotice(setup)), http.StatusSeeOther)
		return
	}
	data, err := s.loadDashboard(dashboard.WithServiceScope(r.Context(), 0, setup.SiteID), user)
	if err != nil {
		http.Error(w, "Could not load setup workspace", http.StatusServiceUnavailable)
		return
	}
	data.Notice, data.NoticeKind = workspaceNotice(w, r)
	view := web.WorkspaceView{Route: "site-setup", Title: "Website setup", DetailID: setup.SiteID, CSRFToken: csrfToken(r), SiteSetup: &setup, SupportCustomerID: supportID, SiteSetupTimedOut: !setup.StartedAt.IsZero() && time.Since(setup.StartedAt) >= 5*time.Minute}
	if supportID > 0 {
		data = filterDashboardForCustomer(data, supportID)
		for _, customer := range data.Customers {
			if customer.ID == supportID {
				view.SupportCustomerName = customer.DisplayName
			}
		}
	}
	actionUser := user
	if supportID > 0 {
		actionUser.Role = auth.RoleClient
	}
	s.renderRoutedPage(w, r, "Website setup", user, data, s.dashboardActions(actionUser), view)
}
