package panelhttp

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/web"
	controlwordpress "github.com/nakroteck/nakpanel/internal/control/wordpress"
	"github.com/nakroteck/nakpanel/internal/types"
)

type websiteCreateInput struct {
	SubscriptionID int64
	Domain         string
	Kind           string
	WordPress      controlwordpress.InstallInput
	GeneratedPass  bool
}

func parseWebsiteCreateInput(r *http.Request) (websiteCreateInput, error) {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var err error
	if mediaType == "multipart/form-data" {
		err = r.ParseMultipartForm(32 << 10)
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
	} else {
		err = r.ParseForm()
	}
	if err != nil {
		return websiteCreateInput{}, err
	}
	input := websiteCreateInput{
		SubscriptionID: parseFormInt64Default(r, "subscription_id", 0),
		Domain:         strings.ToLower(strings.TrimSpace(r.Form.Get("domain"))),
		Kind:           strings.ToLower(strings.TrimSpace(r.Form.Get("website_type"))),
	}
	if input.SubscriptionID <= 0 || input.Domain == "" {
		return input, errors.New("select a subscription and enter a domain")
	}
	switch input.Kind {
	case "php", "git":
		return input, nil
	case "wordpress":
		input.WordPress = controlwordpress.InstallInput{
			Title:         strings.TrimSpace(r.Form.Get("site_title")),
			AdminUser:     strings.TrimSpace(r.Form.Get("admin_user")),
			AdminEmail:    strings.TrimSpace(r.Form.Get("admin_email")),
			AdminPassword: r.Form.Get("admin_password"),
			Version:       "latest",
		}
		if input.WordPress.Title == "" {
			input.WordPress.Title = input.Domain
		}
		if input.WordPress.AdminUser == "" {
			input.WordPress.AdminUser = "siteadmin"
		}
		if input.WordPress.AdminPassword == "" {
			secret := make([]byte, 24)
			if _, err := rand.Read(secret); err != nil {
				return input, err
			}
			input.WordPress.AdminPassword = base64.RawURLEncoding.EncodeToString(secret)
			input.GeneratedPass = true
		}
		validated, err := controlwordpress.ValidateInstallInput(input.WordPress)
		input.WordPress = validated
		return input, err
	default:
		return input, errors.New("choose a website type")
	}
}

func (s *Server) handleCreateWebsite(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleClient && actor.Role != auth.RoleReseller {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	input, err := parseWebsiteCreateInput(r)
	if err != nil {
		s.writeWebsiteCreateError(w, r, actor, http.StatusBadRequest, "Review the website details and try again.", input)
		return
	}
	if s.sites == nil || (input.Kind == "wordpress" && s.wordpress == nil) {
		s.writeWebsiteCreateError(w, r, actor, http.StatusServiceUnavailable, "Website setup is temporarily unavailable.", input)
		return
	}
	if input.Kind == "wordpress" {
		if err := s.wordpress.PreflightNewSite(r.Context(), actor, input.SubscriptionID); err != nil {
			if errors.Is(err, controlwordpress.ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			s.writeWebsiteCreateError(w, r, actor, http.StatusBadRequest, wordpressPreflightMessage(err), input)
			return
		}
	}
	if actor.Role == auth.RoleAdmin {
		if supportID := parseFormInt64Default(r, "support_customer_id", 0); supportID > 0 {
			if s.workspace == nil {
				http.NotFound(w, r)
				return
			}
			customerID, lookupErr := s.workspace.CustomerIDForSubscription(r.Context(), input.SubscriptionID)
			if lookupErr != nil || customerID != supportID {
				http.NotFound(w, r)
				return
			}
		}
	}
	siteID, err := s.sites.CreateSiteFor(r.Context(), actor, actor.ID, types.CreateSiteReq{
		SubscriptionID: input.SubscriptionID,
		Domain:         input.Domain,
	})
	if err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		s.writeWebsiteCreateError(w, r, actor, http.StatusBadRequest, websiteCreateMessage(err), input)
		return
	}
	customerID := int64(0)
	if s.workspace != nil {
		customerID, _ = s.workspace.CustomerIDForSubscription(r.Context(), input.SubscriptionID)
	}
	s.recordAudit(r.Context(), actor, customerID, input.SubscriptionID, "site.queued", "site", siteID, map[string]any{"domain": input.Domain, "website_type": input.Kind})
	result := web.SiteCreationResult{SiteID: siteID, Domain: input.Domain, Kind: input.Kind, Message: "Website setup is underway."}
	result.Redirect = "/sites/" + strconv.FormatInt(siteID, 10)
	switch input.Kind {
	case "git":
		result.Redirect += "/git"
		result.Message = "Hosting is being prepared. Connect the repository when the website is ready."
	case "wordpress":
		_, operation, installErr := s.wordpress.Install(r.Context(), actor, siteID, input.WordPress)
		if installErr != nil {
			result.Partial = true
			result.Redirect += "/wordpress"
			result.Message = "Hosting was created, but WordPress setup could not start. Open the website to retry installation."
		} else {
			result.OperationID = operation.ID
			result.Redirect += "/wordpress"
			result.Message = "Hosting and WordPress setup are underway."
			result.AdminUser = input.WordPress.AdminUser
			if input.GeneratedPass {
				result.AdminPassword = input.WordPress.AdminPassword
			}
		}
	}
	input.WordPress.AdminPassword = ""
	result.Redirect = supportRedirectPath(r, actor, result.Redirect)
	if wantsSPAJSON(r) {
		writeSPAJSON(w, http.StatusAccepted, map[string]any{
			"ok": true, "site_id": siteID, "website_type": input.Kind, "operation_id": result.OperationID,
			"redirect": result.Redirect, "notice": result.Message, "partial": result.Partial,
			"admin_user": result.AdminUser, "admin_password": result.AdminPassword,
		})
		return
	}
	s.renderWebsiteCreatePage(w, r, actor, http.StatusAccepted, input, "", &result)
}

func wordpressPreflightMessage(err error) string {
	switch {
	case errors.Is(err, controlwordpress.ErrDisabled):
		return "WordPress is not included in this subscription. Choose PHP website or ask your provider to enable WordPress."
	case errors.Is(err, controlwordpress.ErrLimitReached):
		return "This subscription has reached its WordPress website limit."
	case errors.Is(err, controlwordpress.ErrDatabaseLimit):
		return "WordPress needs a database, but this subscription has reached its database limit."
	case errors.Is(err, controlwordpress.ErrInactive):
		return "This subscription is not active."
	default:
		return "WordPress setup could not be checked right now. Try again shortly."
	}
}

func websiteCreateMessage(err error) string {
	switch {
	case errors.Is(err, controlquota.ErrExceeded):
		return "This subscription has reached a website or resource limit."
	case errors.Is(err, controlquota.ErrNoActiveSubscription):
		return "Select an active subscription before adding a website."
	default:
		return "Website could not be created. Check the domain and subscription, then try again."
	}
}

func (s *Server) writeWebsiteCreateError(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, status int, message string, input websiteCreateInput) {
	input.WordPress.AdminPassword = ""
	if wantsSPAJSON(r) {
		writeSPAError(w, status, message)
		return
	}
	s.renderWebsiteCreatePage(w, r, actor, status, input, message, nil)
}

func (s *Server) renderWebsiteCreatePage(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, status int, input websiteCreateInput, message string, result *web.SiteCreationResult) {
	data, err := s.loadDashboard(r.Context(), actor)
	if err != nil {
		http.Error(w, "Could not load website setup", http.StatusServiceUnavailable)
		return
	}
	view := web.WorkspaceView{
		Route: "site-new", Title: dashboardTitle(actor.Role), CSRFToken: csrfToken(r),
		SelectedSubscription: input.SubscriptionID, SiteCreateError: message, SiteCreateDomain: input.Domain,
		SiteCreateKind: input.Kind, SiteCreateTitle: input.WordPress.Title, SiteCreateEmail: input.WordPress.AdminEmail,
		SiteCreated: result,
	}
	if s.wordpress == nil && view.SiteCreateKind == "wordpress" {
		view.SiteCreateKind = "php"
	}
	if actor.Role == auth.RoleAdmin {
		view.SupportCustomerID = parseFormInt64Default(r, "support_customer_id", 0)
		if view.SupportCustomerID > 0 {
			data = filterDashboardForCustomer(data, view.SupportCustomerID)
		}
	}
	var body bytes.Buffer
	if err := web.RoutedDashboardPage("Add Website", actor, data, s.dashboardActions(actor), view).Render(r.Context(), &body); err != nil {
		http.Error(w, "Could not render website setup", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status >= http.StatusBadRequest {
		w.Header().Set("X-Nakpanel-Complete-Error-Page", "1")
	}
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}
