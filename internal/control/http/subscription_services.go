package panelhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Server) subscriptionServices(w http.ResponseWriter) (SubscriptionServices, bool) {
	services, ok := s.domains.(SubscriptionServices)
	if !ok {
		http.Error(w, "Subscription services are not configured", http.StatusServiceUnavailable)
	}
	return services, ok
}

func parsePositivePathID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue(name)), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid resource id")
	}
	return id, nil
}

func (s *Server) handleSubscriptionPolicy(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.subscriptionServices(w)
	if !ok {
		return
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil || r.ParseForm() != nil {
		http.Error(w, "Invalid subscription policy", http.StatusBadRequest)
		return
	}
	patch := json.RawMessage(strings.TrimSpace(r.Form.Get("policy_patch")))
	if len(patch) == 0 {
		patch = json.RawMessage(`{}`)
	}
	if err := services.SetSubscriptionPolicy(r.Context(), user, id, patch); err != nil {
		writeQuotaError(w, r, "Could not update subscription policy", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, id, "subscription.policy_updated", "subscription", id, nil)
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(id, 10)+"?notice=policy-saved", http.StatusSeeOther)
}

func (s *Server) handleSitePolicy(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.subscriptionServices(w)
	if !ok {
		return
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil || r.ParseForm() != nil {
		http.Error(w, "Invalid domain policy", http.StatusBadRequest)
		return
	}
	patch := json.RawMessage(strings.TrimSpace(r.Form.Get("policy_patch")))
	if len(patch) == 0 {
		patch = json.RawMessage(`{}`)
	}
	if err := services.SetSitePolicy(r.Context(), user, id, patch); err != nil {
		writeQuotaError(w, r, "Could not update domain policy", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "site.policy_updated", "site", id, nil)
	http.Redirect(w, r, "/sites/"+strconv.FormatInt(id, 10)+"?tab=hosting&notice=policy-saved", http.StatusSeeOther)
}

func (s *Server) handleSFTPIdentity(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	input := types.SFTPIdentityInput{
		ID: parseFormInt64Default(r, "resource_id", 0), Name: strings.TrimSpace(r.Form.Get("name")),
		PublicKey: strings.TrimSpace(r.Form.Get("public_key")), RelativeRoot: strings.TrimSpace(r.Form.Get("relative_root")),
		Enabled: formBoolDefault(r, "enabled", true),
	}
	id, err := services.UpsertSFTPIdentity(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save SFTP identity", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "sftp_identity.saved", "sftp_identity", id, nil)
	s.redirectSubscriptionService(w, r, subscriptionID, "access")
}

func (s *Server) handleScheduledTask(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	input := types.ScheduledTaskInput{
		ID: parseFormInt64Default(r, "resource_id", 0), SiteID: parseFormInt64Default(r, "site_id", 0),
		Name: strings.TrimSpace(r.Form.Get("name")), Schedule: strings.TrimSpace(r.Form.Get("schedule")),
		Command: r.Form.Get("command"), WorkingDirectory: strings.TrimSpace(r.Form.Get("working_directory")),
		TimeoutSeconds: int(parseFormInt64Default(r, "timeout_seconds", 300)), Enabled: formBoolDefault(r, "enabled", true),
	}
	id, err := services.UpsertScheduledTask(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save scheduled task", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "scheduled_task.saved", "scheduled_task", id, nil)
	s.redirectSubscriptionService(w, r, subscriptionID, "tasks")
}

func (s *Server) handleMailDomain(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	policy := strings.TrimSpace(r.Form.Get("dmarc_policy"))
	if policy == "" {
		policy = "none"
	}
	input := types.MailDomainInput{
		ID: parseFormInt64Default(r, "resource_id", 0), SiteID: parseFormInt64Default(r, "site_id", 0),
		Domain: strings.TrimSpace(r.Form.Get("domain")), Enabled: formBoolDefault(r, "enabled", true),
		DKIM: formBoolDefault(r, "dkim", true), DMARCPolicy: policy, CatchAll: strings.TrimSpace(r.Form.Get("catch_all")),
	}
	id, err := services.UpsertMailDomain(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save mail domain", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "mail_domain.saved", "mail_domain", id, nil)
	s.redirectSubscriptionService(w, r, subscriptionID, "mail")
}

func (s *Server) handleMailbox(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	input := types.MailboxInput{
		ID: parseFormInt64Default(r, "resource_id", 0), MailDomainID: parseFormInt64Default(r, "mail_domain_id", 0),
		LocalPart: strings.TrimSpace(r.Form.Get("local_part")), Password: r.Form.Get("password"),
		QuotaMB: int(parseFormInt64Default(r, "quota_mb", 0)), Enabled: formBoolDefault(r, "enabled", true),
	}
	id, err := services.UpsertMailbox(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save mailbox", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "mailbox.saved", "mailbox", id, nil)
	s.redirectSubscriptionService(w, r, subscriptionID, "mail")
}

func (s *Server) handleMailAlias(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	var destinations []string
	for _, destination := range strings.Split(r.Form.Get("destinations"), ",") {
		if destination = strings.TrimSpace(destination); destination != "" {
			destinations = append(destinations, destination)
		}
	}
	input := types.MailAliasInput{
		ID: parseFormInt64Default(r, "resource_id", 0), MailDomainID: parseFormInt64Default(r, "mail_domain_id", 0),
		LocalPart: strings.TrimSpace(r.Form.Get("local_part")), Destinations: destinations,
	}
	id, err := services.UpsertMailAlias(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save mail alias", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "mail_alias.saved", "mail_alias", id, nil)
	s.redirectSubscriptionService(w, r, subscriptionID, "mail")
}

func (s *Server) handleApplication(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	environment := make(map[string]string)
	rawEnvironment := strings.TrimSpace(r.Form.Get("environment"))
	if rawEnvironment != "" {
		if err := json.Unmarshal([]byte(rawEnvironment), &environment); err != nil {
			http.Error(w, "Environment must be a JSON object of string values", http.StatusBadRequest)
			return
		}
	}
	input := types.ApplicationInput{
		ID: parseFormInt64Default(r, "resource_id", 0), SiteID: parseFormInt64Default(r, "site_id", 0),
		Name: strings.TrimSpace(r.Form.Get("name")), Runtime: strings.TrimSpace(r.Form.Get("runtime")),
		CatalogSlug: strings.TrimSpace(r.Form.Get("catalog_slug")), ImageRef: strings.TrimSpace(r.Form.Get("image_ref")),
		DesiredState: formStringDefault(r, "desired_state", "running"), Environment: environment,
	}
	id, err := services.UpsertApplication(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save application", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "application.saved", "application", id, nil)
	s.redirectSubscriptionService(w, r, subscriptionID, "applications")
}

func (s *Server) handleDeleteSubscriptionService(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	resourceID, err := parsePositivePathID(r, "resourceID")
	if err != nil {
		http.Error(w, "Invalid service resource", http.StatusBadRequest)
		return
	}
	kind := strings.TrimSpace(r.PathValue("kind"))
	if err := services.DeleteSubscriptionService(r.Context(), user, subscriptionID, kind, resourceID); err != nil {
		writeQuotaError(w, r, "Could not delete subscription service", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, kind+".deleted", kind, resourceID, nil)
	tab := map[string]string{"sftp": "access", "task": "tasks", "mail": "mail", "mailbox": "mail", "mail_alias": "mail", "application": "applications"}[kind]
	s.redirectSubscriptionService(w, r, subscriptionID, tab)
}

func (s *Server) subscriptionServiceRequest(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, SubscriptionServices, bool) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return auth.SessionUser{}, 0, nil, false
	}
	services, ok := s.subscriptionServices(w)
	if !ok {
		return auth.SessionUser{}, 0, nil, false
	}
	subscriptionID, err := parsePositivePathID(r, "id")
	if err != nil || r.ParseForm() != nil {
		http.Error(w, "Invalid subscription service form", http.StatusBadRequest)
		return auth.SessionUser{}, 0, nil, false
	}
	return user, subscriptionID, services, true
}

func (s *Server) redirectSubscriptionService(w http.ResponseWriter, r *http.Request, subscriptionID int64, tab string) {
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(subscriptionID, 10)+"?tab="+tab+"&notice=service-saved", http.StatusSeeOther)
}
