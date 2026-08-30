package panelhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
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
	if len(patch) == 0 || (string(patch) == "{}" && hasTypedSitePolicyFields(r)) {
		patch, err = typedSitePolicyPatch(r)
		if err != nil {
			http.Error(w, "Invalid domain policy", http.StatusBadRequest)
			return
		}
	}
	if err := services.SetSubscriptionPolicy(r.Context(), user, id, patch); err != nil {
		writeQuotaError(w, r, "Could not update subscription policy", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, id, "subscription.policy_updated", "subscription", id, nil)
	http.Redirect(w, r, supportRedirectPath(r, user, "/subscriptions/"+strconv.FormatInt(id, 10)+"?notice=policy-saved"), http.StatusSeeOther)
}

func hasTypedSitePolicyFields(r *http.Request) bool {
	for _, name := range []string{"site_preferred_domain", "site_request_rate", "site_fpm_mode", "site_fpm_children", "site_php_memory"} {
		if _, exists := r.Form[name]; exists {
			return true
		}
	}
	return false
}

func typedSitePolicyPatch(r *http.Request) (json.RawMessage, error) {
	number := func(name string) (int, error) {
		value := strings.TrimSpace(r.Form.Get(name))
		if value == "" {
			return 0, nil
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%s must be a number", name)
		}
		return parsed, nil
	}
	boolValue := func(name string) bool { return formBoolDefault(r, name, false) }
	patch := make(map[string]any)
	if _, exists := r.Form["site_preferred_domain"]; exists {
		numericNames := []string{
			"site_body_limit", "site_cache_ttl", "site_request_rate", "site_request_burst",
			"site_max_connections", "site_connect_timeout", "site_read_timeout",
		}
		numbers := make(map[string]int, len(numericNames))
		for _, name := range numericNames {
			value, err := number(name)
			if err != nil {
				return nil, err
			}
			numbers[name] = value
		}
		var cidrs []string
		for _, candidate := range strings.Split(r.Form.Get("site_allowed_cidrs"), ",") {
			if candidate = strings.TrimSpace(candidate); candidate != "" {
				cidrs = append(cidrs, candidate)
			}
		}
		patch["web"] = map[string]any{
			"preferred_domain":        strings.TrimSpace(r.Form.Get("site_preferred_domain")),
			"index_files":             strings.TrimSpace(r.Form.Get("site_index_files")),
			"request_body_limit_mb":   numbers["site_body_limit"],
			"compression":             boolValue("site_compression"),
			"cache_ttl_seconds":       numbers["site_cache_ttl"],
			"request_rate_per_second": numbers["site_request_rate"],
			"request_burst":           numbers["site_request_burst"],
			"max_connections":         numbers["site_max_connections"],
			"connect_timeout_seconds": numbers["site_connect_timeout"],
			"read_timeout_seconds":    numbers["site_read_timeout"],
			"security_header_preset":  strings.TrimSpace(r.Form.Get("site_security_headers")),
			"allowed_cidrs":           cidrs,
			"error_document_404":      strings.TrimSpace(r.Form.Get("site_error_document_404")),
			"error_document_50x":      strings.TrimSpace(r.Form.Get("site_error_document_50x")),
			"static_cache":            boolValue("site_static_cache"),
			"fastcgi_microcache":      boolValue("site_fastcgi_microcache"),
		}
	}
	if _, exists := r.Form["site_fpm_mode"]; exists {
		numericNames := []string{
			"site_fpm_children", "site_fpm_requests", "site_fpm_idle", "site_fpm_terminate",
			"site_php_memory", "site_php_execution", "site_php_input", "site_php_post",
			"site_php_upload", "site_php_opcache_memory",
		}
		numbers := make(map[string]int, len(numericNames))
		for _, name := range numericNames {
			value, err := number(name)
			if err != nil {
				return nil, err
			}
			numbers[name] = value
		}
		patch["php"] = map[string]any{
			"fpm_mode":                          strings.TrimSpace(r.Form.Get("site_fpm_mode")),
			"fpm_max_children":                  numbers["site_fpm_children"],
			"fpm_max_requests":                  numbers["site_fpm_requests"],
			"fpm_idle_timeout_seconds":          numbers["site_fpm_idle"],
			"request_terminate_timeout_seconds": numbers["site_fpm_terminate"],
			"memory_limit_mb":                   numbers["site_php_memory"],
			"max_execution_seconds":             numbers["site_php_execution"],
			"max_input_seconds":                 numbers["site_php_input"],
			"post_max_mb":                       numbers["site_php_post"],
			"upload_max_mb":                     numbers["site_php_upload"],
			"log_errors":                        boolValue("site_php_log_errors"),
			"display_errors":                    boolValue("site_php_display_errors"),
			"allow_url_fopen":                   boolValue("site_php_url_fopen"),
			"opcache_enabled":                   boolValue("site_php_opcache"),
			"opcache_memory_mb":                 numbers["site_php_opcache_memory"],
			"exec_enabled":                      boolValue("site_php_exec"),
		}
	}
	encoded, err := json.Marshal(patch)
	return json.RawMessage(encoded), err
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
	resetScope := strings.ToLower(strings.TrimSpace(r.Form.Get("reset_scope")))
	if resetScope != "" {
		if err := services.ResetSitePolicy(r.Context(), user, id, resetScope); err != nil {
			writeQuotaError(w, r, "Could not reset domain policy", err)
			return
		}
		s.recordAudit(r.Context(), user, 0, 0, "site.policy_reset", "site", id, map[string]any{"scope": resetScope})
		redirectSitePolicy(w, r, user, id)
		return
	}
	patch := json.RawMessage(strings.TrimSpace(r.Form.Get("policy_patch")))
	if len(patch) == 0 || (string(patch) == "{}" && hasTypedSitePolicyFields(r)) {
		patch, err = typedSitePolicyPatch(r)
		if err != nil {
			http.Error(w, "Invalid domain policy", http.StatusBadRequest)
			return
		}
	}
	if err := services.SetSitePolicy(r.Context(), user, id, patch); err != nil {
		writeQuotaError(w, r, "Could not update domain policy", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "site.policy_updated", "site", id, nil)
	redirectSitePolicy(w, r, user, id)
}

func redirectSitePolicy(w http.ResponseWriter, r *http.Request, user auth.SessionUser, id int64) {
	tab := strings.TrimSpace(r.Form.Get("policy_return_tab"))
	if tab == "web-server" {
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(id, 10)+"/web-server?notice=policy-saved"), http.StatusSeeOther)
		return
	}
	if tab == "php" {
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(id, 10)+"?tab=php&notice=policy-saved"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(id, 10)+"?tab=hosting&notice=policy-saved"), http.StatusSeeOther)
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
	s.redirectSubscriptionService(w, r, user, subscriptionID, "access")
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
		Kind: formStringDefault(r, "kind", "command"), URL: strings.TrimSpace(r.Form.Get("url")),
		Script: strings.TrimSpace(r.Form.Get("script")), Timezone: formStringDefault(r, "timezone", "UTC"),
	}
	id, err := services.UpsertScheduledTask(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save scheduled task", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "scheduled_task.saved", "scheduled_task", id, nil)
	if r.Form.Get("return_to") == "site-tasks" && input.SiteID > 0 {
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(input.SiteID, 10)+"/scheduled-tasks?notice=service-saved"), http.StatusSeeOther)
		return
	}
	s.redirectSubscriptionService(w, r, user, subscriptionID, "tasks")
}

func (s *Server) handleFTPAccount(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	input := types.FTPAccountInput{
		ID: parseFormInt64Default(r, "resource_id", 0), SiteID: parseFormInt64Default(r, "site_id", 0),
		Name: strings.TrimSpace(r.Form.Get("name")), Password: r.Form.Get("password"),
		Enabled: formBoolDefault(r, "enabled", true),
	}
	id, password, err := services.UpsertFTPAccount(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save FTPS account", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "ftp_account.saved", "ftp_account", id, map[string]any{"site_id": input.SiteID})
	continuePath := "/subscriptions/" + strconv.FormatInt(subscriptionID, 10) + "/access"
	if r.Form.Get("return_to") == "site-access" && input.SiteID > 0 {
		continuePath = "/sites/" + strconv.FormatInt(input.SiteID, 10) + "/access"
	}
	continuePath = supportRedirectPath(r, user, continuePath)
	if password == "" {
		http.Redirect(w, r, continuePath+"?notice=service-saved", http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeSPAJSON(w, http.StatusCreated, map[string]any{"id": id, "password": password})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte("<!doctype html><meta name=\"robots\" content=\"noindex\"><title>FTPS credential</title><h1>FTPS account created</h1><p>This password is shown once.</p><pre>" + html.EscapeString(password) + "</pre><p><a href=\"" + html.EscapeString(continuePath) + "\">Continue</a></p>"))
}

func (s *Server) handleValkey(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	input := types.ValkeyInput{
		DesiredState:       formStringDefault(r, "desired_state", "enabled"),
		MemoryMB:           int(parseFormInt64Default(r, "memory_mb", 64)),
		MaxClients:         int(parseFormInt64Default(r, "max_clients", 64)),
		IdleTimeoutSeconds: int(parseFormInt64Default(r, "idle_timeout_seconds", 300)),
		CPUPercent:         int(parseFormInt64Default(r, "cpu_percent", 25)),
		ProcessLimit:       int(parseFormInt64Default(r, "process_limit", 64)),
		RotateCredential:   formBoolDefault(r, "rotate_credential", false),
		Flush:              formBoolDefault(r, "flush", false),
	}
	if input.Flush && r.Form.Get("confirm") != "flush" {
		http.Error(w, "Type flush to confirm clearing the cache", http.StatusBadRequest)
		return
	}
	credential, err := services.ConfigureValkey(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save cache settings", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "valkey.saved", "subscription", subscriptionID, map[string]any{"state": input.DesiredState, "memory_mb": input.MemoryMB, "flush": input.Flush, "credential_rotated": input.RotateCredential})
	continuePath := "/subscriptions/" + strconv.FormatInt(subscriptionID, 10) + "/cache"
	if r.Form.Get("return_to") == "site-redis" {
		if siteID := parseFormInt64Default(r, "site_id", 0); siteID > 0 {
			continuePath = "/sites/" + strconv.FormatInt(siteID, 10) + "/redis"
		}
	}
	continuePath = supportRedirectPath(r, user, continuePath)
	if credential == "" {
		http.Redirect(w, r, continuePath+"?notice=service-saved", http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeSPAJSON(w, http.StatusOK, map[string]string{"username": "app", "password": credential})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><meta name=\"robots\" content=\"noindex\"><title>Cache credential</title><h1>Cache credential rotated</h1><p>This password is shown once.</p><pre>" + html.EscapeString(credential) + "</pre><p><a href=\"" + html.EscapeString(continuePath) + "\">Continue</a></p>"))
}

func (s *Server) handleGitRepository(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.subscriptionServices(w)
	if !ok {
		return
	}
	siteID, err := parsePositivePathID(r, "id")
	if err != nil || r.ParseForm() != nil {
		http.Error(w, "Invalid Git repository form", http.StatusBadRequest)
		return
	}
	subscriptionID := parseFormInt64Default(r, "subscription_id", 0)
	input := types.GitRepositoryInput{
		ID: parseFormInt64Default(r, "resource_id", 0), Mode: formStringDefault(r, "mode", "remote"),
		RemoteURL: strings.TrimSpace(r.Form.Get("remote_url")), Branch: formStringDefault(r, "branch", "main"),
		DeployTarget: formStringDefault(r, "deploy_target", "."), Automatic: formBoolDefault(r, "automatic", false),
		KnownHostKey: strings.TrimSpace(r.Form.Get("known_host_key")),
	}
	id, err := services.UpsertGitRepository(r.Context(), user, subscriptionID, siteID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save Git repository", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "git_repository.saved", "git_repository", id, map[string]any{"site_id": siteID, "mode": input.Mode})
	http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(siteID, 10)+"/git?notice=service-saved"), http.StatusSeeOther)
}

func (s *Server) gitDeploymentServices(w http.ResponseWriter) (GitDeploymentServices, bool) {
	services, ok := s.domains.(GitDeploymentServices)
	if !ok {
		http.Error(w, "Git deployment is not configured", http.StatusServiceUnavailable)
	}
	return services, ok
}

func (s *Server) handleGitDeploy(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.gitDeploymentServices(w)
	if !ok {
		return
	}
	siteID, err := parsePositivePathID(r, "id")
	if err != nil || r.ParseForm() != nil {
		http.Error(w, "Invalid Git deployment", http.StatusBadRequest)
		return
	}
	subscriptionID := parseFormInt64Default(r, "subscription_id", 0)
	deploymentID, err := services.QueueGitDeployment(r.Context(), user, subscriptionID, siteID)
	if err != nil {
		writeQuotaError(w, r, "Could not queue Git deployment", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "git.deployment_queued", "git_deployment", deploymentID, map[string]any{"site_id": siteID})
	http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(siteID, 10)+"/git?notice=git-deploy-queued"), http.StatusSeeOther)
}

func (s *Server) handleGitWebhookRotate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.gitDeploymentServices(w)
	if !ok {
		return
	}
	siteID, err := parsePositivePathID(r, "id")
	if err != nil || r.ParseForm() != nil {
		http.Error(w, "Invalid Git webhook request", http.StatusBadRequest)
		return
	}
	subscriptionID := parseFormInt64Default(r, "subscription_id", 0)
	token, err := services.RotateGitWebhook(r.Context(), user, subscriptionID, siteID)
	if err != nil {
		writeQuotaError(w, r, "Could not rotate Git webhook", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "git.webhook_rotated", "site", siteID, nil)
	continuePath := supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(siteID, 10)+"/git")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte("<!doctype html><meta name=\"robots\" content=\"noindex\"><title>Git webhook</title><h1>Webhook credential rotated</h1><p>This URL is shown once.</p><pre>/git/hooks/" + strconv.FormatInt(siteID, 10) + "/" + html.EscapeString(token) + "</pre><p><a href=\"" + html.EscapeString(continuePath) + "\">Continue</a></p>"))
}

func (s *Server) handleGitWebhook(w http.ResponseWriter, r *http.Request) {
	services, ok := s.gitDeploymentServices(w)
	if !ok {
		return
	}
	siteID, err := parsePositivePathID(r, "siteID")
	token := strings.TrimSpace(r.PathValue("token"))
	if err != nil || len(token) != 64 {
		http.NotFound(w, r)
		return
	}
	if err := services.TriggerGitWebhook(r.Context(), siteID, token); err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleStagingOperation(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.domains.(StagingServices)
	if !ok {
		http.Error(w, "Staging is not configured", http.StatusServiceUnavailable)
		return
	}
	sourceSiteID, err := parsePositivePathID(r, "id")
	if err != nil || r.ParseForm() != nil {
		http.Error(w, "Invalid staging operation", http.StatusBadRequest)
		return
	}
	input := types.StagingOperationInput{
		SourceSiteID:    sourceSiteID,
		TargetSiteID:    parseFormInt64Default(r, "target_site_id", 0),
		Direction:       formStringDefault(r, "direction", "copy_to_staging"),
		IncludeDatabase: formBoolDefault(r, "include_database", false),
	}
	if input.Direction == "promote" && r.Form.Get("confirm") != "promote" {
		http.Error(w, "Type promote to confirm replacing the target", http.StatusBadRequest)
		return
	}
	_, err = services.QueueStagingOperation(r.Context(), user, input)
	if err != nil {
		writeQuotaError(w, r, "Could not queue staging operation", err)
		return
	}
	http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(sourceSiteID, 10)+"/staging?notice=staging-queued"), http.StatusSeeOther)
}

func (s *Server) handleSiteLogData(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.subscriptionServices(w)
	if !ok {
		return
	}
	siteID, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	result, err := services.ReadSiteLog(r.Context(), user, siteID, types.SiteLogRequest{
		Source: types.SiteLogSource(strings.TrimSpace(r.URL.Query().Get("source"))),
		Cursor: parseQueryInt64(r, "cursor"), LineLimit: int(parseQueryInt64(r, "limit")),
		ByteLimit: int(parseQueryInt64(r, "bytes")), Search: strings.TrimSpace(r.URL.Query().Get("q")),
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
	})
	if err != nil {
		writeQuotaError(w, r, "Could not read site log", err)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="nakpanel-site-log.txt"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(strings.Join(result.Lines, "\n") + "\n"))
		return
	}
	writeSPAJSON(w, http.StatusOK, result)
}

func (s *Server) handleRunScheduledTask(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	taskID, err := parsePositivePathID(r, "taskID")
	if err != nil {
		http.Error(w, "Invalid scheduled task", http.StatusBadRequest)
		return
	}
	run, err := services.RunScheduledTask(r.Context(), user, subscriptionID, taskID)
	if err != nil {
		writeQuotaError(w, r, "Could not run scheduled task", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "scheduled_task.ran", "scheduled_task", taskID, map[string]any{"run_id": run.ID, "status": run.Status})
	if siteID := parseFormInt64Default(r, "site_id", 0); siteID > 0 {
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(siteID, 10)+"/scheduled-tasks?notice=task-ran"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/subscriptions/"+strconv.FormatInt(subscriptionID, 10)+"?tab=tasks&notice=task-ran", http.StatusSeeOther)
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
		Enabled: formBoolDefault(r, "enabled", true),
		DKIM:    formBoolDefault(r, "dkim", true), DMARCPolicy: policy, CatchAll: strings.TrimSpace(r.Form.Get("catch_all")),
	}
	if input.SiteID <= 0 {
		http.Error(w, "A hosted domain is required", http.StatusBadRequest)
		return
	}
	id, err := services.UpsertMailDomain(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save mail domain", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "mail_domain.saved", "mail_domain", id, nil)
	s.redirectSubscriptionService(w, r, user, subscriptionID, "mail")
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
	s.redirectSubscriptionService(w, r, user, subscriptionID, "mail")
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
	s.redirectSubscriptionService(w, r, user, subscriptionID, "mail")
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
	secrets := make(map[string]string)
	rawSecrets := strings.TrimSpace(r.Form.Get("secrets"))
	if rawSecrets != "" {
		if err := json.Unmarshal([]byte(rawSecrets), &secrets); err != nil {
			http.Error(w, "Secrets must be a JSON object of string values", http.StatusBadRequest)
			return
		}
	}
	var volumes []types.ApplicationVolumeSpec
	volumeName := strings.TrimSpace(r.Form.Get("volume_name"))
	volumeTarget := strings.TrimSpace(r.Form.Get("volume_target"))
	volumeSizeRaw := strings.TrimSpace(r.Form.Get("volume_size_mb"))
	if volumeName != "" || volumeTarget != "" || volumeSizeRaw != "" {
		volumeSize, err := strconv.Atoi(volumeSizeRaw)
		if err != nil || volumeName == "" || volumeTarget == "" || volumeSize <= 0 {
			http.Error(w, "Persistent storage requires a name, absolute container path, and positive size", http.StatusBadRequest)
			return
		}
		volumes = append(volumes, types.ApplicationVolumeSpec{
			Name: volumeName, Target: volumeTarget, SizeMB: volumeSize,
			ReadOnly: formBoolDefault(r, "volume_read_only", false),
		})
	}
	input := types.ApplicationInput{
		ID: parseFormInt64Default(r, "resource_id", 0), SiteID: parseFormInt64Default(r, "site_id", 0),
		Name: strings.TrimSpace(r.Form.Get("name")), Runtime: strings.TrimSpace(r.Form.Get("runtime")),
		CatalogSlug: strings.TrimSpace(r.Form.Get("catalog_slug")), ImageRef: strings.TrimSpace(r.Form.Get("image_ref")),
		DesiredState:         formStringDefault(r, "desired_state", "running"),
		RouteMode:            formStringDefault(r, "route_mode", types.ApplicationRoutePrefix),
		RoutePrefix:          strings.TrimSpace(r.Form.Get("route_prefix")),
		ContainerPort:        parseFormIntDefault(r, "container_port", 8080),
		HealthKind:           formStringDefault(r, "health_kind", types.ApplicationHealthHTTP),
		HealthPath:           strings.TrimSpace(r.Form.Get("health_path")),
		HealthTimeoutSeconds: parseFormIntDefault(r, "health_timeout_seconds", 30),
		Environment:          environment, Secrets: secrets, Volumes: volumes,
	}
	id, err := services.UpsertApplication(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save application", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "application.saved", "application", id, nil)
	if (r.Form.Get("return_to") == "site-applications" || r.Form.Get("return_to") == "site-containers") && input.SiteID > 0 {
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(input.SiteID, 10)+"/containers?notice=service-saved"), http.StatusSeeOther)
		return
	}
	s.redirectSubscriptionService(w, r, user, subscriptionID, "applications")
}

func (s *Server) handleApplicationAction(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	lifecycle, ok := services.(ApplicationLifecycleServices)
	if !ok {
		http.Error(w, "Container lifecycle is unavailable", http.StatusServiceUnavailable)
		return
	}
	applicationID, err := parsePositivePathID(r, "applicationID")
	if err != nil {
		http.Error(w, "Invalid container", http.StatusBadRequest)
		return
	}
	action := strings.ToLower(strings.TrimSpace(r.Form.Get("action")))
	if err = lifecycle.SetApplicationAction(r.Context(), user, subscriptionID, applicationID, action); err != nil {
		writeQuotaError(w, r, "Could not update container", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "container."+action, "application", applicationID, nil)
	siteID := parseFormInt64Default(r, "site_id", 0)
	if siteID > 0 {
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(siteID, 10)+
			"/containers/"+strconv.FormatInt(applicationID, 10)+"?notice=service-saved"), http.StatusSeeOther)
		return
	}
	s.redirectSubscriptionService(w, r, user, subscriptionID, "containers")
}

func (s *Server) handleApplicationPreset(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		return
	}
	services, ok := s.domains.(ApplicationPresetServices)
	if !ok {
		http.Error(w, "Application presets are not configured", http.StatusServiceUnavailable)
		return
	}
	if r.ParseForm() != nil {
		http.Error(w, "Invalid application preset", http.StatusBadRequest)
		return
	}
	var volumes []types.ApplicationVolumeSpec
	if raw := strings.TrimSpace(r.Form.Get("volumes")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &volumes); err != nil {
			http.Error(w, "Volume slots must be a JSON array", http.StatusBadRequest)
			return
		}
	}
	input := types.ApplicationPresetInput{
		ID: parseFormInt64Default(r, "resource_id", 0), Slug: strings.TrimSpace(r.Form.Get("slug")),
		Name: strings.TrimSpace(r.Form.Get("name")), Runtime: strings.TrimSpace(r.Form.Get("runtime")),
		ImageRef: strings.TrimSpace(r.Form.Get("image_ref")), Active: formBoolDefault(r, "active", true),
		Manifest: types.ApplicationManifestRevision{
			Runtime: strings.TrimSpace(r.Form.Get("runtime")), ImageRef: strings.TrimSpace(r.Form.Get("image_ref")),
			ReadOnlyRoot: true,
			Endpoint:     types.ApplicationEndpointSpec{ContainerPort: parseFormIntDefault(r, "container_port", 8080)},
			Health: types.ApplicationHealthSpec{
				Kind:           formStringDefault(r, "health_kind", types.ApplicationHealthHTTP),
				Path:           formStringDefault(r, "health_path", "/healthz"),
				TimeoutSeconds: parseFormIntDefault(r, "health_timeout_seconds", 30),
			},
			Volumes: volumes,
		},
	}
	id, err := services.UpsertApplicationPreset(r.Context(), user, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save application preset", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, 0, "application_preset.saved", "application_preset", id, map[string]any{"slug": input.Slug, "runtime": input.Runtime, "active": input.Active})
	siteID := parseFormInt64Default(r, "site_id", 0)
	if siteID > 0 {
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(siteID, 10)+"/containers?notice=service-saved"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/tools-settings/application-catalog?notice=service-saved", http.StatusSeeOther)
}

func (s *Server) handleProtectedDirectory(w http.ResponseWriter, r *http.Request) {
	user, subscriptionID, services, ok := s.subscriptionServiceRequest(w, r)
	if !ok {
		return
	}
	input := types.ProtectedDirectoryInput{
		ID:       parseFormInt64Default(r, "resource_id", 0),
		SiteID:   parseFormInt64Default(r, "site_id", 0),
		Path:     strings.TrimSpace(r.Form.Get("path")),
		Realm:    strings.TrimSpace(r.Form.Get("realm")),
		Username: strings.TrimSpace(r.Form.Get("username")),
		Password: r.Form.Get("password"),
		Enabled:  formBoolDefault(r, "enabled", true),
	}
	id, password, err := services.UpsertProtectedDirectory(r.Context(), user, subscriptionID, input)
	if err != nil {
		writeQuotaError(w, r, "Could not save protected directory", err)
		return
	}
	s.recordAudit(r.Context(), user, 0, subscriptionID, "protected_directory.saved", "protected_directory", id, map[string]any{
		"site_id": input.SiteID, "path": input.Path, "enabled": input.Enabled,
	})
	continuePath := "/subscriptions/" + strconv.FormatInt(subscriptionID, 10) + "/access"
	if r.Form.Get("return_to") == "site-access" && input.SiteID > 0 {
		continuePath = "/sites/" + strconv.FormatInt(input.SiteID, 10) + "/access"
	}
	continuePath = supportRedirectPath(r, user, continuePath)
	if password == "" {
		http.Redirect(w, r, continuePath+"?notice=service-saved", http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte("<!doctype html><meta name=\"robots\" content=\"noindex\"><title>Protected directory credential</title><h1>Protected directory saved</h1><p>This password is shown once.</p><pre>" + html.EscapeString(password) + "</pre><p><a href=\"" + html.EscapeString(continuePath) + "\">Continue</a></p>"))
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
	tab := map[string]string{"sftp": "access", "ftp": "access", "protected": "access", "task": "tasks", "mail": "mail", "mailbox": "mail", "mail_alias": "mail", "application": "containers"}[kind]
	s.redirectSubscriptionService(w, r, user, subscriptionID, tab)
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

func (s *Server) redirectSubscriptionService(w http.ResponseWriter, r *http.Request, user auth.SessionUser, subscriptionID int64, tab string) {
	siteReturnTabs := map[string]string{
		"site-access":       "access",
		"site-tasks":        "scheduled-tasks",
		"site-applications": "applications",
		"site-containers":   "containers",
		"site-redis":        "redis",
	}
	if siteTab, ok := siteReturnTabs[r.Form.Get("return_to")]; ok {
		siteID := parseFormInt64Default(r, "site_id", 0)
		if siteID > 0 {
			http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(siteID, 10)+"/"+siteTab+"?notice=service-saved"), http.StatusSeeOther)
			return
		}
	}
	if r.Form.Get("return_to") == "site-mail" {
		s.redirectSiteMail(w, r, user, parseFormInt64Default(r, "site_id", 0), subscriptionID, "", "service-saved")
		return
	}
	if r.Form.Get("return_to") == "mail" {
		http.Redirect(w, r, "/mail?subscription_id="+strconv.FormatInt(subscriptionID, 10)+"&notice=service-saved", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, supportRedirectPath(r, user, "/subscriptions/"+strconv.FormatInt(subscriptionID, 10)+"?tab="+tab+"&notice=service-saved"), http.StatusSeeOther)
}
