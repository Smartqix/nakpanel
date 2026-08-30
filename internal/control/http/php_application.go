package panelhttp

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlphpapp "github.com/nakroteck/nakpanel/internal/control/phpapp"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"github.com/nakroteck/nakpanel/internal/types"
)

const (
	maxPHPApplicationString = 4096
	maxPHPEnvironmentValue  = 64 << 10
	maxPHPSharedPaths       = 16
	maxPHPWorkerArguments   = 64
)

func (s *Server) loadPHPApplicationWorkspace(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, siteID int64, view *web.WorkspaceView) bool {
	if s.phpApplications == nil {
		http.Error(w, "PHP application management is unavailable", http.StatusServiceUnavailable)
		return false
	}
	workspace, err := s.phpApplications.Workspace(r.Context(), actor, siteID)
	if err != nil {
		if errors.Is(err, controlphpapp.ErrNotFound) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "PHP application workspace is unavailable", http.StatusServiceUnavailable)
		}
		return false
	}
	workspace = sanitizedPHPWorkspace(workspace)
	view.PHPApplication = &workspace
	return true
}

func sanitizedPHPWorkspace(workspace controlphpapp.Workspace) controlphpapp.Workspace {
	workspace.LastError = boundedSafeText(workspace.LastError, 512)
	workspace.ObservedMessage = boundedSafeText(workspace.ObservedMessage, 512)
	for index := range workspace.Environment {
		if workspace.Environment[index].SecretID > 0 {
			workspace.Environment[index].Value = ""
		}
	}
	for index := range workspace.Deployments {
		workspace.Deployments[index].LastError = boundedSafeText(workspace.Deployments[index].LastError, 512)
		workspace.Deployments[index].HealthMessage = boundedSafeText(workspace.Deployments[index].HealthMessage, 512)
		workspace.Deployments[index].ComposerAudit = boundedSafeText(workspace.Deployments[index].ComposerAudit, 4096)
	}
	for index := range workspace.Workers {
		workspace.Workers[index].LastError = boundedSafeText(workspace.Workers[index].LastError, 512)
	}
	capabilities := sanitizedPHPCapabilities(types.RuntimeCapabilities{PHPRuntimes: []types.PHPRuntimeCapability{workspace.Runtime}})
	if len(capabilities.PHPRuntimes) == 1 {
		workspace.Runtime = capabilities.PHPRuntimes[0]
	}
	return workspace
}

func (s *Server) loadPHPRuntimeInventory(w http.ResponseWriter, r *http.Request, view *web.WorkspaceView) bool {
	if s.phpApplications == nil {
		http.Error(w, "PHP runtime inventory is unavailable", http.StatusServiceUnavailable)
		return false
	}
	capabilities, err := s.phpApplications.RuntimeCapabilities(r.Context())
	if err != nil {
		http.Error(w, "PHP runtime inventory is unavailable", http.StatusServiceUnavailable)
		return false
	}
	capabilities = sanitizedPHPCapabilities(capabilities)
	view.PHPRuntimeInventory = &capabilities
	return true
}

func sanitizedPHPCapabilities(capabilities types.RuntimeCapabilities) types.RuntimeCapabilities {
	for index := range capabilities.PHPRuntimes {
		errors := capabilities.PHPRuntimes[index].ValidationErrors
		if len(errors) > 8 {
			errors = errors[:8]
		}
		for errorIndex, message := range errors {
			errors[errorIndex] = boundedSafeText(message, 160)
		}
		capabilities.PHPRuntimes[index].ValidationErrors = errors
	}
	return capabilities
}

func (s *Server) handleConfigurePHPApplication(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP application settings")
		return
	}
	repositoryID, err := optionalPositiveFormID(r, "repository_id")
	if err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP application settings")
		return
	}
	retention, err := boundedFormInt(r, "release_retention", 0, 0, 100)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP application settings")
		return
	}
	sharedPaths, err := boundedFormList(r, "shared_path", "shared_paths", maxPHPSharedPaths, 240, 3840)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP application settings")
		return
	}
	input := controlphpapp.ConfigureApplicationInput{
		HostingMode:      types.PHPHostingMode(strings.ToLower(strings.TrimSpace(r.Form.Get("hosting_mode")))),
		PHPVersion:       boundedFormString(r, "php_version", 16),
		RepositoryID:     repositoryID,
		RepositoryRef:    boundedFormString(r, "repository_ref", 128),
		FrameworkProfile: types.PHPFrameworkProfile(strings.ToLower(boundedFormString(r, "framework_profile", 16))),
		PublicPath:       boundedFormString(r, "public_path", 240),
		HealthPath:       boundedFormString(r, "health_path", 240),
		SharedPaths:      sharedPaths,
		ReleaseRetention: retention,
		Composer: types.PHPComposerSpec{
			Install: parseFormBool(r, "composer_install"), AllowScripts: parseFormBool(r, "composer_allow_scripts"),
			AllowPlugins: parseFormBool(r, "composer_allow_plugins"),
		},
	}
	if input.PHPVersion == "" || input.HostingMode == "" || formFieldTooLong(r, maxPHPApplicationString) {
		s.writePHPApplicationError(w, r, errors.New("invalid settings"), "Invalid PHP application settings")
		return
	}
	application, err := s.phpApplications.ConfigureApplication(r.Context(), actor, siteID, input)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "PHP application settings could not be saved")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.application.http_configured", "site", siteID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusOK, "php-application-saved", map[string]any{"ok": true, "application_id": application.ApplicationID})
}

func (s *Server) handleQueuePHPDeployment(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid deployment request")
		return
	}
	revision := boundedFormString(r, "revision", 128)
	if len(strings.TrimSpace(r.Form.Get("revision"))) > 128 {
		s.writePHPApplicationError(w, r, errors.New("revision too long"), "Invalid deployment request")
		return
	}
	deployment, err := s.phpApplications.QueueDeployment(r.Context(), actor, siteID, controlphpapp.DeploymentInput{RequestedRevision: revision})
	if err != nil {
		s.writePHPApplicationError(w, r, err, "PHP deployment could not be queued")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.deployment.http_queued", "php_deployment", deployment.ID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusAccepted, "php-deployment-queued", map[string]any{"ok": true, "deployment_id": deployment.ID, "status": deployment.Status})
}

func (s *Server) handleQueuePHPRollback(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return
	}
	deploymentID, err := parsePositivePathID(r, "deploymentID")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err = r.ParseForm(); err != nil || strings.ToLower(strings.TrimSpace(r.Form.Get("confirm"))) != "rollback" {
		s.writePHPApplicationError(w, r, errors.New("confirmation required"), "Rollback confirmation is required")
		return
	}
	deployment, err := s.phpApplications.QueueRollback(r.Context(), actor, siteID, deploymentID)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "PHP rollback could not be queued")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.deployment.http_rollback_queued", "php_deployment", deployment.ID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusAccepted, "php-rollback-queued", map[string]any{"ok": true, "deployment_id": deployment.ID, "status": deployment.Status})
}

func (s *Server) handleUpsertPHPEnvironment(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid environment variable")
		return
	}
	plainValue, secretValue := r.Form.Get("value"), r.Form.Get("secret_value")
	secret := parseFormBool(r, "secret") || secretValue != ""
	if len(plainValue) > maxPHPEnvironmentValue || len(secretValue) > maxPHPEnvironmentValue ||
		(secret && (secretValue == "" || plainValue != "")) || (!secret && secretValue != "") {
		s.writePHPApplicationError(w, r, errors.New("invalid environment value"), "Invalid environment variable")
		return
	}
	value := plainValue
	if secret {
		value = secretValue
	}
	input := controlphpapp.EnvironmentInput{Name: boundedFormString(r, "name", 128), Value: value, Secret: secret}
	if input.Name == "" || len(strings.TrimSpace(r.Form.Get("name"))) > 128 {
		s.writePHPApplicationError(w, r, errors.New("invalid environment name"), "Invalid environment variable")
		return
	}
	item, err := s.phpApplications.UpsertEnvironment(r.Context(), actor, siteID, input)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "Environment variable could not be saved")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.environment.http_upserted", "site", siteID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusOK, "php-environment-saved", map[string]any{"ok": true, "name": item.Name, "secret": secret})
}

func (s *Server) handleDeletePHPEnvironment(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil || strings.ToLower(strings.TrimSpace(r.Form.Get("confirm"))) != "delete" {
		s.writePHPApplicationError(w, r, errors.New("confirmation required"), "Delete confirmation is required")
		return
	}
	name := boundedFormString(r, "name", 128)
	if name == "" || len(strings.TrimSpace(r.Form.Get("name"))) > 128 {
		s.writePHPApplicationError(w, r, errors.New("invalid environment name"), "Invalid environment variable")
		return
	}
	if err := s.phpApplications.DeleteEnvironment(r.Context(), actor, siteID, name); err != nil {
		s.writePHPApplicationError(w, r, err, "Environment variable could not be deleted")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.environment.http_deleted", "site", siteID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusOK, "php-environment-deleted", map[string]any{"ok": true})
}

func (s *Server) handleUpsertPHPWorker(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP worker")
		return
	}
	workerID, err := optionalPositiveFormID(r, "worker_id")
	if err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP worker")
		return
	}
	processes, err := boundedFormInt(r, "processes", 0, 1, 64)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP worker")
		return
	}
	arguments, err := boundedFormList(r, "argument", "arguments", maxPHPWorkerArguments, 4096, 32<<10)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP worker")
		return
	}
	input := controlphpapp.WorkerInput{ID: workerID, Name: boundedFormString(r, "name", 48), Script: boundedFormString(r, "script", 240), Arguments: arguments, Processes: processes, DesiredState: strings.ToLower(boundedFormString(r, "desired_state", 16))}
	if input.Name == "" || input.Script == "" || formFieldTooLong(r, maxPHPApplicationString) {
		s.writePHPApplicationError(w, r, errors.New("invalid worker"), "Invalid PHP worker")
		return
	}
	worker, err := s.phpApplications.UpsertWorker(r.Context(), actor, siteID, input)
	if err != nil {
		s.writePHPApplicationError(w, r, err, "PHP worker could not be saved")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.worker.http_upserted", "php_worker", worker.ID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusOK, "php-worker-saved", map[string]any{"ok": true, "worker_id": worker.ID})
}

func (s *Server) handleSetPHPWorkerState(w http.ResponseWriter, r *http.Request) {
	actor, siteID, workerID, ok := s.phpWorkerMutationRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writePHPApplicationError(w, r, err, "Invalid PHP worker state")
		return
	}
	state := strings.ToLower(strings.TrimSpace(r.Form.Get("state")))
	if state != "running" && state != "stopped" {
		s.writePHPApplicationError(w, r, errors.New("invalid state"), "Invalid PHP worker state")
		return
	}
	if err := s.phpApplications.SetWorkerState(r.Context(), actor, siteID, workerID, state); err != nil {
		s.writePHPApplicationError(w, r, err, "PHP worker state could not be changed")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.worker.http_state_changed", "php_worker", workerID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusOK, "php-worker-state-saved", map[string]any{"ok": true, "worker_id": workerID, "state": state})
}

func (s *Server) handleDeletePHPWorker(w http.ResponseWriter, r *http.Request) {
	actor, siteID, workerID, ok := s.phpWorkerMutationRequest(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil || strings.ToLower(strings.TrimSpace(r.Form.Get("confirm"))) != "delete" {
		s.writePHPApplicationError(w, r, errors.New("confirmation required"), "Delete confirmation is required")
		return
	}
	if err := s.phpApplications.DeleteWorker(r.Context(), actor, siteID, workerID); err != nil {
		s.writePHPApplicationError(w, r, err, "PHP worker could not be deleted")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.worker.http_deleted", "php_worker", workerID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusOK, "php-worker-deleted", map[string]any{"ok": true})
}

func (s *Server) handleReconcilePHPApplication(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return
	}
	if err := s.phpApplications.RequestReconcile(r.Context(), actor, siteID); err != nil {
		s.writePHPApplicationError(w, r, err, "PHP application reconciliation could not be queued")
		return
	}
	s.recordAudit(r.Context(), actor, 0, 0, "php.application.http_reconcile_queued", "site", siteID, nil)
	s.writePHPApplicationSuccess(w, r, actor, siteID, http.StatusAccepted, "php-reconcile-queued", map[string]any{"ok": true, "status": "pending"})
}

func (s *Server) phpApplicationMutationRequest(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, bool) {
	actor, ok := s.currentUser(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return auth.SessionUser{}, 0, false
	}
	siteID, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return auth.SessionUser{}, 0, false
	}
	if actor.Role == auth.RoleAdmin {
		if !s.phpSupportMutationVisible(w, r, actor, siteID) {
			return auth.SessionUser{}, 0, false
		}
	}
	if s.phpApplications == nil {
		s.writePHPApplicationError(w, r, errors.New("unconfigured"), "PHP application management is unavailable")
		return auth.SessionUser{}, 0, false
	}
	return actor, siteID, true
}

func (s *Server) phpSupportMutationVisible(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, siteID int64) bool {
	if err := r.ParseForm(); err != nil {
		s.writePHPApplicationError(w, r, errors.New("invalid form"), "Invalid support context")
		return false
	}
	raw := strings.TrimSpace(r.Form.Get("support_customer_id"))
	if raw == "" {
		return true
	}
	customerID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || customerID <= 0 || s.dashboard == nil {
		http.NotFound(w, r)
		return false
	}
	data, err := s.loadDashboard(r.Context(), actor)
	if err != nil {
		http.Error(w, "Could not validate support context", http.StatusInternalServerError)
		return false
	}
	for _, site := range data.Sites {
		if site.ID == siteID && site.CustomerID == customerID {
			return true
		}
	}
	http.NotFound(w, r)
	return false
}

func (s *Server) phpWorkerMutationRequest(w http.ResponseWriter, r *http.Request) (auth.SessionUser, int64, int64, bool) {
	actor, siteID, ok := s.phpApplicationMutationRequest(w, r)
	if !ok {
		return auth.SessionUser{}, 0, 0, false
	}
	workerID, err := parsePositivePathID(r, "workerID")
	if err != nil {
		http.NotFound(w, r)
		return auth.SessionUser{}, 0, 0, false
	}
	return actor, siteID, workerID, true
}

func (s *Server) writePHPApplicationSuccess(w http.ResponseWriter, r *http.Request, actor auth.SessionUser, siteID int64, status int, notice string, payload map[string]any) {
	if wantsSPAJSON(r) {
		writeSPAJSON(w, status, payload)
		return
	}
	target := "/sites/" + strconv.FormatInt(siteID, 10) + "/applications?notice=" + notice
	http.Redirect(w, r, supportRedirectPath(r, actor, target), http.StatusSeeOther)
}

func (s *Server) writePHPApplicationError(w http.ResponseWriter, r *http.Request, err error, message string) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, controlphpapp.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, controlphpapp.ErrInactive), errors.Is(err, controlphpapp.ErrRuntimeUnavailable),
		errors.Is(err, controlphpapp.ErrRevisionConflict), errors.Is(err, controlphpapp.ErrManagedToClassic):
		status = http.StatusConflict
	case errors.Is(err, controlquota.ErrExceeded):
		status = http.StatusBadRequest
	case errors.Is(err, controlphpapp.ErrInvalidInput):
		status = http.StatusBadRequest
	case errors.Is(err, serveradmin.ErrSecretUnavailable), err != nil && err.Error() == "unconfigured":
		status = http.StatusServiceUnavailable
	default:
		// Parsing/validation failures are created inside this HTTP layer. Any
		// other manager error is treated as infrastructure and never exposed.
		if err == nil || !isPHPHTTPValidationError(err) {
			status = http.StatusInternalServerError
			message = "PHP application operation failed"
		}
	}
	if wantsSPAJSON(r) {
		writeSPAError(w, status, message)
		return
	}
	http.Error(w, message, status)
}

func isPHPHTTPValidationError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.HasPrefix(message, "invalid ") || strings.Contains(message, "confirmation") ||
		strings.HasSuffix(message, " too long") || strings.Contains(message, " must be ") ||
		strings.Contains(message, " exceeds ") || strings.Contains(message, " at most ")
}

func optionalPositiveFormID(r *http.Request, name string) (int64, error) {
	raw := strings.TrimSpace(r.Form.Get(name))
	if raw == "" || raw == "0" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("invalid identifier")
	}
	return value, nil
}

func boundedFormInt(r *http.Request, name string, fallback, minimum, maximum int) (int, error) {
	raw := strings.TrimSpace(r.Form.Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, errors.New("invalid numeric value")
	}
	return value, nil
}

func boundedFormString(r *http.Request, name string, maximum int) string {
	value := strings.TrimSpace(r.Form.Get(name))
	if len(value) > maximum {
		return ""
	}
	return value
}

func boundedFormList(r *http.Request, repeatedName, linesName string, maximumItems, maximumItemBytes, maximumTotalBytes int) ([]string, error) {
	values := append([]string(nil), r.Form[repeatedName]...)
	if lines := r.Form.Get(linesName); lines != "" {
		values = append(values, strings.Split(strings.ReplaceAll(lines, "\r\n", "\n"), "\n")...)
	}
	result := make([]string, 0, len(values))
	total := 0
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		total += len(value)
		if len(value) > maximumItemBytes || total > maximumTotalBytes || strings.ContainsAny(value, "\x00\r\n") {
			return nil, errors.New("invalid list value")
		}
		result = append(result, value)
		if len(result) > maximumItems {
			return nil, errors.New("list exceeds maximum items")
		}
	}
	return result, nil
}

func formFieldTooLong(r *http.Request, maximum int) bool {
	for name, values := range r.Form {
		if name == "secret_value" || name == "value" || name == "csrf_token" {
			continue
		}
		for _, value := range values {
			if len(value) > maximum {
				return true
			}
		}
	}
	return false
}

func boundedSafeText(value string, maximum int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > maximum {
		value = value[:maximum]
	}
	return value
}
