package panelhttp

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/gitremote"
	"github.com/nakroteck/nakpanel/internal/types"
)

type gitWorkspaceOperations interface {
	QueueGitWorkspaceOperation(context.Context, auth.SessionUser, int64, int64, types.GitWorkspaceOperationInput) (int64, error)
}

func (s *Server) handleGitKey(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		writeSPAError(w, 400, "Invalid repository URL.")
		return
	}
	user, site, _, ok := s.gitWorkspaceTarget(w, r)
	if !ok {
		return
	}
	service, ok := s.domains.(interface {
		PrepareGitKey(context.Context, auth.SessionUser, int64, int64, string) (string, error)
	})
	if !ok {
		writeSPAError(w, 503, "Git key preparation is unavailable.")
		return
	}
	remote := strings.TrimSpace(r.Form.Get("remote_url"))
	key, err := service.PrepareGitKey(r.Context(), user, site.SubscriptionID, site.ID, remote)
	if err != nil {
		writeQuotaError(w, r, "Could not prepare SSH key", err)
		return
	}
	s.recordAudit(r.Context(), user, site.CustomerID, site.SubscriptionID, "git.key_prepared", "site", site.ID, nil)
	writeSPAJSON(w, 200, map[string]any{"ok": true, "public_key": key, "key_title": gitremote.KeyTitle(site.Domain, remote, site.ID), "key_fingerprint": gitremote.PublicKeyFingerprint(key), "trusted_host_key": gitremote.TrustedHostKey(remote)})
}

func (s *Server) gitWorkspaceTarget(w http.ResponseWriter, r *http.Request) (auth.SessionUser, dashboard.Site, dashboard.Data, bool) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return user, dashboard.Site{}, dashboard.Data{}, false
	}
	var supportCustomerID int64
	if raw := r.PathValue("customerID"); raw != "" {
		var err error
		supportCustomerID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || supportCustomerID <= 0 || user.Role != auth.RoleAdmin {
			http.NotFound(w, r)
			return user, dashboard.Site{}, dashboard.Data{}, false
		}
	}
	id, err := parsePositivePathID(r, "id")
	if err != nil {
		http.NotFound(w, r)
		return user, dashboard.Site{}, dashboard.Data{}, false
	}
	data, err := s.loadDashboard(r.Context(), user)
	if err != nil {
		http.Error(w, "Could not load Git workspace", http.StatusServiceUnavailable)
		return user, dashboard.Site{}, data, false
	}
	for _, site := range data.Sites {
		if site.ID == id {
			if supportCustomerID > 0 && site.CustomerID != supportCustomerID {
				break
			}
			if !databaseSupportScopeAllowed(r, user, site.CustomerID) {
				break
			}
			if raw := strings.TrimSpace(r.FormValue("subscription_id")); raw != "" {
				submitted, e := strconv.ParseInt(raw, 10, 64)
				if e != nil || submitted != site.SubscriptionID {
					break
				}
			}
			return user, site, data, true
		}
	}
	http.NotFound(w, r)
	return user, dashboard.Site{}, data, false
}

func (s *Server) handleGitStatus(w http.ResponseWriter, r *http.Request) {
	_, site, data, ok := s.gitWorkspaceTarget(w, r)
	if !ok {
		return
	}
	var repository *types.GitRepository
	deployments := []types.GitDeployment{}
	for _, candidate := range data.SubscriptionServices.Git {
		if candidate.SiteID == site.ID {
			item := candidate
			repository = &item
			break
		}
	}
	if repository != nil {
		for _, item := range data.SubscriptionServices.GitDeployments {
			if item.RepositoryID == repository.ID {
				deployments = append(deployments, item)
			}
		}
	}
	title, fingerprint := "", ""
	if repository != nil {
		title = gitremote.KeyTitle(site.Domain, repository.RemoteURL, site.ID)
		fingerprint = gitremote.PublicKeyFingerprint(repository.DeployPublicKey)
	}
	writeSPAJSON(w, 200, map[string]any{"ok": true, "site_id": site.ID, "repository": repository, "deployments": deployments, "key_title": title, "key_fingerprint": fingerprint})
}

func (s *Server) handleGitWorkspaceAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() != nil {
			writeSPAError(w, 400, "Invalid Git form.")
			return
		}
		user, site, _, ok := s.gitWorkspaceTarget(w, r)
		if !ok {
			return
		}
		service, ok := s.domains.(gitWorkspaceOperations)
		if !ok {
			writeSPAError(w, 503, "Git workspace operations are unavailable.")
			return
		}
		expected, err := strconv.ParseInt(r.Form.Get("expected_revision"), 10, 64)
		if err != nil || expected < 0 {
			writeSPAError(w, 400, "Refresh the Git workspace before continuing.")
			return
		}
		confirm := r.Form.Get("confirm") == "yes"
		if (action == "deploy" || action == "rollback" || action == "disconnect") && !confirm {
			writeSPAError(w, 400, "Confirm the effect on published code before continuing.")
			return
		}
		input := types.GitWorkspaceOperationInput{Action: action, Revision: strings.TrimSpace(r.Form.Get("revision")), ExpectedRevision: expected, ConfirmOverwrite: confirm, IdempotencyKey: strings.TrimSpace(r.Form.Get("idempotency_key"))}
		id, err := service.QueueGitWorkspaceOperation(r.Context(), user, site.SubscriptionID, site.ID, input)
		if err != nil {
			writeQuotaError(w, r, "Could not queue Git operation", err)
			return
		}
		s.recordAudit(r.Context(), user, site.CustomerID, site.SubscriptionID, "git."+action+"_queued", "git_deployment", id, map[string]any{"site_id": site.ID})
		if wantsSPAJSON(r) {
			writeSPAJSON(w, 202, map[string]any{"ok": true, "operation_id": id, "notice": "Git operation queued. Progress will update automatically."})
			return
		}
		http.Redirect(w, r, supportRedirectPath(r, user, "/sites/"+strconv.FormatInt(site.ID, 10)+"/git?notice=git-deploy-queued"), 303)
	}
}
