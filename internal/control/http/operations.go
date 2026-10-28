package panelhttp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/control/web"
	"net/http"
	"strconv"
)

type OperationsService interface {
	Page(context.Context, auth.SessionUser, string, operations.Filter) (operations.Page, error)
	Feed(context.Context, auth.SessionUser, int64, operations.Filter) (operations.Feed, error)
	Issue(context.Context, auth.SessionUser, int64) (operations.Issue, error)
	Operation(context.Context, auth.SessionUser, int64) (operations.OperationDetail, error)
	Notification(context.Context, auth.SessionUser, int64, operations.Resource) (operations.Notification, error)
	MarkNotificationRead(context.Context, auth.SessionUser, int64) error
	MarkAllNotificationsRead(context.Context, auth.SessionUser, operations.Filter) error
	ArchiveNotification(context.Context, auth.SessionUser, int64) error
	AcknowledgeIssue(context.Context, auth.SessionUser, int64) error
}

func (s *Server) operationsUser(w http.ResponseWriter, r *http.Request) (auth.SessionUser, bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	actor, ok := s.currentUser(w, r, func() { http.Error(w, "Unauthorized", http.StatusUnauthorized) })
	if !ok {
		return actor, false
	}
	if s.operations == nil {
		http.Error(w, "Operations are temporarily unavailable", http.StatusServiceUnavailable)
		return actor, false
	}
	return actor, true
}
func operationsFilter(r *http.Request) (operations.Filter, error) {
	q := r.URL.Query()
	f := operations.Filter{Resource: operations.Resource{Kind: operations.ResourceKind(q.Get("resource_kind"))}, Search: q.Get("q"), Status: q.Get("status"), Severity: q.Get("severity")}
	var err error
	if q.Has("resource_id") {
		f.Resource.ID, err = strconv.ParseInt(q.Get("resource_id"), 10, 64)
		if err != nil || f.Resource.Kind == "" {
			return f, operations.ErrInvalid
		}
	}
	if f.Resource.Kind != "" && !f.Resource.Valid() {
		return f, operations.ErrInvalid
	}
	if q.Has("before") {
		f.Before, err = strconv.ParseInt(q.Get("before"), 10, 64)
		if err != nil || f.Before < 0 {
			return f, operations.ErrInvalid
		}
	}
	if q.Has("limit") {
		f.Limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || f.Limit < 1 || f.Limit > 200 {
			return f, operations.ErrInvalid
		}
	}
	if len(f.Search) > 200 {
		return f, operations.ErrInvalid
	}
	return f, nil
}
func operationsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, operations.ErrNotFound):
		http.Error(w, "Not found", http.StatusNotFound)
	case errors.Is(err, operations.ErrInvalid):
		http.Error(w, "Invalid operations request", http.StatusBadRequest)
	case errors.Is(err, operations.ErrConflict):
		http.Error(w, "The resource changed. Refresh and check again.", http.StatusConflict)
	default:
		http.Error(w, "Operations are temporarily unavailable", http.StatusServiceUnavailable)
	}
}
func (s *Server) handleOperations(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	f, err := operationsFilter(r)
	if err != nil {
		operationsError(w, err)
		return
	}
	view := r.URL.Query().Get("view")
	if view == "" {
		view = "issues"
	}
	switch view {
	case "issues", "tasks", "history", "inbox":
	default:
		operationsError(w, operations.ErrInvalid)
		return
	}
	p, err := s.operations.Page(r.Context(), actor, view, f)
	if err != nil {
		operationsError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(p)
}
func (s *Server) handleOperationEvents(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	f, err := operationsFilter(r)
	if err != nil {
		operationsError(w, err)
		return
	}
	var after int64
	if value := r.URL.Query().Get("after"); value != "" {
		after, err = strconv.ParseInt(value, 10, 64)
		if err != nil || after < 0 {
			operationsError(w, operations.ErrInvalid)
			return
		}
	}
	p, err := s.operations.Feed(r.Context(), actor, after, f)
	if err != nil {
		operationsError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(p)
}
func (s *Server) handleOperationDetail(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		operationsError(w, operations.ErrInvalid)
		return
	}
	var result any
	if r.PathValue("type") == "issues" {
		var issue operations.Issue
		issue, err = s.operations.Issue(r.Context(), actor, id)
		if err == nil {
			result = web.DescribeOperationIssue(actor, issue)
		}
	} else if r.PathValue("type") == "tasks" {
		result, err = s.operations.Operation(r.Context(), actor, id)
	} else {
		operationsError(w, operations.ErrNotFound)
		return
	}
	if err != nil {
		operationsError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
func (s *Server) handleOperationReceipt(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		operationsError(w, operations.ErrInvalid)
		return
	}
	switch r.PathValue("action") {
	case "read":
		err = s.operations.MarkNotificationRead(r.Context(), actor, id)
	case "archive":
		err = s.operations.ArchiveNotification(r.Context(), actor, id)
	default:
		err = operations.ErrNotFound
	}
	if err != nil {
		operationsError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleOperationNotification(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		operationsError(w, operations.ErrInvalid)
		return
	}
	f, err := operationsFilter(r)
	if err != nil {
		operationsError(w, err)
		return
	}
	n, err := s.operations.Notification(r.Context(), actor, id, f.Resource)
	if err != nil {
		operationsError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(n)
}
func (s *Server) handleOperationsReadAll(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	f, err := operationsFilter(r)
	if err == nil {
		err = s.operations.MarkAllNotificationsRead(r.Context(), actor, f)
	}
	if err != nil {
		operationsError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleIssueAcknowledge(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		operationsError(w, operations.ErrInvalid)
		return
	}
	if err = s.operations.AcknowledgeIssue(r.Context(), actor, id); err != nil {
		operationsError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type OperationsRecoveryService interface {
	Preflight(context.Context, auth.SessionUser, int64) (provision.RecoveryPreflight, error)
	Recover(context.Context, auth.SessionUser, int64, string) (provision.RecoveryStarted, error)
	RequestVerification(context.Context, auth.SessionUser, int64) error
}

func (s *Server) handleIssueRecovery(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	service, ok := s.operations.(OperationsRecoveryService)
	if !ok {
		operationsError(w, errors.New("unavailable"))
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		operationsError(w, operations.ErrInvalid)
		return
	}
	action := r.PathValue("action")
	if (action == "preflight" && r.Method != "GET") || (action != "preflight" && r.Method != "POST") {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if action != "verify" && actor.Role != auth.RoleAdmin {
		operationsError(w, operations.ErrNotFound)
		return
	}
	switch action {
	case "preflight":
		p, err := service.Preflight(r.Context(), actor, id)
		if err != nil {
			operationsError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(p)
	case "recover":
		var body struct {
			Confirmation string `json:"confirmation"`
			Confirmed    bool   `json:"confirmed"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || !body.Confirmed || body.Confirmation == "" {
			operationsError(w, operations.ErrInvalid)
			return
		}
		result, err := service.Recover(r.Context(), actor, id, body.Confirmation)
		if err != nil {
			operationsError(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(result)
	case "verify":
		if err = service.RequestVerification(r.Context(), actor, id); err != nil {
			operationsError(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{"queued": true})
	default:
		operationsError(w, operations.ErrNotFound)
	}
}

func (s *Server) loadOperationsView(r *http.Request, actor auth.SessionUser, view *web.WorkspaceView) {
	view.OperationsTab = r.URL.Query().Get("tab")
	switch view.OperationsTab {
	case "issues", "tasks", "history", "inbox", "preferences":
	default:
		view.OperationsTab = "issues"
	}
	if s.operations == nil {
		view.OperationsError = "Current status is unavailable. Check again shortly."
		return
	}
	f := operations.Filter{Limit: 25}
	if view.SelectedSubscription > 0 {
		f.Resource = operations.Resource{Kind: operations.ResourceSubscription, ID: view.SelectedSubscription}
	} else if view.SupportCustomerID > 0 {
		f.Resource = operations.Resource{Kind: operations.ResourceCustomer, ID: view.SupportCustomerID}
	}
	tab := "issues"
	if view.Route == "activity" && view.OperationsTab != "preferences" {
		tab = view.OperationsTab
		f.Search = r.URL.Query().Get("q")
		f.Status = r.URL.Query().Get("status")
		f.Severity = r.URL.Query().Get("severity")
		f.Before = parseQueryInt64(r, "before")
	}
	p, err := s.operations.Page(r.Context(), actor, tab, f)
	if err != nil {
		view.OperationsError = "Current status is unavailable. Check again shortly."
		return
	}
	view.Operations = p
	f.ActiveFirst = true
	f.Before = 0
	f.Search = ""
	f.Status = ""
	f.Severity = ""
	f.Limit = 8
	view.OperationsQuick, err = s.operations.Page(r.Context(), actor, "tasks", f)
	if err != nil {
		view.OperationsError = "Task status is unavailable. Check again shortly."
	}
	f.ActiveFirst = false
	f.Limit = 5
	view.OperationsInbox, err = s.operations.Page(r.Context(), actor, "inbox", f)
	if err != nil {
		view.OperationsError = "Notification status is unavailable. Check again shortly."
	}
}

type OperationsPreferencesService interface {
	Preferences(context.Context, auth.SessionUser) (operations.Preferences, error)
	SavePreferences(context.Context, auth.SessionUser, operations.Preferences) error
	DeliveryPolicy(context.Context, auth.SessionUser) (operations.DeliveryPolicy, error)
	SaveDeliveryPolicy(context.Context, auth.SessionUser, operations.DeliveryPolicy) error
}

func (s *Server) handleOperationsPreferences(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.operationsUser(w, r)
	if !ok {
		return
	}
	service, ok := s.operations.(OperationsPreferencesService)
	if !ok {
		operationsError(w, errors.New("unavailable"))
		return
	}
	policy := r.URL.Path == "/api/workspace/operations/delivery-policy"
	if policy && actor.Role != auth.RoleAdmin {
		operationsError(w, operations.ErrNotFound)
		return
	}
	if r.Method == "GET" {
		var p any
		var err error
		if policy {
			p, err = service.DeliveryPolicy(r.Context(), actor)
		} else {
			p, err = service.Preferences(r.Context(), actor)
		}
		if err != nil {
			operationsError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(p)
		return
	}
	decode := func(v any) error {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		d.DisallowUnknownFields()
		return d.Decode(v)
	}
	if policy {
		var p struct {
			Enabled *bool `json:"enabled"`
		}
		if decode(&p) != nil || p.Enabled == nil {
			operationsError(w, operations.ErrInvalid)
			return
		}
		if err := service.SaveDeliveryPolicy(r.Context(), actor, operations.DeliveryPolicy{Enabled: *p.Enabled}); err != nil {
			operationsError(w, err)
			return
		}
	} else {
		var p struct {
			EmailMode string `json:"email_mode"`
		}
		if decode(&p) != nil {
			operationsError(w, operations.ErrInvalid)
			return
		}
		if err := service.SavePreferences(r.Context(), actor, operations.Preferences{EmailMode: p.EmailMode}); err != nil {
			operationsError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
