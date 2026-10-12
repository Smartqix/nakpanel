package panelhttp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/databaseadmin"
	"github.com/nakroteck/nakpanel/internal/control/provision"
	"github.com/nakroteck/nakpanel/internal/types"
)

type databaseIdempotentCreator interface {
	CreateDatabaseIdempotentFor(context.Context, auth.SessionUser, int64, types.CreateDatabaseReq) (int64, error)
}

func databaseSupportScopeAllowed(r *http.Request, user auth.SessionUser, customerID int64) bool {
	raw := strings.TrimSpace(r.FormValue("support_customer_id"))
	if raw == "" {
		return true
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && id > 0 && user.Role == auth.RoleAdmin && id == customerID
}

func prepareDatabaseIdempotency(r *http.Request, user auth.SessionUser, ownerID int64, req *types.CreateDatabaseReq) error {
	key := strings.TrimSpace(r.Form.Get("idempotency_key"))
	if key == "" {
		return nil
	}
	if len(key) > 128 {
		return errors.New("invalid database request key")
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return errors.New("invalid database request key")
		}
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return errors.New("database request session is missing")
	}
	scope := sha256.Sum256([]byte(fmt.Sprintf("database-create:%d:%s", user.ID, cookie.Value)))
	payload, _ := json.Marshal(struct {
		OwnerID int64
		Request types.CreateDatabaseReq
	}{ownerID, *req})
	mac := hmac.New(sha256.New, []byte(cookie.Value))
	_, _ = mac.Write(payload)
	req.IdempotencyScope = hex.EncodeToString(scope[:])
	req.IdempotencyKey = key
	req.IdempotencyFingerprint = hex.EncodeToString(mac.Sum(nil))
	return nil
}

func (s *Server) registerDatabaseWorkspaceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sites/{id}/databases/status", s.handleDatabaseStatus)
	mux.HandleFunc("GET /databases/{id}/connection", s.handleDatabaseConnection)
	mux.HandleFunc("POST /databases/{id}/retry", s.handleDatabaseRetry)
	mux.HandleFunc("POST /databases/{id}/password", s.handleScopedDatabasePassword)
}

func (s *Server) prepareDatabaseCreate(r *http.Request, user auth.SessionUser, req *types.CreateDatabaseReq) error {
	for _, field := range []string{"site_id", "subscription_id"} {
		if raw := strings.TrimSpace(r.Form.Get(field)); raw != "" {
			id, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || id < 0 {
				return provision.ErrForbidden
			}
		}
	}
	if req.SiteID <= 0 {
		return nil
	}
	data, err := s.loadDashboard(r.Context(), user)
	if err != nil {
		return err
	}
	for _, site := range data.Sites {
		if site.ID != req.SiteID {
			continue
		}
		if site.SubscriptionID <= 0 || (req.SubscriptionID > 0 && req.SubscriptionID != site.SubscriptionID) {
			return provision.ErrForbidden
		}
		if !databaseSupportScopeAllowed(r, user, site.CustomerID) {
			return provision.ErrForbidden
		}
		req.SubscriptionID = site.SubscriptionID
		return nil
	}
	return provision.ErrForbidden
}

type databaseStatusResponse struct {
	CredentialState string `json:"credential_state,omitempty"`
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Status          string `json:"status"`
	Error           string `json:"error,omitempty"`
}

func safeDatabaseStatus(db dashboard.Database) databaseStatusResponse {
	result := databaseStatusResponse{ID: db.ID, Name: db.Name, Status: db.Status}
	if db.Status == "failed" {
		result.Error = "Database provisioning did not complete. Retry or contact your provider."
	}
	return result
}

func (s *Server) handleDatabaseStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Error(w, "Unauthorized", 401)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	data, err := s.loadDashboard(r.Context(), user)
	if err != nil {
		http.Error(w, "Could not load database status", 500)
		return
	}
	var site dashboard.Site
	for _, candidate := range data.Sites {
		if candidate.ID == id {
			site = candidate
			break
		}
	}
	if site.ID == 0 {
		http.NotFound(w, r)
		return
	}
	if !databaseSupportScopeAllowed(r, user, site.CustomerID) {
		http.NotFound(w, r)
		return
	}
	rows := make([]databaseStatusResponse, 0)
	for _, db := range data.Databases {
		if db.SiteID == site.ID && db.SubscriptionID == site.SubscriptionID {
			row := safeDatabaseStatus(db)
			if service, ok := s.databaseAdmin.(databaseCredentialStateReader); ok && db.Status == "active" {
				state, stateErr := service.DatabaseCredentialState(r.Context(), db.ID, db.SubscriptionID)
				if stateErr != nil {
					row.CredentialState = "unknown"
				} else {
					row.CredentialState = state
				}
			}
			rows = append(rows, row)
		}
	}
	writeSPAJSON(w, 200, map[string]any{"site_id": id, "databases": rows})
}

type databaseCredentialStateReader interface {
	DatabaseCredentialState(context.Context, int64, int64) (string, error)
}
type scopedDatabasePasswordRotator interface {
	RotatePasswordForSubscription(context.Context, int64, int64, int64, string) (types.ManageDatabaseAdminResult, error)
}

func (s *Server) handleScopedDatabasePassword(w http.ResponseWriter, r *http.Request) {
	user, db, ok := s.databaseWorkspaceTarget(w, r)
	if !ok {
		return
	}
	if db.Status != "active" || db.SubscriptionID <= 0 {
		writeSPAError(w, 409, "Database is not active.")
		return
	}
	if r.FormValue("confirm") != "yes" {
		writeSPAError(w, 400, "Confirm that applications must be updated with the new password.")
		return
	}
	service, ok := s.databaseAdmin.(scopedDatabasePasswordRotator)
	if !ok {
		writeSPAError(w, 503, "Password changes are unavailable.")
		return
	}
	result, err := service.RotatePasswordForSubscription(r.Context(), user.ID, db.ID, db.SubscriptionID, r.FormValue("password"))
	if err != nil {
		status := 400
		if errors.Is(err, databaseadmin.ErrOperationInProgress) {
			status = 409
		}
		writeSPAError(w, status, "Password change could not be queued. Check the subscription or an existing operation.")
		return
	}
	s.recordAudit(r.Context(), user, db.CustomerID, db.SubscriptionID, "database.password_queued", "database", db.ID, nil)
	if wantsSPAJSON(r) {
		writeSPAJSON(w, 202, map[string]any{"ok": true, "database_id": db.ID, "operation_id": result.OperationID, "credential_state": "updating", "notice": "Password update queued. Update applications after it completes."})
		return
	}
	target := "/databases?notice=database-password-queued"
	if db.SiteID > 0 {
		target = fmt.Sprintf("/sites/%d?tab=databases&notice=database-password-queued", db.SiteID)
	}
	http.Redirect(w, r, supportRedirectPath(r, user, target), 303)
}

func (s *Server) databaseWorkspaceTarget(w http.ResponseWriter, r *http.Request) (auth.SessionUser, dashboard.Database, bool) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := s.currentUser(w, r)
	if !ok {
		http.Error(w, "Unauthorized", 401)
		return user, dashboard.Database{}, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return user, dashboard.Database{}, false
	}
	data, err := s.loadDashboard(r.Context(), user)
	if err != nil {
		http.Error(w, "Could not load database", 500)
		return user, dashboard.Database{}, false
	}
	for _, db := range data.Databases {
		if db.ID == id {
			if !databaseSupportScopeAllowed(r, user, db.CustomerID) {
				http.NotFound(w, r)
				return user, dashboard.Database{}, false
			}
			return user, db, true
		}
	}
	http.NotFound(w, r)
	return user, dashboard.Database{}, false
}

func (s *Server) handleDatabaseConnection(w http.ResponseWriter, r *http.Request) {
	_, db, ok := s.databaseWorkspaceTarget(w, r)
	if !ok {
		return
	}
	if db.Status != "active" {
		writeSPAError(w, 409, "Database is not active yet.")
		return
	}
	if db.Engine != "mariadb" && db.Engine != "mysql" {
		writeSPAError(w, 409, "Connection details are unavailable for this engine.")
		return
	}
	writeSPAJSON(w, 200, map[string]any{"database_id": db.ID, "database": db.Name, "username": db.User, "engine": db.Engine, "host": "127.0.0.1", "port": 3306, "pdo": fmt.Sprintf("$pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=%s;charset=utf8mb4', '%s', 'YOUR_DATABASE_PASSWORD');", db.Name, db.User)})
}

type databaseRetrier interface {
	RetryDatabaseFor(context.Context, auth.SessionUser, int64, int64) error
}

func (s *Server) handleDatabaseRetry(w http.ResponseWriter, r *http.Request) {
	user, db, ok := s.databaseWorkspaceTarget(w, r)
	if !ok {
		return
	}
	if db.Status != "failed" {
		writeSPAError(w, 409, "Only failed databases can be retried.")
		return
	}
	retrier, ok := s.databases.(databaseRetrier)
	if !ok {
		writeSPAError(w, 503, "Database retry is unavailable.")
		return
	}
	if err := retrier.RetryDatabaseFor(r.Context(), user, db.ID, db.SubscriptionID); err != nil {
		if errors.Is(err, provision.ErrForbidden) {
			http.NotFound(w, r)
			return
		}
		writeSPAError(w, 409, "Database retry could not be queued. Check the subscription and try again.")
		return
	}
	s.recordAudit(r.Context(), user, db.CustomerID, db.SubscriptionID, "database.retry_queued", "database", db.ID, nil)
	if wantsSPAJSON(r) {
		writeSPAJSON(w, 202, map[string]any{"ok": true, "database_id": db.ID, "notice": "Database retry queued."})
		return
	}
	target := "/databases?notice=database-queued"
	if db.SiteID > 0 {
		target = fmt.Sprintf("/sites/%d?tab=databases&notice=database-queued", db.SiteID)
	}
	http.Redirect(w, r, supportRedirectPath(r, user, target), 303)
}
