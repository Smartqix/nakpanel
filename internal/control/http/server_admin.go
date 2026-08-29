package panelhttp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

const maxServerAdminJSONBytes = 16 << 10

const (
	reauthenticationFailureLimit  = 5
	reauthenticationFailureWindow = 15 * time.Minute
	reauthenticationLockout       = 15 * time.Minute
)

type reauthAttempt struct {
	failures      int
	windowStarted time.Time
	lockedUntil   time.Time
}

type reauthLimiter struct {
	mu       sync.Mutex
	attempts map[string]reauthAttempt
}

func newReauthLimiter() *reauthLimiter {
	return &reauthLimiter{attempts: make(map[string]reauthAttempt)}
}

func (l *reauthLimiter) allowed(key string, now time.Time) time.Duration {
	if l == nil || key == "" {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.attempts[key]
	if !ok {
		return 0
	}
	if now.Before(state.lockedUntil) {
		return state.lockedUntil.Sub(now)
	}
	if now.Sub(state.windowStarted) >= reauthenticationFailureWindow {
		delete(l.attempts, key)
	}
	return 0
}

func (l *reauthLimiter) failed(key string, now time.Time) (int, time.Duration) {
	if l == nil || key == "" {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.attempts[key]
	if state.windowStarted.IsZero() || now.Sub(state.windowStarted) >= reauthenticationFailureWindow {
		state = reauthAttempt{windowStarted: now}
	}
	state.failures++
	if state.failures >= reauthenticationFailureLimit {
		state.lockedUntil = now.Add(reauthenticationLockout)
	}
	l.attempts[key] = state
	return state.failures, state.lockedUntil.Sub(now)
}

func (l *reauthLimiter) reset(key string) {
	if l == nil || key == "" {
		return
	}
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

var managedServiceActions = map[string]map[string]struct{}{
	"web":     actionRegistry("reload", "restart", "start", "stop"),
	"dns":     actionRegistry("reload", "restart", "start", "stop"),
	"mail":    actionRegistry("reload", "restart", "start", "stop"),
	"php-8.1": actionRegistry("reload", "restart", "start", "stop"),
	"php-8.2": actionRegistry("reload", "restart", "start", "stop"),
	"php-8.3": actionRegistry("reload", "restart", "start", "stop"),
	"php-8.4": actionRegistry("reload", "restart", "start", "stop"),
	"php-8.5": actionRegistry("reload", "restart", "start", "stop"),
}

type managedServiceActionInput struct {
	ServiceID string `json:"service_id"`
	Action    string `json:"action"`
}

// handleServerAdminWorkspace deliberately renders the existing settings
// workspace. Focused templates can be added without widening authorization.
func (s *Server) handleServerAdminWorkspace(w http.ResponseWriter, r *http.Request) {
	s.handleWorkspace("tools-settings")(w, r)
}

func (s *Server) handleServerInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	s.writeServerInventory(w, r)
}

func (s *Server) handleRefreshServerInventory(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.writeServerInventory(w, r) {
		s.recordAudit(r.Context(), user, 0, 0, "server.inventory_refreshed", "server", 0, nil)
	}
}

func (s *Server) writeServerInventory(w http.ResponseWriter, r *http.Request) bool {
	if s.serverAdmin == nil {
		writeSPAError(w, http.StatusServiceUnavailable, "Server inventory is unavailable")
		return false
	}
	inventory, err := s.serverAdmin.InspectServer(r.Context())
	if err != nil {
		if errors.Is(err, serveradmin.ErrInventoryCacheFallback) {
			writeSPAJSON(w, http.StatusOK, map[string]any{
				"ok": true, "inventory": inventory, "cached": true,
			})
			return false
		}
		writeSPAError(w, http.StatusBadGateway, "Server inventory could not be collected")
		return false
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "inventory": inventory})
	return true
}

func (s *Server) handleManagedServiceAction(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.serverAdmin == nil {
		writeSPAError(w, http.StatusServiceUnavailable, "Server service management is unavailable")
		return
	}

	input, err := decodeManagedServiceAction(r)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid managed service action")
		return
	}
	if !managedServiceActionAllowed(input.ServiceID, input.Action) {
		writeSPAError(w, http.StatusBadRequest, "Managed service or action is not allowed")
		return
	}
	if (input.Action == "restart" || input.Action == "stop") && !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	operationID, err := newServerAdminOperationID()
	if err != nil {
		writeSPAError(w, http.StatusInternalServerError, "Could not start the managed service action")
		return
	}
	result, err := s.serverAdmin.ControlManagedService(r.Context(), types.ControlManagedServiceReq{
		ServiceID: input.ServiceID, Action: input.Action, OperationID: operationID, ActorUserID: user.ID,
	})
	if err != nil {
		if errors.Is(err, serveradmin.ErrOperationInProgress) {
			writeSPAError(w, http.StatusConflict, "A matching managed service action is already active")
			return
		}
		writeSPAError(w, http.StatusBadGateway, "Managed service action failed")
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "result": result})
}

func (s *Server) handleServerReauthenticate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(w, r)
	if !ok {
		writeSPAError(w, http.StatusUnauthorized, "Session could not be reauthenticated")
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		writeSPAError(w, http.StatusUnauthorized, "Session could not be reauthenticated")
		return
	}
	sessionKey := auth.TokenHash(cookie.Value)
	if retryAfter := s.reauthLimiter.allowed(sessionKey, time.Now()); retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Round(time.Second)/time.Second))))
		writeSPAError(w, http.StatusTooManyRequests, "Too many failed attempts; try again later")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid reauthentication request")
		return
	}
	for key := range r.Form {
		switch key {
		case "password", "csrf_token":
		default:
			writeSPAError(w, http.StatusBadRequest, "Invalid reauthentication request")
			return
		}
	}
	account, err := s.users.FindUserByEmail(r.Context(), user.Email)
	if err != nil {
		writeSPAError(w, http.StatusUnauthorized, "Password verification failed")
		return
	}
	valid, err := auth.VerifyPassword(r.Form.Get("password"), account.PasswordHash)
	if err != nil || !valid {
		attempt, retryAfter := s.reauthLimiter.failed(sessionKey, time.Now())
		locked := retryAfter > 0
		s.recordAudit(r.Context(), user, 0, 0, "server.reauthentication_failed", "session", 0, map[string]any{
			"attempt": attempt,
			"locked":  locked,
		})
		if locked {
			w.Header().Set("Retry-After", strconv.Itoa(int(reauthenticationLockout/time.Second)))
			writeSPAError(w, http.StatusTooManyRequests, "Too many failed attempts; try again later")
			return
		}
		writeSPAError(w, http.StatusUnauthorized, "Password verification failed")
		return
	}
	if s.sessions.MarkReauthenticated(r.Context(), cookie.Value) != nil {
		writeSPAError(w, http.StatusUnauthorized, "Session could not be reauthenticated")
		return
	}
	s.reauthLimiter.reset(sessionKey)
	s.recordAudit(r.Context(), user, 0, 0, "server.reauthenticated", "session", 0, nil)
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func decodeManagedServiceAction(r *http.Request) (managedServiceActionInput, error) {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		var input managedServiceActionInput
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxServerAdminJSONBytes+1))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return managedServiceActionInput{}, err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return managedServiceActionInput{}, errors.New("request must contain one JSON object")
		}
		return canonicalManagedServiceAction(input), nil
	}

	if err := r.ParseForm(); err != nil {
		return managedServiceActionInput{}, err
	}
	for key := range r.Form {
		switch key {
		case "service_id", "action", "csrf_token":
		default:
			return managedServiceActionInput{}, errors.New("unknown managed service action field")
		}
	}
	return canonicalManagedServiceAction(managedServiceActionInput{
		ServiceID: r.Form.Get("service_id"),
		Action:    r.Form.Get("action"),
	}), nil
}

func canonicalManagedServiceAction(input managedServiceActionInput) managedServiceActionInput {
	input.ServiceID = strings.ToLower(strings.TrimSpace(input.ServiceID))
	input.Action = strings.ToLower(strings.TrimSpace(input.Action))
	return input
}

func managedServiceActionAllowed(serviceID, action string) bool {
	actions, ok := managedServiceActions[serviceID]
	if !ok {
		return false
	}
	_, ok = actions[action]
	return ok
}

func actionRegistry(actions ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		result[action] = struct{}{}
	}
	return result
}

func newServerAdminOperationID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "op_" + hex.EncodeToString(random[:]), nil
}
