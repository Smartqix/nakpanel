package panelhttp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type serverSecurityReader interface {
	InspectServerSecurity(context.Context) (types.ServerSecurityPolicy, error)
}

type serverSecurityManager interface {
	ListSecurityBans(context.Context) (types.SecurityBansResult, error)
	UnbanSecurityAddress(context.Context, types.UnbanSecurityAddressReq, int64) (types.UnbanSecurityAddressResult, error)
	ApplyFail2Ban(context.Context, types.ApplyFail2BanPolicyReq, int64) error
	StageFirewall(context.Context, types.StageServerSecurityReq, int64) error
	ConfirmSecurityOperation(context.Context, string, int64) (types.StagedSecurityResult, error)
	RevertSecurityOperation(context.Context, string, int64) (types.StagedSecurityResult, error)
	OperationStatus(context.Context, string) (serveradmin.Operation, error)
}

func (s *Server) registerServerSecurityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /tools-settings/security/status", s.handleServerSecurityStatus)
	mux.HandleFunc("GET /tools-settings/security/bans", s.handleServerSecurityBans)
	mux.HandleFunc("POST /tools-settings/security/bans/unban", s.handleServerSecurityUnban)
	mux.HandleFunc("POST /tools-settings/security/fail2ban", s.handleServerSecurityFail2Ban)
	mux.HandleFunc("POST /tools-settings/security/firewall", s.handleServerSecurityFirewallStage)
	mux.HandleFunc("POST /tools-settings/security/firewall/confirm", s.handleServerSecurityFirewallConfirm)
	mux.HandleFunc("POST /tools-settings/security/firewall/revert", s.handleServerSecurityFirewallRevert)
}

func (s *Server) securityManager(w http.ResponseWriter) (serverSecurityManager, bool) {
	manager, ok := s.serverAdmin.(serverSecurityManager)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server security management is unavailable")
		return nil, false
	}
	return manager, true
}

func (s *Server) handleServerSecurityStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	reader, ok := s.serverAdmin.(serverSecurityReader)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server security inspection is unavailable")
		return
	}
	policy, err := reader.InspectServerSecurity(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Server security state could not be collected")
		return
	}
	_, mutable := s.serverAdmin.(serverSecurityManager)
	writeSPAJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"policy": policy,
		"capabilities": map[string]bool{
			"firewall_inspection": true,
			"firewall_mutation":   mutable,
			"ssh_mutation":        false,
			"fail2ban_mutation":   mutable,
		},
		"smtp_configured": s.smtpConfigured,
	})
}

func (s *Server) handleServerSecurityBans(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	manager, ok := s.securityManager(w)
	if !ok {
		return
	}
	result, err := manager.ListSecurityBans(r.Context())
	if err != nil {
		log.Printf("list security bans: %v", err)
		writeSPAError(w, http.StatusBadGateway, "Jail status could not be collected")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "bans": result})
}

func decodeSecurityJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 32<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func (s *Server) handleServerSecurityUnban(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	manager, ok := s.securityManager(w)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	var input types.UnbanSecurityAddressReq
	if err := decodeSecurityJSON(r, &input); err != nil || strings.TrimSpace(input.Address) == "" {
		writeSPAError(w, http.StatusBadRequest, "A jail id and IP address are required")
		return
	}
	result, err := manager.UnbanSecurityAddress(r.Context(), input, user.ID)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

type fail2banApplyInput struct {
	Policy   types.Fail2BanPolicy `json:"policy"`
	SSHPorts []int                `json:"ssh_ports,omitempty"`
}

func newSecurityOperationID() (string, error) {
	return newServerAdminOperationID()
}

func (s *Server) handleServerSecurityFail2Ban(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	manager, ok := s.securityManager(w)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	var input fail2banApplyInput
	if err := decodeSecurityJSON(r, &input); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid fail2ban policy payload")
		return
	}
	operationID, err := newSecurityOperationID()
	if err != nil {
		writeSPAError(w, http.StatusInternalServerError, "Could not start the operation")
		return
	}
	if err := manager.ApplyFail2Ban(r.Context(), types.ApplyFail2BanPolicyReq{
		Policy: input.Policy, SSHPorts: input.SSHPorts, OperationID: operationID,
	}, user.ID); err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "operation_id": operationID})
}

type firewallStageInput struct {
	Policy types.ServerSecurityPolicy `json:"policy"`
}

func (s *Server) handleServerSecurityFirewallStage(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	manager, ok := s.securityManager(w)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	var input firewallStageInput
	if err := decodeSecurityJSON(r, &input); err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid firewall policy payload")
		return
	}
	operationID, err := newSecurityOperationID()
	if err != nil {
		writeSPAError(w, http.StatusInternalServerError, "Could not start the operation")
		return
	}
	if err := manager.StageFirewall(r.Context(), types.StageServerSecurityReq{
		Scope:         "firewall",
		Policy:        input.Policy,
		OperationID:   operationID,
		ClientAddress: clientIP(r),
	}, user.ID); err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "operation_id": operationID})
}

type securityOperationInput struct {
	OperationID string `json:"operation_id"`
}

func (s *Server) handleServerSecurityFirewallConfirm(w http.ResponseWriter, r *http.Request) {
	s.handleSecurityOperationAction(w, r, "confirm")
}

func (s *Server) handleServerSecurityFirewallRevert(w http.ResponseWriter, r *http.Request) {
	s.handleSecurityOperationAction(w, r, "revert")
}

func (s *Server) handleSecurityOperationAction(w http.ResponseWriter, r *http.Request, action string) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	manager, ok := s.securityManager(w)
	if !ok {
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	var input securityOperationInput
	if err := decodeSecurityJSON(r, &input); err != nil || strings.TrimSpace(input.OperationID) == "" {
		writeSPAError(w, http.StatusBadRequest, "An operation id is required")
		return
	}
	var result types.StagedSecurityResult
	var err error
	if action == "confirm" {
		result, err = manager.ConfirmSecurityOperation(r.Context(), input.OperationID, user.ID)
	} else {
		result, err = manager.RevertSecurityOperation(r.Context(), input.OperationID, user.ID)
	}
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}
