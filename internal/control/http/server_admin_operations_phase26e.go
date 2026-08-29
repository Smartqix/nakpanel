package panelhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type phase26Operations interface {
	InspectUpdates(context.Context) (types.UpdateState, error)
	ApplyUpdates(context.Context, types.ApplyUpdatesReq, int64) error
	ControlHostPower(context.Context, types.HostPowerReq) error
	ApplicationCatalogInventory(context.Context) ([]types.ApplicationCatalogInventory, error)
}

type phase26UpdateInput struct {
	PackageNames []string `json:"package_names"`
	SecurityOnly bool     `json:"security_only"`
	DryRun       bool     `json:"dry_run"`
	Confirmation string   `json:"confirmation"`
}

type phase26HostPowerInput struct {
	Action                string `json:"action"`
	Confirmation          string `json:"confirmation"`
	OutOfBandAcknowledged bool   `json:"out_of_band_acknowledged"`
}

// registerPhase26OperationsRoutes is intentionally separate from Handler so
// the operations can remain hidden until the compatible panel and agent are
// deployed together. Handler should call this once during route assembly.
func (s *Server) registerPhase26OperationsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /tools-settings/operations/updates", s.handlePhase26UpdateInventory)
	mux.HandleFunc("POST /tools-settings/operations/updates", s.handlePhase26ApplyUpdates)
	mux.HandleFunc("GET /tools-settings/operations/application-catalog", s.handlePhase26ApplicationCatalog)
	mux.HandleFunc("POST /tools-settings/operations/power", s.handlePhase26HostPower)
	mux.HandleFunc("GET /tools-settings/operations/{operationID}", s.handlePhase26OperationStatus)
}

func (s *Server) handlePhase26UpdateInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	operations, ok := s.phase26Operations(w)
	if !ok {
		return
	}
	state, err := operations.InspectUpdates(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Update inventory could not be collected")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "updates": state})
}

func (s *Server) handlePhase26ApplicationCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	operations, ok := s.phase26Operations(w)
	if !ok {
		return
	}
	inventory, err := operations.ApplicationCatalogInventory(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Application catalog inventory could not be collected")
		return
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{"ok": true, "catalog": inventory})
}

func (s *Server) handlePhase26ApplyUpdates(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	operations, ok := s.phase26Operations(w)
	if !ok {
		return
	}
	input, err := decodePhase26UpdateInput(r)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, "Invalid managed update request")
		return
	}
	if !input.DryRun {
		if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
			writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
			return
		}
		if input.Confirmation != "INSTALL UPDATES" {
			writeSPAError(w, http.StatusBadRequest, "Type INSTALL UPDATES to confirm")
			return
		}
	}
	updateInventory, err := operations.InspectUpdates(r.Context())
	if err != nil {
		writeSPAError(w, http.StatusBadGateway, "Current update inventory could not be verified")
		return
	}
	selected, err := bindSelectedUpdatePackages(updateInventory.Packages, input.PackageNames, input.SecurityOnly)
	if err != nil {
		writeSPAError(w, http.StatusBadRequest, err.Error())
		return
	}
	operationID, err := newServerAdminOperationID()
	if err != nil {
		writeSPAError(w, http.StatusInternalServerError, "Could not start the update operation")
		return
	}
	if err := operations.ApplyUpdates(r.Context(), types.ApplyUpdatesReq{
		PackageNames: input.PackageNames,
		Packages:     selected,
		SecurityOnly: input.SecurityOnly,
		DryRun:       input.DryRun,
		OperationID:  operationID,
	}, user.ID); err != nil {
		if errors.Is(err, serveradmin.ErrOperationInProgress) {
			writeSPAError(w, http.StatusConflict, "A package operation is already active")
			return
		}
		writeSPAError(w, http.StatusBadGateway, "Managed update operation could not be queued")
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "operation_id": operationID})
}

func bindSelectedUpdatePackages(available []types.UpdatePackage, names []string, securityOnly bool) ([]types.UpdatePackage, error) {
	byName := make(map[string]types.UpdatePackage, len(available))
	for _, item := range available {
		if item.Name != "" && !item.Held {
			byName[item.Name] = item
		}
	}
	if len(names) == 0 && securityOnly {
		for name, item := range byName {
			if item.Security {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil, errors.New("Select at least one current package update")
	}
	selected := make([]types.UpdatePackage, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		item, ok := byName[name]
		if !ok || (securityOnly && !item.Security) {
			return nil, errors.New("Selected packages are no longer in the current update inventory")
		}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			selected = append(selected, item)
		}
	}
	return selected, nil
}

func (s *Server) handlePhase26HostPower(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	operations, ok := s.phase26Operations(w)
	if !ok {
		return
	}
	input, err := decodePhase26HostPowerInput(r)
	if err != nil || (input.Action != types.HostPowerReboot && input.Action != types.HostPowerShutdown) {
		writeSPAError(w, http.StatusBadRequest, "Invalid host power request")
		return
	}
	if !s.sessions.RecentlyAuthenticated(user, 10*time.Minute) {
		writeSPAError(w, http.StatusPreconditionRequired, "Recent authentication is required")
		return
	}
	expected := "REBOOT"
	if input.Action == types.HostPowerShutdown {
		if !input.OutOfBandAcknowledged {
			writeSPAError(w, http.StatusBadRequest, "Confirm an out-of-band power-on path before shutdown")
			return
		}
		inventory, inspectErr := s.serverAdmin.InspectServer(r.Context())
		if inspectErr != nil || strings.TrimSpace(inventory.Hostname) == "" {
			writeSPAError(w, http.StatusPreconditionFailed, "A current hostname is required for shutdown confirmation")
			return
		}
		expected = inventory.Hostname
	}
	if input.Confirmation != expected {
		writeSPAError(w, http.StatusBadRequest, "Typed confirmation does not match")
		return
	}
	operationID, err := newServerAdminOperationID()
	if err != nil {
		writeSPAError(w, http.StatusInternalServerError, "Could not start the host operation")
		return
	}
	if err := operations.ControlHostPower(r.Context(), types.HostPowerReq{
		Action: input.Action, OperationID: operationID, ActorUserID: user.ID,
	}); err != nil {
		if errors.Is(err, serveradmin.ErrOperationInProgress) {
			writeSPAError(w, http.StatusConflict, "A host power operation is already active")
			return
		}
		writeSPAError(w, http.StatusBadGateway, "Host operation could not be queued")
		return
	}
	writeSPAJSON(w, http.StatusAccepted, map[string]any{"ok": true, "operation_id": operationID})
}

func (s *Server) handlePhase26OperationStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	reader, ok := s.serverAdmin.(interface {
		OperationStatus(context.Context, string) (serveradmin.Operation, error)
	})
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server operation status is unavailable")
		return
	}
	operation, err := reader.OperationStatus(r.Context(), r.PathValue("operationID"))
	if err != nil {
		writeSPAError(w, http.StatusNotFound, "Server operation was not found")
		return
	}
	errorMessage := ""
	if operation.Status == serveradmin.OperationFailed {
		errorMessage = "The operation failed. Review the bounded server logs for details."
	}
	writeSPAJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"operation": map[string]any{
			"operation_id": operation.OperationID,
			"action":       operation.Action,
			"target_type":  operation.TargetType,
			"target_key":   operation.TargetKey,
			"status":       operation.Status,
			"error":        errorMessage,
			"started_at":   operation.StartedAt,
			"completed_at": operation.CompletedAt,
		},
	})
}

func (s *Server) phase26Operations(w http.ResponseWriter) (phase26Operations, bool) {
	operations, ok := s.serverAdmin.(phase26Operations)
	if !ok {
		writeSPAError(w, http.StatusServiceUnavailable, "Server operations are unavailable")
	}
	return operations, ok
}

func decodePhase26UpdateInput(r *http.Request) (phase26UpdateInput, error) {
	var input phase26UpdateInput
	if err := decodePhase26OperationInput(r, &input, map[string]bool{
		"package_names": true, "security_only": true, "dry_run": true,
		"confirmation": true, "csrf_token": true,
	}); err != nil {
		return input, err
	}
	input.Confirmation = strings.TrimSpace(input.Confirmation)
	for index := range input.PackageNames {
		input.PackageNames[index] = strings.TrimSpace(input.PackageNames[index])
	}
	return input, nil
}

func decodePhase26HostPowerInput(r *http.Request) (phase26HostPowerInput, error) {
	var input phase26HostPowerInput
	if err := decodePhase26OperationInput(r, &input, map[string]bool{
		"action": true, "confirmation": true, "out_of_band_acknowledged": true, "csrf_token": true,
	}); err != nil {
		return input, err
	}
	input.Action = strings.ToLower(strings.TrimSpace(input.Action))
	input.Confirmation = strings.TrimSpace(input.Confirmation)
	return input, nil
}

func decodePhase26OperationInput(r *http.Request, output any, allowedFormFields map[string]bool) error {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxServerAdminJSONBytes+1))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(output); err != nil {
			return err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errors.New("request must contain one JSON object")
		}
		return nil
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	for field := range r.Form {
		if !allowedFormFields[field] {
			return errors.New("unknown operation field")
		}
	}
	switch typed := output.(type) {
	case *phase26UpdateInput:
		typed.PackageNames = append([]string(nil), r.Form["package_names"]...)
		typed.SecurityOnly = r.Form.Get("security_only") == "true"
		typed.DryRun = r.Form.Get("dry_run") == "true"
		typed.Confirmation = r.Form.Get("confirmation")
	case *phase26HostPowerInput:
		typed.Action = r.Form.Get("action")
		typed.Confirmation = r.Form.Get("confirmation")
		typed.OutOfBandAcknowledged = r.Form.Get("out_of_band_acknowledged") == "true"
	default:
		return errors.New("unsupported operation input")
	}
	return nil
}
