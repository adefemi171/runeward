package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Runewardd/runeward/internal/controlplane"
	"github.com/Runewardd/runeward/internal/fleet"
)

func (s *Server) handleCreateFleet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile string `json:"profile"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Profile == "" {
		writeError(w, http.StatusBadRequest, "profile is required")
		return
	}
	owner := ""
	if p := principalFrom(r.Context()); p != nil {
		if !p.CanLaunch(req.Profile) {
			writeError(w, http.StatusForbidden, "not authorized to launch profile "+req.Profile)
			return
		}
		owner = p.Name
	}
	v, err := s.mgr.CreateFleetForOwner(r.Context(), req.Profile, owner)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleListFleets(w http.ResponseWriter, r *http.Request) {
	list := s.mgr.ListFleets()
	if p := principalFrom(r.Context()); p != nil && !p.Admin {
		filtered := make([]controlplane.FleetView, 0, len(list))
		for _, v := range list {
			if s.fleetOwnedBy(v.ID, p.Name) {
				filtered = append(filtered, v)
			}
		}
		list = filtered
	}
	if list == nil {
		list = []controlplane.FleetView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"fleets": list})
}

func (s *Server) handleGetFleet(w http.ResponseWriter, r *http.Request) {
	v, ok := s.mgr.FleetView(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "fleet not found")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleKillFleet(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.KillFleet(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.mgr.ListTasks(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if tasks == nil {
		tasks = []fleet.Task{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}

func (s *Server) handleAddTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Payload string `json:"payload"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	t, err := s.mgr.AddTask(r.PathValue("id"), req.Payload)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleClaimTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner string `json:"owner"`
	}
	if err := decodeJSON(r, &req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	t, ok, err := s.mgr.ClaimTask(r.PathValue("id"), req.Owner)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"claimed": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"claimed": true, "task": t})
}

func (s *Server) handleCompleteTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner  string `json:"owner"`
		Result string `json:"result"`
	}
	if err := decodeJSON(r, &req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	owner, err := taskOwnerFromRequest(r, req.Owner)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.mgr.CompleteTask(r.PathValue("id"), r.PathValue("taskID"), owner, req.Result); err != nil {
		writeTaskErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleHeartbeatTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner string `json:"owner"`
	}
	if err := decodeJSON(r, &req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	t, err := s.mgr.HeartbeatTask(r.PathValue("id"), r.PathValue("taskID"), req.Owner)
	if err != nil {
		writeTaskErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "task": t})
}

func (s *Server) handleFailTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Owner   string `json:"owner"`
		Error   string `json:"error"`
		Requeue bool   `json:"requeue"`
	}
	if err := decodeJSON(r, &req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	owner, err := taskOwnerFromRequest(r, req.Owner)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.mgr.FailTask(r.PathValue("id"), r.PathValue("taskID"), owner, req.Error, req.Requeue); err != nil {
		writeTaskErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func taskOwnerFromRequest(r *http.Request, requested string) (string, error) {
	if p := principalFrom(r.Context()); p != nil {
		if strings.TrimSpace(p.Name) == "" {
			return "", errors.New("authenticated principal name is empty")
		}
		return p.Name, nil
	}
	owner := strings.TrimSpace(requested)
	if owner == "" {
		return "", errors.New("owner is required")
	}
	return owner, nil
}

// writeTaskErr maps board errors to HTTP statuses.
func writeTaskErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, fleet.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, fleet.ErrIllegalTransition):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}
