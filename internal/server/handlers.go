package server

import (
	"net/http"

	"github.com/adefemi171/runeward/internal/backend"
	"github.com/adefemi171/runeward/internal/browser"
	"github.com/adefemi171/runeward/internal/controlplane"
	"github.com/adefemi171/runeward/internal/profile"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.mgr.ListProfiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if profiles == nil {
		profiles = []controlplane.ProfileInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *Server) handleCreateSandbox(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile  string `json:"profile"`
		CopyFrom string `json:"copy_from"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Profile == "" {
		writeError(w, http.StatusBadRequest, "profile is required")
		return
	}
	sb, err := s.mgr.CreateSandbox(r.Context(), req.Profile, controlplane.CreateOptions{CopyFrom: req.CopyFrom})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sandboxView(sb))
}

func (s *Server) handleListSandboxes(w http.ResponseWriter, r *http.Request) {
	list := s.mgr.ListSandboxes()
	views := make([]map[string]any, 0, len(list))
	for i := range list {
		views = append(views, sandboxView(&list[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sandboxes": views})
}

func (s *Server) handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sb, ok := s.mgr.Sandbox(id)
	if !ok {
		writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	writeJSON(w, http.StatusOK, sandboxView(sb))
}

func (s *Server) handleKillSandbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mgr.KillSandbox(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- tool endpoints ---

func (s *Server) handleShell(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command []string `json:"command"`
		Workdir string   `json:"workdir"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.mgr.Shell(r.Context(), r.PathValue("id"), req.Command, req.Workdir)
	writeToolResult(w, res, err)
}

func (s *Server) handleBrowser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL  string `json:"url"`
		Mode string `json:"mode"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.mgr.Browser(r.Context(), r.PathValue("id"), req.URL, req.Mode)
	writeToolResult(w, res, err)
}

func (s *Server) handleBrowserOpen(w http.ResponseWriter, r *http.Request) {
	sid, res, err := s.mgr.BrowserOpen(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res != nil && res.Verdict != profile.VerdictAllow {
		writeToolResult(w, res, nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"session_id": sid})
}

func (s *Server) handleBrowserAct(w http.ResponseWriter, r *http.Request) {
	var cmd browser.Command
	if err := decodeJSON(r, &cmd); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.mgr.BrowserAct(r.Context(), r.PathValue("id"), r.PathValue("sid"), cmd)
	writeToolResult(w, res, err)
}

func (s *Server) handleBrowserClose(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.BrowserClose(r.Context(), r.PathValue("id"), r.PathValue("sid")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePython(w http.ResponseWriter, r *http.Request) {
	code, ok := decodeCode(w, r)
	if !ok {
		return
	}
	res, err := s.mgr.Python(r.Context(), r.PathValue("id"), code)
	writeToolResult(w, res, err)
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	code, ok := decodeCode(w, r)
	if !ok {
		return
	}
	res, err := s.mgr.Node(r.Context(), r.PathValue("id"), code)
	writeToolResult(w, res, err)
}

func (s *Server) handleFileRead(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.mgr.FileRead(r.Context(), r.PathValue("id"), req.Path)
	if handled := writeIfBlocked(w, res, err); handled {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": res.Stdout, "verdict": res.Verdict})
}

func (s *Server) handleFileWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.mgr.FileWrite(r.Context(), r.PathValue("id"), req.Path, req.Content)
	if handled := writeIfBlocked(w, res, err); handled {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bytes": len(req.Content), "verdict": res.Verdict})
}

func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.mgr.FileList(r.Context(), r.PathValue("id"), req.Path)
	if handled := writeIfBlocked(w, res, err); handled {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": res.Stdout, "verdict": res.Verdict})
}

func (s *Server) handleFileSearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
		Path  string `json:"path"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.mgr.FileSearch(r.Context(), r.PathValue("id"), req.Query, req.Path)
	if handled := writeIfBlocked(w, res, err); handled {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": res.Stdout, "verdict": res.Verdict})
}

// --- snapshots ---

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ref, err := s.mgr.Snapshot(r.Context(), r.PathValue("id"), req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, ref)
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	snaps := s.mgr.ListSnapshots()
	if snaps == nil {
		snaps = []backend.SnapshotRef{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps})
}

func (s *Server) handleRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	sb, err := s.mgr.RestoreSnapshot(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sandboxView(sb))
}

// --- approvals ---

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	list := s.mgr.Approvals().List()
	if list == nil {
		list = []controlplane.ApprovalView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": list})
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	s.resolveApproval(w, r, true)
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	s.resolveApproval(w, r, false)
}

func (s *Server) resolveApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	if ok := s.mgr.Approvals().Resolve(r.PathValue("id"), approve); !ok {
		writeError(w, http.StatusNotFound, "approval not found or already resolved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- audit ---

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	events, err := s.mgr.Ledger().Replay(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.VerifyLedger(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "signed": s.mgr.Signed(), "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "signed": s.mgr.Signed()})
}

func (s *Server) handleAuditPubKey(w http.ResponseWriter, r *http.Request) {
	pub, keyID := s.mgr.LedgerPublicKey()
	if pub == "" {
		writeJSON(w, http.StatusOK, map[string]any{"signed": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"signed": true, "public_key": pub, "key_id": keyID})
}

// handleAuditExport streams a verifiable transcript bundle; ?session=<id>
// narrows it to one session.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	session := r.URL.Query().Get("session")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=runeward-audit-bundle.json")
	if err := s.mgr.ExportBundle(w, session); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
}

// --- helpers ---

func sandboxView(sb *backend.Sandbox) map[string]any {
	return map[string]any{
		"id":      sb.ID,
		"profile": sb.Profile,
		"backend": sb.Backend,
		"image":   sb.Image,
		"status":  sb.Status,
	}
}

func decodeCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return req.Code, true
}

// writeToolResult maps a ToolResult to HTTP status: 403 deny, 202 pending
// approval, 200 otherwise.
func writeToolResult(w http.ResponseWriter, res *controlplane.ToolResult, err error) {
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	switch res.Verdict {
	case profile.VerdictDeny:
		writeJSON(w, http.StatusForbidden, res)
	case profile.VerdictRequireApprove:
		writeJSON(w, http.StatusAccepted, res)
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

// writeIfBlocked handles the error/deny/pending cases shared by the file
// endpoints; it returns true when it has written a response.
func writeIfBlocked(w http.ResponseWriter, res *controlplane.ToolResult, err error) bool {
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return true
	}
	switch res.Verdict {
	case profile.VerdictDeny:
		writeJSON(w, http.StatusForbidden, res)
		return true
	case profile.VerdictRequireApprove:
		writeJSON(w, http.StatusAccepted, res)
		return true
	}
	return false
}
