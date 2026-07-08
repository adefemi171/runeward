package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Runewardd/runeward/internal/backend"
	"github.com/Runewardd/runeward/internal/browser"
	"github.com/Runewardd/runeward/internal/controlplane"
	"github.com/Runewardd/runeward/internal/egress"
	"github.com/Runewardd/runeward/internal/policy"
	"github.com/Runewardd/runeward/internal/profile"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleWhoami reports the authenticated caller's identity and capabilities so
// the dashboard can render an interactive login and gate controls (create,
// approve) the caller isn't permitted to use. Reachable only after
// authentication, so a 200 here confirms the presented token is valid.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"authenticated": true,
		"rbac":          s.Authz != nil,
	}
	if p := principalFrom(r.Context()); p != nil {
		resp["principal"] = map[string]any{
			"name":             p.Name,
			"admin":            p.Admin,
			"can_approve":      p.MayApprove(),
			"can_launch":       true,
			"allowed_profiles": p.AllowedProfiles,
		}
	} else {
		// Legacy single-token or open mode: no named identity, full rights.
		resp["principal"] = map[string]any{
			"name":        "",
			"admin":       true,
			"can_approve": true,
			"can_launch":  true,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.mgr.ListProfiles()
	if err != nil {
		writeServerError(w, s.logger, err)
		return
	}
	if profiles == nil {
		profiles = []controlplane.ProfileInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *Server) handleCreateTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind      string `json:"kind"`
		SandboxID string `json:"sandbox_id"`
		Path      string `json:"path"`
		TTLSecond int    `json:"ttl_seconds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	scope := ticketScope{
		Kind:      strings.ToLower(strings.TrimSpace(req.Kind)),
		SandboxID: strings.TrimSpace(req.SandboxID),
		Path:      strings.TrimSpace(req.Path),
	}
	if scope.Kind == "" {
		if scope.SandboxID != "" {
			scope.Kind = ticketKindTerminal
		} else {
			scope.Kind = ticketKindDownload
		}
	}
	if scope.Kind == ticketKindTerminal && scope.SandboxID == "" {
		writeError(w, http.StatusBadRequest, "sandbox_id is required for terminal tickets")
		return
	}
	if scope.Kind == ticketKindTerminal {
		if _, ok := s.mgr.Sandbox(scope.SandboxID); !ok {
			writeError(w, http.StatusNotFound, "sandbox not found")
			return
		}
		if p := principalFrom(r.Context()); p != nil && !p.Admin {
			if owner, ok := s.mgr.SandboxOwner(scope.SandboxID); !ok || owner != p.Name {
				writeError(w, http.StatusNotFound, "sandbox not found")
				return
			}
		}
	}
	if scope.Kind == ticketKindDownload && scope.Path == "" {
		scope.Path = "/v1/audit/export"
	}
	ttl := 30 * time.Second
	if req.TTLSecond > 0 {
		ttl = time.Duration(req.TTLSecond) * time.Second
	}
	ticket, expiresAt, err := s.issueTicket(scope, principalFrom(r.Context()), ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ticket":     ticket,
		"expires_at": expiresAt.UTC(),
		"scope": map[string]any{
			"kind":       scope.Kind,
			"sandbox_id": scope.SandboxID,
			"path":       scope.Path,
		},
	})
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
	owner := ""
	if p := principalFrom(r.Context()); p != nil {
		if !p.CanLaunch(req.Profile) {
			writeError(w, http.StatusForbidden, "not authorized to launch profile "+req.Profile)
			return
		}
		owner = p.Name
	}
	sb, err := s.mgr.CreateSandbox(r.Context(), req.Profile, controlplane.CreateOptions{CopyFrom: req.CopyFrom, Owner: owner})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sandboxView(sb, owner))
}

func (s *Server) handleListSandboxes(w http.ResponseWriter, r *http.Request) {
	infos := s.mgr.ListSandboxInfos()
	p := principalFrom(r.Context())
	views := make([]map[string]any, 0, len(infos))
	for i := range infos {
		// Per-principal visibility: a non-admin principal sees only the
		// sandboxes it owns. Legacy/open mode (no principal) sees all.
		if p != nil && !p.Admin && infos[i].Owner != p.Name {
			continue
		}
		views = append(views, sandboxView(&infos[i].Sandbox, infos[i].Owner))
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
	owner, _ := s.mgr.SandboxOwner(id)
	view := sandboxView(sb, owner)
	u := s.mgr.SandboxUsage(id)
	view["usage"] = map[string]any{"tokens": u.Tokens, "cost_usd": u.CostUSD}
	if p, err := s.loadProfileByName(sb.Profile); err == nil {
		view["limits"] = map[string]any{
			"max_tokens":      p.Limits.MaxTokens,
			"max_cost_usd":    p.Limits.MaxCostUSD,
			"max_execs":       p.Limits.MaxExecs,
			"egress_requests": p.Limits.EgressRequests,
			"wall_clock":      p.Limits.WallClock,
		}
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleKillSandbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.mgr.KillSandbox(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

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
	s.writeToolResult(w, res, err)
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
	s.writeToolResult(w, res, err)
}

func (s *Server) handleBrowserOpen(w http.ResponseWriter, r *http.Request) {
	sid, res, err := s.mgr.BrowserOpen(r.Context(), r.PathValue("id"))
	if err != nil {
		writeServerError(w, s.logger, err)
		return
	}
	if res != nil && res.Verdict != profile.VerdictAllow {
		s.writeToolResult(w, res, nil)
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
	s.writeToolResult(w, res, err)
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
	s.writeToolResult(w, res, err)
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	code, ok := decodeCode(w, r)
	if !ok {
		return
	}
	res, err := s.mgr.Node(r.Context(), r.PathValue("id"), code)
	s.writeToolResult(w, res, err)
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
	if handled := s.writeIfBlocked(w, res, err); handled {
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
	if handled := s.writeIfBlocked(w, res, err); handled {
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
	if handled := s.writeIfBlocked(w, res, err); handled {
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
	if handled := s.writeIfBlocked(w, res, err); handled {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": res.Stdout, "verdict": res.Verdict})
}

// handleReportUsage records model token/cost usage against a sandbox so it
// counts toward the profile's budget. Agents or fleet workers post the usage
// they observe from the model provider.
func (s *Server) handleReportUsage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tokens  int64   `json:"tokens"`
		CostUSD float64 `json:"cost_usd"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	if err := s.mgr.RecordUsage(id, req.Tokens, req.CostUSD); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	u := s.mgr.SandboxUsage(id)
	writeJSON(w, http.StatusOK, map[string]any{"tokens": u.Tokens, "cost_usd": u.CostUSD})
}

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
	if p := principalFrom(r.Context()); p != nil && !p.Admin {
		filtered := make([]backend.SnapshotRef, 0, len(snaps))
		for _, snap := range snaps {
			if p.CanLaunch(snap.Profile) {
				filtered = append(filtered, snap)
			}
		}
		snaps = filtered
	}
	if snaps == nil {
		snaps = []backend.SnapshotRef{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps})
}

func (s *Server) handleRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	owner := ""
	if p := principalFrom(r.Context()); p != nil {
		if !p.Admin && !s.snapshotVisibleTo(p, r.PathValue("id")) {
			writeError(w, http.StatusNotFound, "snapshot not found")
			return
		}
		owner = p.Name
	}
	sb, err := s.mgr.RestoreSnapshot(r.Context(), r.PathValue("id"), owner)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sandboxView(sb, owner))
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if p := principalFrom(r.Context()); p != nil && !p.MayApprove() {
		writeError(w, http.StatusForbidden, "not authorized to view approvals")
		return
	}
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
	if p := principalFrom(r.Context()); p != nil && !p.MayApprove() {
		writeError(w, http.StatusForbidden, "not authorized to resolve approvals")
		return
	}
	if ok := s.mgr.ResolveApproval(r.PathValue("id"), approve, approver(r)); !ok {
		writeError(w, http.StatusNotFound, "approval not found or already resolved")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// approver identifies who resolved an approval for the audit record. It prefers
// an explicit X-Runeward-Actor header (or ?actor= query), falling back to the
// peer address so a decision is never recorded as fully anonymous.
func approver(r *http.Request) string {
	// A resolved RBAC principal is the most trustworthy actor identity.
	if p := principalFrom(r.Context()); p != nil && p.Name != "" {
		return p.Name
	}
	if a := r.Header.Get("X-Runeward-Actor"); a != "" {
		return a
	}
	if a := r.URL.Query().Get("actor"); a != "" {
		return a
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	events, err := s.mgr.Ledger().Replay(r.PathValue("id"))
	if err != nil {
		writeServerError(w, s.logger, err)
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
	if p := principalFrom(r.Context()); p != nil && !p.Admin {
		writeError(w, http.StatusForbidden, "not authorized to export audit bundle")
		return
	}
	session := r.URL.Query().Get("session")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=runeward-audit-bundle.json")
	if err := s.mgr.ExportBundle(w, session); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
}

func (s *Server) handleEgressLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.mgr.Sandbox(id); !ok {
		writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	// Strict egress sidecars run out-of-process, so only in-process host/transparent
	// proxy decisions are currently visible in this bounded in-memory buffer.
	decisions := egress.ListDecisions(id)
	if decisions == nil {
		decisions = []egress.Decision{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": decisions})
}

func (s *Server) handlePolicySimulate(w http.ResponseWriter, r *http.Request) {
	type actionReq struct {
		Name    string   `json:"name"`
		Tool    string   `json:"tool"`
		Arg     string   `json:"arg"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	var req struct {
		ProfileName string           `json:"profile_name"`
		Profile     *profile.Profile `json:"profile"`
		Actions     []actionReq      `json:"actions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Actions) == 0 {
		writeError(w, http.StatusBadRequest, "actions is required")
		return
	}

	p, err := s.resolveSimulationProfile(req.ProfileName, req.Profile)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	engine, err := simulationEngineForProfile(p)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	results := make([]map[string]any, 0, len(req.Actions))
	for _, a := range req.Actions {
		arg := strings.TrimSpace(a.Arg)
		if arg == "" {
			arg = strings.TrimSpace(a.Command)
		}
		if arg == "" && len(a.Args) > 0 {
			arg = strings.Join(a.Args, " ")
		}
		act := policy.Action{
			Tool: strings.TrimSpace(a.Tool),
			Arg:  arg,
			Args: a.Args,
		}
		dec := engine.Evaluate(act)
		var matchedRule map[string]any
		if dec.Rule != nil {
			matchedRule = map[string]any{
				"tool":       dec.Rule.Tool,
				"match":      dec.Rule.Match,
				"match_argv": dec.Rule.MatchArgv,
				"verdict":    dec.Rule.Verdict,
				"reason":     dec.Rule.Reason,
			}
		}
		results = append(results, map[string]any{
			"name":         a.Name,
			"tool":         act.Tool,
			"arg":          act.Arg,
			"args":         act.Args,
			"verdict":      dec.Verdict,
			"reason":       dec.Reason,
			"matched_rule": matchedRule,
			"trace":        firstMatchTrace(p, act),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile": map[string]any{
			"name":   p.Name,
			"source": p.Source,
		},
		"results": results,
	})
}

func (s *Server) resolveSimulationProfile(profileName string, inline *profile.Profile) (*profile.Profile, error) {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" && inline == nil {
		return nil, errors.New("profile_name or profile is required")
	}
	if profileName != "" && inline != nil {
		return nil, errors.New("provide profile_name or profile, not both")
	}
	if profileName != "" {
		return s.loadProfileByName(profileName)
	}
	p := *inline
	if p.Name == "" {
		p.Name = "inline"
	}
	if p.Host.Type == "" {
		p.Host.Type = profile.HostContainer
	}
	if p.Host.Workdir == "" {
		p.Host.Workdir = "/workspace"
	}
	if p.Host.Image == "" {
		p.Host.Image = "ghcr.io/runewardd/runeward-sandbox:latest"
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid inline profile: %w", err)
	}
	return &p, nil
}

func (s *Server) loadProfileByName(name string) (*profile.Profile, error) {
	configDir := strings.TrimSpace(os.Getenv("RUNEWARD_CONFIG_DIR"))
	return profile.Load(name, profile.Options{ConfigDir: configDir})
}

func simulationEngineForProfile(p *profile.Profile) (policy.Evaluator, error) {
	noMatch := profile.VerdictAllow
	if strings.EqualFold(strings.TrimSpace(string(p.PolicyDefault)), string(profile.VerdictDeny)) {
		noMatch = profile.VerdictDeny
	}
	switch {
	case p.UsesPolicyBundle():
		return nil, fmt.Errorf("profile %q uses an OCI policy bundle (%s), which is not supported by policy simulation", p.Name, p.PolicyBundle.Ref)
	case p.UsesRego():
		module := p.Rego.Module
		if module == "" && p.Rego.File != "" {
			b, err := os.ReadFile(expandHomePath(p.Rego.File))
			if err != nil {
				return nil, fmt.Errorf("read rego policy %q: %w", p.Rego.File, err)
			}
			module = string(b)
		}
		return policy.NewRego(module, p.Rego.Query, noMatch)
	case p.UsesCEL():
		return policy.NewCEL(p.CEL, noMatch)
	default:
		return policy.New(p.Policy, noMatch), nil
	}
}

func firstMatchTrace(p *profile.Profile, act policy.Action) []map[string]any {
	trace := make([]map[string]any, 0)
	switch {
	case p.UsesCEL():
		for i, rule := range p.CEL {
			engine, err := policy.NewCEL([]profile.CELRule{rule}, profile.VerdictDeny)
			matched := false
			if err == nil {
				matched = engine.Evaluate(act).Rule != nil
			}
			trace = append(trace, map[string]any{
				"index":   i + 1,
				"engine":  "cel",
				"expr":    rule.Expr,
				"verdict": rule.Verdict,
				"matched": matched,
			})
			if matched {
				break
			}
		}
	case p.UsesRego():
		trace = append(trace, map[string]any{
			"index":   1,
			"engine":  "rego",
			"query":   p.Rego.Query,
			"matched": true,
		})
	default:
		for i, rule := range p.Policy {
			engine := policy.New([]profile.PolicyRule{rule}, profile.VerdictDeny)
			dec := engine.Evaluate(act)
			matched := dec.Rule != nil
			trace = append(trace, map[string]any{
				"index":      i + 1,
				"engine":     "builtin",
				"tool":       rule.Tool,
				"match":      rule.Match,
				"match_argv": rule.MatchArgv,
				"verdict":    rule.Verdict,
				"matched":    matched,
			})
			if matched {
				break
			}
		}
	}
	return trace
}

func expandHomePath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func sandboxView(sb *backend.Sandbox, owner string) map[string]any {
	v := map[string]any{
		"id":      sb.ID,
		"profile": sb.Profile,
		"backend": sb.Backend,
		"image":   sb.Image,
		"status":  sb.Status,
	}
	if owner != "" {
		v["owner"] = owner
	}
	return v
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
func (s *Server) writeToolResult(w http.ResponseWriter, res *controlplane.ToolResult, err error) {
	if err != nil {
		writeServerError(w, s.logger, err)
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
func (s *Server) writeIfBlocked(w http.ResponseWriter, res *controlplane.ToolResult, err error) bool {
	if err != nil {
		writeServerError(w, s.logger, err)
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
