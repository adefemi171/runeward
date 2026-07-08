// Package controlplane is runeward's governed execution core. Every tool call
// runs through one path: policy, approval gate, guardrails, backend exec, audit
// ledger. The Manager owns sandbox sessions and the shared ledger; the REST and
// MCP servers are thin adapters over it.
package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Runewardd/runeward/internal/accounting"
	"github.com/Runewardd/runeward/internal/anomaly"
	"github.com/Runewardd/runeward/internal/auditsink"
	"github.com/Runewardd/runeward/internal/backend"
	"github.com/Runewardd/runeward/internal/ledger"
	"github.com/Runewardd/runeward/internal/obs"
	"github.com/Runewardd/runeward/internal/policy"
	"github.com/Runewardd/runeward/internal/policybundle"
	"github.com/Runewardd/runeward/internal/profile"
	"github.com/Runewardd/runeward/internal/secrets"
	"github.com/pelletier/go-toml/v2"
)

// Manager is the control-plane core. It is safe for concurrent use.
type Manager struct {
	configDir string

	ledger    *ledger.Ledger
	signer    *ledger.Signer
	approvals *ApprovalStore

	// sink streams audit events to external destinations (webhook/file) in
	// real time. Never nil; a no-op sink when nothing is configured.
	sink auditsink.Sink

	// accounting tracks per-sandbox and per-profile token/cost usage reported
	// via the usage API, and enforces profile budget limits. Never nil.
	accounting *accounting.Tracker

	// approvalWait bounds how long a require-approval call blocks before the
	// REST layer returns 202 pending.
	approvalWait time.Duration

	mu       sync.Mutex
	sessions map[string]*Session

	snapMu    sync.Mutex
	snapshots map[string]backend.SnapshotRef

	fleetMu sync.Mutex
	fleets  map[string]*Fleet

	stateDir   string        // ledger, keys, fleets.json
	fleetLease time.Duration // claim lease for dead-worker recovery
	sweepStop  chan struct{}
	sweepDone  chan struct{}
}

// Session is the per-sandbox governed state.
type Session struct {
	Sandbox *backend.Sandbox
	Backend backend.Backend
	Profile *profile.Profile
	Engine  policy.Evaluator
	Guard   *policy.Guard

	Env     map[string]string
	Workdir string

	// Owner is the name of the RBAC principal that created the sandbox, used
	// for per-principal ("multi-user") visibility and access control. Empty
	// when RBAC is not configured.
	Owner string

	// secrets are resolved secret env values, kept so they can be redacted
	// from ledger payloads.
	secrets []string
	// scrubber applies built-in and profile-specific audit scrub patterns.
	scrubber *ledger.Scrubber

	browserMu sync.Mutex
	browsers  map[string]*browserSession // live CDP sessions, keyed by session id
}

func (s *Session) eventScrubber() *ledger.Scrubber {
	if s != nil && s.scrubber != nil {
		return s.scrubber
	}
	return ledger.NewScrubber()
}

// New constructs a Manager and opens the shared audit ledger.
func New(configDir string) (*Manager, error) {
	path, err := defaultLedgerPath()
	if err != nil {
		return nil, err
	}
	l, err := ledger.Open(path)
	if err != nil {
		return nil, err
	}

	// Signing is on by default; RUNEWARD_LEDGER_SIGN=off disables it.
	var signer *ledger.Signer
	if !strings.EqualFold(os.Getenv("RUNEWARD_LEDGER_SIGN"), "off") {
		s, err := ledger.LoadOrCreateSigner(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		l.SetSigner(s)
		signer = s
	}

	// Optional real-time audit fan-out (webhook/file); a misconfigured sink is
	// a hard error so it isn't silently ignored. The ledger anomaly detector is
	// always chained in so novel-egress / exec-burst / denial-spike patterns are
	// surfaced regardless of whether an external sink is configured.
	envSink, err := auditsink.FromEnv(nil)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("configure audit sink: %w", err)
	}
	sink := auditsink.NewMulti(envSink, anomaly.New(nil))

	m := &Manager{
		configDir:    configDir,
		ledger:       l,
		signer:       signer,
		sink:         sink,
		accounting:   accounting.New(),
		approvals:    NewApprovalStore(),
		approvalWait: 5 * time.Minute,
		sessions:     make(map[string]*Session),
		snapshots:    make(map[string]backend.SnapshotRef),
		fleets:       make(map[string]*Fleet),
		stateDir:     filepath.Dir(path),
		fleetLease:   fleetLeaseFromEnv(),
	}
	if err := m.loadFleets(); err != nil {
		return nil, err
	}
	m.startSweeper(30 * time.Second)
	return m, nil
}

// fleetLeaseFromEnv reads $RUNEWARD_FLEET_LEASE (default 2m; "0"/"off" disables).
func fleetLeaseFromEnv() time.Duration {
	v := os.Getenv("RUNEWARD_FLEET_LEASE")
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return 2 * time.Minute
	case "0", "off", "none":
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return 2 * time.Minute
}

// Signed reports whether the ledger is being signed.
func (m *Manager) Signed() bool { return m.signer != nil }

// appendAudit writes an event to the ledger, logging (rather than silently
// dropping) a failure so a broken audit trail is at least visible.
func (m *Manager) appendAudit(ev ledger.Event) {
	if _, err := m.ledger.Append(ev); err != nil {
		log.Printf("runeward: audit ledger append failed (tool=%s verdict=%s): %v", ev.Tool, ev.Verdict, err)
	}
	// Fan out to external sinks (non-blocking); redaction already applied by
	// the caller so the streamed event matches the ledger record.
	if m.sink != nil {
		m.sink.Emit(ev)
	}
}

// recordFleet appends a fleet-level audit event.
func (m *Manager) recordFleet(f *Fleet, action, taskID, reason string) {
	ev := ledger.Event{
		SessionID: "fleet:" + f.ID,
		Profile:   f.Profile,
		Tool:      "fleet",
		Action:    action,
		Verdict:   string(profile.VerdictAllow),
	}
	if taskID != "" {
		ev.Args = []string{taskID}
	}
	if reason != "" {
		ev.Meta = map[string]string{"reason": reason}
	}
	m.appendAudit(ev)
}

// LedgerPublicKey returns the base64 signing key and key id, or empty strings
// when signing is disabled.
func (m *Manager) LedgerPublicKey() (pub string, keyID string) {
	if m.signer == nil {
		return "", ""
	}
	return base64.StdEncoding.EncodeToString(m.signer.Public()), m.signer.KeyID()
}

// ExportBundle writes a verifiable transcript of a session's audit events (all
// events when sessionID is "") to w. Fails when signing is disabled.
func (m *Manager) ExportBundle(w io.Writer, sessionID string) error {
	if m.signer == nil {
		return fmt.Errorf("ledger signing is disabled; no verifiable transcript to export")
	}
	return m.ledger.ExportBundle(w, sessionID, m.signer.Public())
}

// VerifyLedger checks the hash chain and, when signing is enabled, signatures.
func (m *Manager) VerifyLedger() error {
	if m.signer != nil {
		return m.ledger.VerifySignatures(m.signer.Public(), false)
	}
	return m.ledger.Verify()
}

// Close stops the sweeper, flushes audit sinks, and releases the ledger handle.
func (m *Manager) Close() error {
	m.stopSweeper()
	if m.sink != nil {
		_ = m.sink.Close()
	}
	return m.ledger.Close()
}

// Ledger returns the shared ledger.
func (m *Manager) Ledger() *ledger.Ledger { return m.ledger }

// StateDir returns the directory holding runeward state (ledger, keys, and
// terminal recordings).
func (m *Manager) StateDir() string { return m.stateDir }

// Approvals returns the approval store.
func (m *Manager) Approvals() *ApprovalStore { return m.approvals }

// ResolveApproval resolves a pending approval and records who decided it in the
// tamper-evident ledger, so a human-in-the-loop decision is always attributed.
// It reports whether the id was pending.
func (m *Manager) ResolveApproval(id string, approve bool, actor string) bool {
	view, ok := m.approvals.ResolveView(id, approve)
	if !ok {
		return false
	}
	if strings.TrimSpace(actor) == "" {
		actor = "unknown"
	}
	decision, verdict := "approved", string(profile.VerdictAllow)
	if !approve {
		decision, verdict = "denied", string(profile.VerdictDeny)
	}

	ev := ledger.Event{
		SessionID: view.Sandbox,
		Sandbox:   view.Sandbox,
		Tool:      "approval",
		Action:    view.Action,
		Args:      []string{view.Tool},
		Verdict:   verdict,
		Meta: map[string]string{
			"decision":    decision,
			"approver":    actor,
			"approval_id": view.ID,
		},
	}
	if view.Reason != "" {
		ev.Meta["reason"] = view.Reason
	}

	m.mu.Lock()
	sess := m.sessions[view.Sandbox]
	m.mu.Unlock()
	if sess != nil {
		ev.Profile = sess.Profile.Name
		if sess.Profile.Audit.RedactEnabled() {
			ev = sess.eventScrubber().Scrub(ev, sess.secrets...)
		}
	} else {
		ev = ledger.Scrub(ev)
	}
	obs.RecordAction("approval", verdict, 0)
	m.appendAudit(ev)
	return true
}

// ProfileInfo is a lightweight profile descriptor for listing.
type ProfileInfo struct {
	Name   string `json:"name"`
	Host   string `json:"host"`
	Egress string `json:"egress"`
}

// ListProfiles returns the resolvable profiles for the configured search path.
func (m *Manager) ListProfiles() ([]ProfileInfo, error) {
	names, err := profile.List(profile.Options{ConfigDir: m.configDir})
	if err != nil {
		return nil, err
	}
	out := make([]ProfileInfo, 0, len(names))
	for _, n := range names {
		info := ProfileInfo{Name: n, Host: string(profile.HostContainer), Egress: "open"}
		if p, err := profile.Load(n, profile.Options{ConfigDir: m.configDir}); err == nil {
			if p.Host.Type != "" {
				info.Host = string(p.Host.Type)
			}
			if p.Network.DenyByDefault() {
				info.Egress = "deny-by-default"
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// CreateOptions carries per-create overrides that are not part of the profile.
type CreateOptions struct {
	// CopyFrom overrides host.copy_from for this create: a one-time copy into
	// the fresh workspace, the host dir is never mounted. "~/" is expanded.
	CopyFrom string
	// Owner records the RBAC principal that created the sandbox, for
	// per-principal visibility and access control. Empty means unowned
	// (RBAC disabled), in which case every caller can see it.
	Owner string
}

// CreateSandbox loads the named profile, provisions a sandbox on its backend,
// and registers a governed session for it.
func (m *Manager) CreateSandbox(ctx context.Context, profileName string, opts CreateOptions) (*backend.Sandbox, error) {
	p, err := profile.Load(profileName, profile.Options{ConfigDir: m.configDir})
	if err != nil {
		return nil, err
	}
	extraScrubPatterns, err := compileAuditScrubPatterns(p.Audit.ScrubPatterns)
	if err != nil {
		return nil, err
	}

	env, secrets, err := resolveEnv(p)
	if err != nil {
		return nil, err
	}

	be, err := backend.For(p)
	if err != nil {
		return nil, err
	}
	spec := backend.SpecFromProfile(p, env)
	if opts.CopyFrom != "" {
		spec.SeedDir = expandHome(opts.CopyFrom)
	}
	sb, err := be.Create(ctx, spec)
	if err != nil {
		return nil, err
	}

	guard, err := policyGuard(p)
	if err != nil {
		_ = be.Kill(context.Background(), sb.ID)
		return nil, err
	}

	engine, err := newEngine(p)
	if err != nil {
		_ = be.Kill(context.Background(), sb.ID)
		return nil, err
	}

	sess := &Session{
		Sandbox:  sb,
		Backend:  be,
		Profile:  p,
		Engine:   engine,
		Guard:    guard,
		Env:      env,
		Workdir:  p.Host.Workdir,
		Owner:    opts.Owner,
		secrets:  secrets,
		scrubber: ledger.NewScrubber(extraScrubPatterns...),
	}

	m.mu.Lock()
	m.sessions[sb.ID] = sess
	m.mu.Unlock()

	obs.IncSandboxCreated()
	m.record(sess, "sandbox", "create", nil, string(profile.VerdictAllow), 0, 0, "")
	return sb, nil
}

// Sandbox returns the handle for a sandbox id.
func (m *Manager) Sandbox(id string) (*backend.Sandbox, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, false
	}
	return s.Sandbox, true
}

// ListSandboxes returns handles for every governed sandbox.
func (m *Manager) ListSandboxes() []backend.Sandbox {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]backend.Sandbox, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, *s.Sandbox)
	}
	return out
}

// SandboxInfo pairs a sandbox handle with its owning principal for listing.
type SandboxInfo struct {
	Sandbox backend.Sandbox
	Owner   string
}

// ListSandboxInfos returns every governed sandbox together with its owner. The
// server uses this to filter the list per principal ("multi-user" views).
func (m *Manager) ListSandboxInfos() []SandboxInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SandboxInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, SandboxInfo{Sandbox: *s.Sandbox, Owner: s.Owner})
	}
	return out
}

// SandboxOwner returns the owning principal for a sandbox id. ok is false when
// the sandbox is unknown; a known-but-unowned sandbox returns ("", true).
func (m *Manager) SandboxOwner(id string) (owner string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return "", false
	}
	return s.Owner, true
}

// KillSandbox tears down a sandbox and removes its session.
func (m *Manager) KillSandbox(ctx context.Context, id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return notFoundError("sandbox %q not found", id)
	}
	if m.accounting != nil {
		m.accounting.Forget(id)
	}
	m.record(sess, "sandbox", "kill", nil, string(profile.VerdictAllow), 0, 0, "")
	return sess.Backend.Kill(ctx, id)
}

// RecordUsage attributes reported model usage (tokens and/or US-dollar spend)
// to a sandbox, updating the accounting totals and metrics and appending an
// audit event. Callers (agents, fleet workers) report usage they observe from
// the model provider; once the profile's budget is exceeded, govern denies
// further tool calls. It errors if the sandbox is unknown.
func (m *Manager) RecordUsage(id string, tokens int64, costUSD float64) error {
	sess, err := m.session(id)
	if err != nil {
		return err
	}
	if m.accounting == nil {
		return fmt.Errorf("usage accounting is not initialized")
	}

	if tokens < 0 || costUSD < 0 {
		return fmt.Errorf("usage deltas must be non-negative")
	}
	if math.IsNaN(costUSD) || math.IsInf(costUSD, 0) {
		return fmt.Errorf("cost_usd must be finite")
	}
	if tokens > maxClientUsageTokenDelta || costUSD > maxClientUsageCostDelta {
		return nil
	}
	u := m.accounting.Usage(id)
	if tokens > math.MaxInt64-u.Tokens || costUSD > math.MaxFloat64-u.CostUSD {
		return nil
	}

	m.accounting.Record(sess.Profile.Name, id, tokens, costUSD)
	u = m.accounting.Usage(id)
	ev := ledger.Event{
		SessionID: id,
		Sandbox:   id,
		Profile:   sess.Profile.Name,
		Tool:      "usage",
		Action:    "report",
		Verdict:   string(profile.VerdictAllow),
		Meta: map[string]string{
			"tokens":       strconv.FormatInt(tokens, 10),
			"cost_usd":     strconv.FormatFloat(costUSD, 'f', -1, 64),
			"tokens_tot":   strconv.FormatInt(u.Tokens, 10),
			"cost_usd_tot": strconv.FormatFloat(u.CostUSD, 'f', -1, 64),
		},
	}
	m.appendAudit(ev)
	return nil
}

// SandboxUsage returns the cumulative reported usage for a sandbox.
func (m *Manager) SandboxUsage(id string) accounting.Usage {
	if m.accounting == nil {
		return accounting.Usage{}
	}
	return m.accounting.Usage(id)
}

// AttachTerminal wires an interactive PTY to the sandbox. Terminals are not
// policy-gated per keystroke, but the attach itself is audited.
func (m *Manager) AttachTerminal(ctx context.Context, id string, stream backend.PTYStream) error {
	sess, err := m.session(id)
	if err != nil {
		return err
	}
	// A raw terminal is an unrestricted RCE primitive that bypasses per-action
	// policy, so it is itself policy-gated as tool "terminal" (a profile can
	// deny it in hardened mode). require-approval isn't meaningful for an
	// interactive attach, so it is treated as deny here.
	dec := sess.Engine.Evaluate(policy.Action{Tool: "terminal", Arg: "attach"})
	if dec.Verdict != profile.VerdictAllow {
		reason := orReason(dec.Reason, "terminal attach denied by policy")
		m.record(sess, "terminal", "attach", nil, string(profile.VerdictDeny), -1, 0, reason)
		return fmt.Errorf("%s", reason)
	}
	m.record(sess, "terminal", "attach", nil, string(profile.VerdictAllow), 0, 0, "")
	return sess.Backend.AttachPTY(ctx, id, stream)
}

func (m *Manager) session(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, notFoundError("sandbox %q not found", id)
	}
	return s, nil
}

// govern runs one action through the governed path. run is only invoked once
// the action is authorized and within guardrails.
func (m *Manager) govern(ctx context.Context, sess *Session, tool, arg string, args []string, run func(context.Context) (*backend.ExecResult, error)) (*ToolResult, error) {
	return m.governOut(ctx, sess, tool, arg, args, false, run)
}

// governOut is govern with control over stdout scrubbing. When rawStdout is
// true the text secret-scrubber is skipped for stdout (stderr is still
// scrubbed): callers use this for binary artifacts like browser screenshots,
// whose base64 would otherwise be masked wholesale by the high-entropy blob
// detector, destroying the image.
func (m *Manager) governOut(ctx context.Context, sess *Session, tool, arg string, args []string, rawStdout bool, run func(context.Context) (*backend.ExecResult, error)) (*ToolResult, error) {
	dec := sess.Engine.Evaluate(policy.Action{Tool: tool, Arg: arg, Args: args})

	switch dec.Verdict {
	case profile.VerdictDeny:
		reason := orReason(dec.Reason, "denied by policy")
		m.record(sess, tool, arg, args, string(profile.VerdictDeny), -1, 0, reason)
		return &ToolResult{Verdict: profile.VerdictDeny, Reason: reason}, nil

	case profile.VerdictRequireApprove:
		reason := orReason(dec.Reason, "approval required")
		ap := m.approvals.Create(sess.Sandbox.ID, tool, arg, reason)
		m.record(sess, "approval", arg, args, string(profile.VerdictRequireApprove), -1, 0, reason)

		wait := ctx
		var cancel context.CancelFunc
		if m.approvalWait > 0 {
			wait, cancel = context.WithTimeout(ctx, m.approvalWait)
			defer cancel()
		}
		select {
		case ok := <-ap.decided:
			if !ok {
				m.record(sess, tool, arg, args, string(profile.VerdictDeny), -1, 0, "denied by approver")
				return &ToolResult{Verdict: profile.VerdictDeny, Reason: "denied by approver", ApprovalID: ap.ID}, nil
			}
			// Approved: fall through to guardrails + execution.
		case <-wait.Done():
			m.approvals.forget(ap.ID)
			return &ToolResult{Verdict: profile.VerdictRequireApprove, Pending: true, ApprovalID: ap.ID, Reason: reason}, nil
		}
	}

	if err := sess.Guard.CheckExec(); err != nil {
		m.record(sess, tool, arg, args, string(profile.VerdictDeny), -1, 0, err.Error())
		return &ToolResult{Verdict: profile.VerdictDeny, Reason: err.Error()}, nil
	}

	// Enforce the spend/token budget: once a sandbox's reported usage exceeds
	// the profile's limits, further tool calls are denied fail-closed.
	if m.accounting != nil && !ignoreClientUsageBudget() {
		if over, why := m.accounting.Over(sess.Sandbox.ID, sess.Profile.Limits.MaxTokens, sess.Profile.Limits.MaxCostUSD); over {
			m.record(sess, tool, arg, args, string(profile.VerdictDeny), -1, 0, why)
			return &ToolResult{Verdict: profile.VerdictDeny, Reason: why}, nil
		}
	}

	// Enforce the egress budget for outbound tools (previously dead code).
	if isEgressTool(tool) {
		if err := sess.Guard.CheckEgress(); err != nil {
			m.record(sess, tool, arg, args, string(profile.VerdictDeny), -1, 0, err.Error())
			return &ToolResult{Verdict: profile.VerdictDeny, Reason: err.Error()}, nil
		}
	}

	res, err := run(ctx)
	loopKey := tool + "|" + arg
	if err != nil {
		sess.Guard.RecordOutcome(loopKey, true)
		m.record(sess, tool, arg, args, "error", -1, 0, err.Error())
		return nil, err
	}
	sess.Guard.RecordOutcome(loopKey, res.ExitCode != 0)
	m.record(sess, tool, arg, args, string(profile.VerdictAllow), res.ExitCode, res.Duration.Milliseconds(), "")

	// Redact secrets from returned output too, not just the ledger, so a leaked
	// credential in stdout/stderr doesn't reach the API/MCP client in cleartext.
	stdout, stderr := res.Stdout, res.Stderr
	if sess.Profile.Audit.RedactEnabled() {
		if !rawStdout {
			stdout = sess.eventScrubber().ScrubString(stdout, sess.secrets...)
		}
		stderr = sess.eventScrubber().ScrubString(stderr, sess.secrets...)
	}

	return &ToolResult{
		Verdict:    profile.VerdictAllow,
		ExitCode:   res.ExitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		DurationMS: res.Duration.Milliseconds(),
	}, nil
}

// isEgressTool reports whether a tool causes outbound network access subject to
// the egress budget.
func isEgressTool(tool string) bool {
	return tool == "browser" || tool == "net"
}

// record appends an event to the ledger.
func (m *Manager) record(sess *Session, tool, action string, args []string, verdict string, exit int, durMS int64, reason string) {
	ev := ledger.Event{
		SessionID:  sess.Sandbox.ID,
		Sandbox:    sess.Sandbox.ID,
		Profile:    sess.Profile.Name,
		Tool:       tool,
		Action:     action,
		Args:       args,
		Verdict:    verdict,
		ExitCode:   exit,
		DurationMS: durMS,
	}
	if reason != "" {
		ev.Meta = map[string]string{"reason": reason}
	}
	obs.RecordAction(tool, verdict, durMS)
	// Scrub declared secret values (hashed) and pattern-detected credentials
	// (masked) from the payload. Unlike a whole-payload hash, this keeps the
	// trail readable while catching secrets pasted into a command or snippet.
	if sess.Profile.Audit.RedactEnabled() {
		ev = sess.eventScrubber().Scrub(ev, sess.secrets...)
	}
	m.appendAudit(ev)
}

// defaultLedgerPath returns the ledger file location, honoring
// $RUNEWARD_STATE_DIR and falling back to the user cache dir.
func defaultLedgerPath() (string, error) {
	dir := os.Getenv("RUNEWARD_STATE_DIR")
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "runeward")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "ledger.jsonl"), nil
}

// resolveEnv turns a profile's [[env]] entries into literal values and returns
// the resolved secret values for redaction. It fails closed: an env entry that
// names a source it can't resolve (unreadable file, or a scheme reference such
// as env://, vault://, op:// that the resolver rejects) is an error rather than
// a silently-missing secret, so a sandbox never starts believing it has a
// credential it does not.
func resolveEnv(p *profile.Profile) (map[string]string, []string, error) {
	out := make(map[string]string, len(p.Env))
	var secretVals []string
	resolver := secrets.Default()
	for _, e := range p.Env {
		var val string
		switch {
		case e.Op != "":
			// e.Op holds a scheme reference (op://, vault://, env://). Resolve
			// it fail-closed: an unresolvable reference is an error so a
			// sandbox never starts believing it has a credential it doesn't.
			resolved, err := resolver.Resolve(context.Background(), e.Op)
			if err != nil {
				return nil, nil, fmt.Errorf("env %q: resolve %q: %w", e.Name, e.Op, err)
			}
			val = resolved
		case e.File != "":
			b, err := os.ReadFile(expandHome(e.File))
			if err != nil {
				return nil, nil, fmt.Errorf("env %q: read file %q: %w", e.Name, e.File, err)
			}
			val = strings.TrimRight(string(b), "\r\n")
		case e.Value != "":
			val = e.Value
		default:
			continue
		}
		out[e.Name] = val
		if e.Secret() && val != "" {
			secretVals = append(secretVals, val)
		}
	}
	return out, secretVals, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

// newEngine builds the policy engine for a profile: Rego or CEL when requested,
// otherwise the built-in first-match glob engine.
func newEngine(p *profile.Profile) (policy.Evaluator, error) {
	noMatch := noMatchPolicyVerdict(p)
	switch {
	case p.UsesPolicyBundle():
		return newBundleEngine(p)
	case p.UsesRego():
		module := p.Rego.Module
		if module == "" && p.Rego.File != "" {
			b, err := os.ReadFile(expandHome(p.Rego.File))
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

const bundlePullTimeout = 30 * time.Second

// newBundleEngine pulls the profile's OCI policy bundle and builds the engine
// from it. With a verify key configured, the bundle's ed25519 signature is
// required before its policy is trusted.
func newBundleEngine(p *profile.Profile) (policy.Evaluator, error) {
	noMatch := noMatchPolicyVerdict(p)
	pb := p.PolicyBundle
	var verify ed25519.PublicKey
	switch {
	case pb.VerifyKey != "":
		k, err := policybundle.DecodePublicKey(pb.VerifyKey)
		if err != nil {
			return nil, fmt.Errorf("policy bundle: %w", err)
		}
		verify = k
	case pb.Insecure:
		// Explicit, logged opt-out: pull without verifying the signature.
		log.Printf("runeward: WARNING: policy bundle %q pulled WITHOUT signature verification (insecure_skip_verify=true)", pb.Ref)
	default:
		// Fail closed: an unverified bundle is remotely-controlled policy, so
		// refuse rather than silently trusting whatever the registry serves.
		return nil, fmt.Errorf("policy bundle %q: verify_key is required; set policy_bundle.verify_key, or set insecure_skip_verify=true to explicitly accept an unsigned bundle", pb.Ref)
	}

	ctx, cancel := context.WithTimeout(context.Background(), bundlePullTimeout)
	defer cancel()

	b, err := policybundle.Pull(ctx, pb.Ref, verify, policybundle.PullOptions{PlainHTTP: pb.PlainHTTP})
	if err != nil {
		return nil, fmt.Errorf("policy bundle %q: %w", pb.Ref, err)
	}

	switch b.Engine {
	case policybundle.EngineRego:
		return policy.NewRego(string(b.Policy), b.Query, noMatch)
	case policybundle.EngineCEL:
		var frag struct {
			CEL []profile.CELRule `toml:"cel"`
		}
		if err := toml.Unmarshal(b.Policy, &frag); err != nil {
			return nil, fmt.Errorf("policy bundle %q: parse cel fragment: %w", pb.Ref, err)
		}
		return policy.NewCEL(frag.CEL, noMatch)
	default:
		return nil, fmt.Errorf("policy bundle %q: unknown engine %q", pb.Ref, b.Engine)
	}
}

func noMatchPolicyVerdict(p *profile.Profile) profile.Verdict {
	if p != nil {
		switch strings.ToLower(strings.TrimSpace(string(p.PolicyDefault))) {
		case string(profile.VerdictDeny):
			return profile.VerdictDeny
		case string(profile.VerdictAllow):
			return profile.VerdictAllow
		}
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RUNEWARD_POLICY_DEFAULT"))) {
	case string(profile.VerdictDeny):
		return profile.VerdictDeny
	case string(profile.VerdictAllow):
		return profile.VerdictAllow
	}
	return profile.VerdictAllow
}

func compileAuditScrubPatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, raw := range patterns {
		pat := strings.TrimSpace(raw)
		if pat == "" {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("audit.scrub_patterns %q: %w", pat, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

const (
	maxClientUsageTokenDelta int64   = 1_000_000_000
	maxClientUsageCostDelta  float64 = 1_000_000
)

func ignoreClientUsageBudget() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RUNEWARD_IGNORE_CLIENT_USAGE"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// policyGuard builds and starts the cost/loop guard for a profile.
func policyGuard(p *profile.Profile) (*policy.Guard, error) {
	g, err := policy.NewGuard(p.Limits)
	if err != nil {
		return nil, err
	}
	g.Start()
	return g, nil
}

func orReason(reason, fallback string) string {
	if strings.TrimSpace(reason) == "" {
		return fallback
	}
	return reason
}
