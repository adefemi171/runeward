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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/adefemi171/runeward/internal/backend"
	"github.com/adefemi171/runeward/internal/ledger"
	"github.com/adefemi171/runeward/internal/policy"
	"github.com/adefemi171/runeward/internal/policybundle"
	"github.com/adefemi171/runeward/internal/profile"
	"github.com/pelletier/go-toml/v2"
)

// Manager is the control-plane core. It is safe for concurrent use.
type Manager struct {
	configDir string

	ledger    *ledger.Ledger
	signer    *ledger.Signer
	approvals *ApprovalStore

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

	// secrets are resolved secret env values, kept so they can be redacted
	// from ledger payloads.
	secrets []string

	browserMu sync.Mutex
	browsers  map[string]*browserSession // live CDP sessions, keyed by session id
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

	m := &Manager{
		configDir:    configDir,
		ledger:       l,
		signer:       signer,
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
	_, _ = m.ledger.Append(ev)
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

// Close stops the sweeper and releases the ledger handle.
func (m *Manager) Close() error {
	m.stopSweeper()
	return m.ledger.Close()
}

// Ledger returns the shared ledger.
func (m *Manager) Ledger() *ledger.Ledger { return m.ledger }

// Approvals returns the approval store.
func (m *Manager) Approvals() *ApprovalStore { return m.approvals }

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
}

// CreateSandbox loads the named profile, provisions a sandbox on its backend,
// and registers a governed session for it.
func (m *Manager) CreateSandbox(ctx context.Context, profileName string, opts CreateOptions) (*backend.Sandbox, error) {
	p, err := profile.Load(profileName, profile.Options{ConfigDir: m.configDir})
	if err != nil {
		return nil, err
	}

	env, secrets := resolveEnv(p)

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
		Sandbox: sb,
		Backend: be,
		Profile: p,
		Engine:  engine,
		Guard:   guard,
		Env:     env,
		Workdir: p.Host.Workdir,
		secrets: secrets,
	}

	m.mu.Lock()
	m.sessions[sb.ID] = sess
	m.mu.Unlock()

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

// KillSandbox tears down a sandbox and removes its session.
func (m *Manager) KillSandbox(ctx context.Context, id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("sandbox %q not found", id)
	}
	m.record(sess, "sandbox", "kill", nil, string(profile.VerdictAllow), 0, 0, "")
	return sess.Backend.Kill(ctx, id)
}

// AttachTerminal wires an interactive PTY to the sandbox. Terminals are not
// policy-gated per keystroke, but the attach itself is audited.
func (m *Manager) AttachTerminal(ctx context.Context, id string, stream backend.PTYStream) error {
	sess, err := m.session(id)
	if err != nil {
		return err
	}
	m.record(sess, "terminal", "attach", nil, string(profile.VerdictAllow), 0, 0, "")
	return sess.Backend.AttachPTY(ctx, id, stream)
}

func (m *Manager) session(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("sandbox %q not found", id)
	}
	return s, nil
}

// govern runs one action through the governed path. run is only invoked once
// the action is authorized and within guardrails.
func (m *Manager) govern(ctx context.Context, sess *Session, tool, arg string, args []string, run func(context.Context) (*backend.ExecResult, error)) (*ToolResult, error) {
	dec := sess.Engine.Evaluate(policy.Action{Tool: tool, Arg: arg})

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

	res, err := run(ctx)
	loopKey := tool + "|" + arg
	if err != nil {
		sess.Guard.RecordOutcome(loopKey, true)
		m.record(sess, tool, arg, args, "error", -1, 0, err.Error())
		return nil, err
	}
	sess.Guard.RecordOutcome(loopKey, res.ExitCode != 0)
	m.record(sess, tool, arg, args, string(profile.VerdictAllow), res.ExitCode, res.Duration.Milliseconds(), "")

	return &ToolResult{
		Verdict:    profile.VerdictAllow,
		ExitCode:   res.ExitCode,
		Stdout:     res.Stdout,
		Stderr:     res.Stderr,
		DurationMS: res.Duration.Milliseconds(),
	}, nil
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
	// Only redact when there are known secrets: ledger.Redact with no values
	// hashes the whole payload, making the trail unreadable.
	if sess.Profile.Audit.RedactEnabled() && len(sess.secrets) > 0 {
		ev = ledger.Redact(ev, sess.secrets...)
	}
	_, _ = m.ledger.Append(ev)
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
// the resolved secret values for redaction.
func resolveEnv(p *profile.Profile) (map[string]string, []string) {
	out := make(map[string]string, len(p.Env))
	var secrets []string
	for _, e := range p.Env {
		var val string
		switch {
		case e.Op != "":
			continue // 1Password resolution deferred
		case e.File != "":
			b, err := os.ReadFile(expandHome(e.File))
			if err != nil {
				continue
			}
			val = strings.TrimRight(string(b), "\r\n")
		case e.Value != "":
			val = e.Value
		default:
			continue
		}
		out[e.Name] = val
		if e.Secret() && val != "" {
			secrets = append(secrets, val)
		}
	}
	return out, secrets
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
		return policy.NewRego(module, p.Rego.Query, profile.VerdictAllow)
	case p.UsesCEL():
		return policy.NewCEL(p.CEL, profile.VerdictAllow)
	default:
		return policy.New(p.Policy, profile.VerdictAllow), nil
	}
}

const bundlePullTimeout = 30 * time.Second

// newBundleEngine pulls the profile's OCI policy bundle and builds the engine
// from it. With a verify key configured, the bundle's ed25519 signature is
// required before its policy is trusted.
func newBundleEngine(p *profile.Profile) (policy.Evaluator, error) {
	pb := p.PolicyBundle
	var verify ed25519.PublicKey
	if pb.VerifyKey != "" {
		k, err := policybundle.DecodePublicKey(pb.VerifyKey)
		if err != nil {
			return nil, fmt.Errorf("policy bundle: %w", err)
		}
		verify = k
	}

	ctx, cancel := context.WithTimeout(context.Background(), bundlePullTimeout)
	defer cancel()

	b, err := policybundle.Pull(ctx, pb.Ref, verify, policybundle.PullOptions{PlainHTTP: pb.PlainHTTP})
	if err != nil {
		return nil, fmt.Errorf("policy bundle %q: %w", pb.Ref, err)
	}

	switch b.Engine {
	case policybundle.EngineRego:
		return policy.NewRego(string(b.Policy), b.Query, profile.VerdictAllow)
	case policybundle.EngineCEL:
		var frag struct {
			CEL []profile.CELRule `toml:"cel"`
		}
		if err := toml.Unmarshal(b.Policy, &frag); err != nil {
			return nil, fmt.Errorf("policy bundle %q: parse cel fragment: %w", pb.Ref, err)
		}
		return policy.NewCEL(frag.CEL, profile.VerdictAllow)
	default:
		return nil, fmt.Errorf("policy bundle %q: unknown engine %q", pb.Ref, b.Engine)
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
