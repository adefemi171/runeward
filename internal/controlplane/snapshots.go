package controlplane

import (
	"context"
	"fmt"

	"github.com/Runewardd/runeward/internal/backend"
	"github.com/Runewardd/runeward/internal/profile"
)

// Snapshot captures a sandbox's workspace and registers the reference.
func (m *Manager) Snapshot(ctx context.Context, id, name string) (*backend.SnapshotRef, error) {
	sess, err := m.session(id)
	if err != nil {
		return nil, err
	}
	ref, err := sess.Backend.Snapshot(ctx, id, name)
	if err != nil {
		return nil, err
	}
	// Carry the originating profile so a restore can re-derive governance.
	ref.Profile = sess.Profile.Name

	m.snapMu.Lock()
	m.snapshots[ref.ID] = *ref
	m.snapMu.Unlock()

	m.record(sess, "snapshot", name, nil, string(profile.VerdictAllow), 0, 0, "snapshot "+ref.ID)
	return ref, nil
}

// ListSnapshots returns all captured snapshot references.
func (m *Manager) ListSnapshots() []backend.SnapshotRef {
	m.snapMu.Lock()
	defer m.snapMu.Unlock()
	out := make([]backend.SnapshotRef, 0, len(m.snapshots))
	for _, r := range m.snapshots {
		out = append(out, r)
	}
	return out
}

// RestoreSnapshot recreates a governed sandbox from a snapshot, re-deriving
// policy and guardrails from the snapshot's profile.
func (m *Manager) RestoreSnapshot(ctx context.Context, snapshotID, owner string) (*backend.Sandbox, error) {
	m.snapMu.Lock()
	ref, ok := m.snapshots[snapshotID]
	m.snapMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("snapshot %q not found", snapshotID)
	}

	p, err := profile.Load(ref.Profile, profile.Options{ConfigDir: m.configDir})
	if err != nil {
		return nil, fmt.Errorf("load snapshot profile %q: %w", ref.Profile, err)
	}
	env, secrets, err := resolveEnv(p)
	if err != nil {
		return nil, err
	}
	spec := backend.SpecFromProfile(p, env)

	be, err := backend.For(p)
	if err != nil {
		return nil, err
	}
	sb, err := backend.RestoreSnapshot(ctx, be, ref, spec)
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
		Owner:   owner,
		secrets: secrets,
	}
	m.mu.Lock()
	m.sessions[sb.ID] = sess
	m.mu.Unlock()

	m.record(sess, "snapshot", "restore", nil, string(profile.VerdictAllow), 0, 0, "from "+snapshotID)
	return sb, nil
}
