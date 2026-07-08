package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/Runewardd/runeward/internal/fleet"
	"github.com/Runewardd/runeward/internal/profile"
)

// Fleet is a set of sandboxes from one profile sharing an atomic task board.
type Fleet struct {
	ID        string
	Profile   string
	Owner     string
	Board     *fleet.Board
	Sandboxes []string
	Created   time.Time
	// restored marks fleets loaded from disk; the board survives but the
	// sandboxes were not recreated.
	restored bool
}

// FleetView is the JSON projection of a fleet.
type FleetView struct {
	ID        string      `json:"id"`
	Profile   string      `json:"profile"`
	Owner     string      `json:"owner,omitempty"`
	Sandboxes []string    `json:"sandboxes"`
	Stats     fleet.Stats `json:"stats"`
	Created   time.Time   `json:"created"`
}

func (f *Fleet) view() FleetView {
	return FleetView{
		ID:        f.ID,
		Profile:   f.Profile,
		Owner:     f.Owner,
		Sandboxes: f.Sandboxes,
		Stats:     f.Board.Stats(),
		Created:   f.Created,
	}
}

// CreateFleet provisions the profile's replicas with a shared task board seeded
// from its task_board list.
func (m *Manager) CreateFleet(ctx context.Context, profileName string) (*FleetView, error) {
	return m.CreateFleetForOwner(ctx, profileName, "")
}

// CreateFleetForOwner provisions the profile's replicas with a shared task
// board seeded from its task_board list and attributes member sandboxes to the
// owning principal when provided.
func (m *Manager) CreateFleetForOwner(ctx context.Context, profileName, owner string) (*FleetView, error) {
	p, err := profile.Load(profileName, profile.Options{ConfigDir: m.configDir})
	if err != nil {
		return nil, err
	}
	replicas := 1
	var seed []string
	if p.Fleet != nil {
		if p.Fleet.Replicas > 0 {
			replicas = p.Fleet.Replicas
		}
		seed = p.Fleet.TaskBoard
	}

	board := fleet.Seed(seed)
	board.SetLease(m.fleetLease)
	f := &Fleet{
		ID:      newID(),
		Profile: profileName,
		Owner:   owner,
		Board:   board,
		Created: time.Now().UTC(),
	}

	for i := 0; i < replicas; i++ {
		sb, err := m.CreateSandbox(ctx, profileName, CreateOptions{Owner: owner})
		if err != nil {
			// Best-effort teardown of anything already created.
			for _, id := range f.Sandboxes {
				_ = m.KillSandbox(context.Background(), id)
			}
			return nil, fmt.Errorf("provision fleet replica %d/%d: %w", i+1, replicas, err)
		}
		f.Sandboxes = append(f.Sandboxes, sb.ID)
	}

	m.fleetMu.Lock()
	m.fleets[f.ID] = f
	m.fleetMu.Unlock()

	m.saveFleets()
	v := f.view()
	return &v, nil
}

// ListFleets returns all fleets.
func (m *Manager) ListFleets() []FleetView {
	m.fleetMu.Lock()
	defer m.fleetMu.Unlock()
	out := make([]FleetView, 0, len(m.fleets))
	for _, f := range m.fleets {
		out = append(out, f.view())
	}
	return out
}

// FleetView returns a single fleet's projection.
func (m *Manager) FleetView(id string) (*FleetView, bool) {
	f, ok := m.fleet(id)
	if !ok {
		return nil, false
	}
	v := f.view()
	return &v, true
}

// KillFleet tears down every sandbox in the fleet and removes it.
func (m *Manager) KillFleet(ctx context.Context, id string) error {
	f, ok := m.fleet(id)
	if !ok {
		return fmt.Errorf("fleet %q not found", id)
	}
	for _, sid := range f.Sandboxes {
		_ = m.KillSandbox(ctx, sid)
	}
	m.fleetMu.Lock()
	delete(m.fleets, id)
	m.fleetMu.Unlock()
	m.saveFleets()
	return nil
}

// AddTask appends a task to a fleet's board.
func (m *Manager) AddTask(fleetID, payload string) (*fleet.Task, error) {
	f, ok := m.fleet(fleetID)
	if !ok {
		return nil, fmt.Errorf("fleet %q not found", fleetID)
	}
	t := f.Board.Add(payload)
	m.saveFleets()
	return t, nil
}

// ClaimTask atomically claims the next pending task for a worker.
func (m *Manager) ClaimTask(fleetID, owner string) (fleet.Task, bool, error) {
	f, ok := m.fleet(fleetID)
	if !ok {
		return fleet.Task{}, false, fmt.Errorf("fleet %q not found", fleetID)
	}
	t, claimed := f.Board.Claim(owner)
	if claimed {
		m.saveFleets()
	}
	return t, claimed, nil
}

// HeartbeatTask extends a worker's lease on a task so the sweeper won't
// requeue it.
func (m *Manager) HeartbeatTask(fleetID, taskID, owner string) (fleet.Task, error) {
	f, ok := m.fleet(fleetID)
	if !ok {
		return fleet.Task{}, fmt.Errorf("fleet %q not found", fleetID)
	}
	t, err := f.Board.Heartbeat(taskID, owner)
	if err == nil {
		m.saveFleets()
	}
	return t, err
}

// CompleteTask marks a claimed task done. owner must match the claiming worker.
func (m *Manager) CompleteTask(fleetID, taskID, owner, result string) error {
	f, ok := m.fleet(fleetID)
	if !ok {
		return fmt.Errorf("fleet %q not found", fleetID)
	}
	if err := f.Board.Complete(taskID, owner, result); err != nil {
		return err
	}
	m.saveFleets()
	return nil
}

// FailTask marks a claimed task failed, optionally requeuing it. owner must
// match the claiming worker.
func (m *Manager) FailTask(fleetID, taskID, owner, errMsg string, requeue bool) error {
	f, ok := m.fleet(fleetID)
	if !ok {
		return fmt.Errorf("fleet %q not found", fleetID)
	}
	if err := f.Board.Fail(taskID, owner, errMsg, requeue); err != nil {
		return err
	}
	m.saveFleets()
	return nil
}

// ListTasks returns a snapshot of a fleet's tasks.
func (m *Manager) ListTasks(fleetID string) ([]fleet.Task, error) {
	f, ok := m.fleet(fleetID)
	if !ok {
		return nil, fmt.Errorf("fleet %q not found", fleetID)
	}
	return f.Board.List(), nil
}

func (m *Manager) fleet(id string) (*Fleet, bool) {
	m.fleetMu.Lock()
	defer m.fleetMu.Unlock()
	f, ok := m.fleets[id]
	return f, ok
}
