package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/adefemi171/runeward/internal/fleet"
)

// fleetsFileName persists fleet task boards across control-plane restarts.
const fleetsFileName = "fleets.json"

// persistedFleet is the on-disk projection of a Fleet. Sandbox ids are kept for
// reference only; the sandboxes are not recreated on load.
type persistedFleet struct {
	ID        string       `json:"id"`
	Profile   string       `json:"profile"`
	Sandboxes []string     `json:"sandboxes"`
	Created   time.Time    `json:"created"`
	Tasks     []fleet.Task `json:"tasks"`
}

func (m *Manager) fleetsPath() string {
	if m.stateDir == "" {
		return ""
	}
	return filepath.Join(m.stateDir, fleetsFileName)
}

// loadFleets restores persisted fleets. A missing file is not an error.
func (m *Manager) loadFleets() error {
	path := m.fleetsPath()
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var pfs []persistedFleet
	if err := json.Unmarshal(b, &pfs); err != nil {
		return err
	}
	m.fleetMu.Lock()
	defer m.fleetMu.Unlock()
	for _, pf := range pfs {
		m.fleets[pf.ID] = &Fleet{
			ID:        pf.ID,
			Profile:   pf.Profile,
			Board:     fleet.Load(pf.Tasks, m.fleetLease),
			Sandboxes: pf.Sandboxes,
			Created:   pf.Created,
			restored:  true,
		}
	}
	return nil
}

// saveFleets atomically writes the current fleets to disk (no-op without a
// state dir). The snapshot is taken under the lock; the write happens outside.
func (m *Manager) saveFleets() {
	path := m.fleetsPath()
	if path == "" {
		return
	}

	m.fleetMu.Lock()
	pfs := make([]persistedFleet, 0, len(m.fleets))
	for _, f := range m.fleets {
		pfs = append(pfs, persistedFleet{
			ID:        f.ID,
			Profile:   f.Profile,
			Sandboxes: f.Sandboxes,
			Created:   f.Created,
			Tasks:     f.Board.Export(),
		})
	}
	m.fleetMu.Unlock()

	data, err := json.MarshalIndent(pfs, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// startSweeper launches the lease-expiry sweeper, which requeues tasks with
// expired worker leases every interval. Stopped by Close.
func (m *Manager) startSweeper(interval time.Duration) {
	if interval <= 0 {
		return
	}
	m.sweepStop = make(chan struct{})
	m.sweepDone = make(chan struct{})
	go func() {
		defer close(m.sweepDone)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-m.sweepStop:
				return
			case <-t.C:
				m.sweepOnce()
			}
		}
	}()
}

func (m *Manager) sweepOnce() {
	now := time.Now().UTC()
	m.fleetMu.Lock()
	fleets := make([]*Fleet, 0, len(m.fleets))
	for _, f := range m.fleets {
		fleets = append(fleets, f)
	}
	m.fleetMu.Unlock()

	changed := false
	for _, f := range fleets {
		for _, t := range f.Board.Sweep(now) {
			changed = true
			m.recordFleet(f, "task.requeue", t.ID, "lease expired (worker "+t.Owner+")")
		}
	}
	if changed {
		m.saveFleets()
	}
}

func (m *Manager) stopSweeper() {
	if m.sweepStop == nil {
		return
	}
	close(m.sweepStop)
	<-m.sweepDone
	m.sweepStop = nil
}
